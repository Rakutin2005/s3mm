// s3mmws_mod_s3mmc — s3mmws REST module for the s3mmc cluster client.
//
// Configuration (s3mmws.conf):
//   module s3mmc {
//       socket /var/run/s3mmc/node-a/s3mmc.sock;   # control socket, or:
//       config /etc/s3mm/s3mmc.conf;               # derive it from node + run_dir
//       timeout 5s;                                # per request (default 5s)
//   }
//
// Routes (JSON):
//   GET    /ext/s3mmc/status                  node, links, routes, managed
//   GET    /ext/s3mmc/peers                   peer table
//   POST   /ext/s3mmc/peers   {id,address}    add a peer
//   DELETE /ext/s3mmc/peers?id=<peer>         remove a peer
//   GET    /ext/s3mmc/visibility?peer=<peer>  what a peer may see
//   POST   /ext/s3mmc/sync                    force an inventory exchange
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "s3mm/common/log.hpp"
#include "s3mm/common/units.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/rest/module.hpp"
#include "s3mm/rest/router.hpp"

namespace s3mm::rest {
namespace {

/// node + run_dir of an s3mmc configuration (top level or inside s3mmc { }).
Result<std::string> socketFromConfig(const std::string& path) {
    auto cfg = config::Config::load(path);
    if (!cfg) return Result<std::string>::failure("cannot load " + path + ": " + cfg.error());
    std::string node, runDir = "/var/run/s3mmc";
    auto scan = [&](const config::Node& scope) {
        // A top-level directive is its own scope; an s3mmc { } block holds them.
        for (const auto& c : scope.block ? scope.children : std::vector<config::Node>{scope}) {
            if (c.name == "node" && c.hasArg(0) && node.empty()) node = c.arg(0);
            if (c.name == "run_dir" && c.hasArg(0)) runDir = c.arg(0);
        }
    };
    for (const auto& r : cfg.value().roots()) scan(r);
    if (node.empty()) return Result<std::string>::failure(path + ": no 'node' directive");
    return runDir + "/" + node + "/s3mmc.sock";
}

class S3mmcModule : public IRestModule {
public:
    RestModuleInfo info() const override { return {"s3mmc", S3MM_VERSION, "s3mm"}; }

    Result<void> configure(const config::Node& block) override {
        socket_ = block.value("socket");
        std::string cfgPath = block.value("config");
        if (socket_.empty() && cfgPath.empty()) cfgPath = "/etc/s3mm/s3mmc.conf";
        if (socket_.empty()) {
            auto s = socketFromConfig(cfgPath);
            if (!s) return Result<void>::failure(s.error());
            socket_ = s.value();
            LOG_INFO("s3mmc module: control socket ", socket_, " (from ", cfgPath, ")");
        } else {
            LOG_INFO("s3mmc module: control socket ", socket_);
        }
        if (auto t = block.value("timeout"); !t.empty()) timeoutMs_ = (int)units::parseDurationSeconds(t) * 1000;
        if (timeoutMs_ <= 0) timeoutMs_ = 5000;
        return Result<void>::success();
    }

    Value uiExtension() const override {
        std::string json = R"json({
          "id": "s3mmc", "title": "Cluster mesh", "icon": "cluster", "refresh": 10,
          "sections": [
            {"type": "kv", "title": "Node", "source": "/ext/s3mmc/status",
             "fields": [{"key": "node", "title": "Node"}, {"key": "revision", "title": "Inventory revision"},
                        {"key": "poll_model", "title": "Poll model"}, {"key": "poll_interval_sec", "title": "Poll interval, s"},
                        {"key": "pending_tasks", "title": "Pending tasks"}, {"key": "managed", "title": "Managed nodes", "type": "tag"}]},
            {"type": "table", "title": "Peers", "source": "/ext/s3mmc/peers", "path": "peers", "rowKey": "id",
             "columns": [{"key": "id", "title": "Peer"}, {"key": "address", "title": "Address"},
                         {"key": "direction", "title": "Direction", "type": "tag"},
                         {"key": "connected", "title": "Connected", "type": "bool"},
                         {"key": "cn", "title": "Certificate CN"},
                         {"key": "managed_by_us", "title": "Managed by us", "type": "bool"},
                         {"key": "inventory_revision", "title": "Inventory rev."}],
             "rowActions": [
               {"label": "Visibility", "method": "GET", "endpoint": "/ext/s3mmc/visibility?peer={id}"},
               {"label": "Remove", "method": "DELETE", "endpoint": "/ext/s3mmc/peers?id={id}",
                "confirm": "Remove peer {id}?", "danger": true}]},
            {"type": "table", "title": "Links", "source": "/ext/s3mmc/status", "path": "links", "rowKey": "id",
             "columns": [{"key": "id", "title": "Peer"}, {"key": "address", "title": "Address"},
                         {"key": "connected", "title": "Connected", "type": "bool"},
                         {"key": "last_error", "title": "Last error"}]},
            {"type": "table", "title": "Cluster routes", "source": "/ext/s3mmc/status", "path": "routes", "rowKey": "cluster",
             "columns": [{"key": "cluster", "title": "Cluster"}, {"key": "via", "title": "Via peer"}]},
            {"type": "actions", "title": "Actions", "actions": [
               {"label": "Add peer", "method": "POST", "endpoint": "/ext/s3mmc/peers",
                "body": {"id": "{id}", "address": "{address}"},
                "fields": [{"name": "id", "label": "Peer id", "required": true},
                           {"name": "address", "label": "Address (host:port)", "required": true}]},
               {"label": "Sync inventory now", "method": "POST", "endpoint": "/ext/s3mmc/sync"}]}
          ]})json";
        return Value::parseJson(json);
    }

    void registerRoutes(Router& router) override {
        router.add("GET", "/ext/s3mmc/status", [this](const RestRequest&, RestResponse& res) {
            reply(res, call(simple("status")));
        });
        router.add("GET", "/ext/s3mmc/peers", [this](const RestRequest&, RestResponse& res) {
            reply(res, call(simple("peers")));
        });
        router.add("POST", "/ext/s3mmc/peers", [this](const RestRequest& req, RestResponse& res) {
            std::string perr;
            Value body = Value::parseJson(req.body, &perr);
            if (!perr.empty() || !body.isObject()) return badRequest(res, "JSON object with id and address expected");
            Value r = simple("add-peer");
            r.set("id", Value::str(body.getString("id")));
            r.set("address", Value::str(body.getString("address")));
            LOG_INFO("s3mmc module: add peer '", body.getString("id"), "' at ", body.getString("address"));
            reply(res, call(r));
        });
        router.add("DELETE", "/ext/s3mmc/peers", [this](const RestRequest& req, RestResponse& res) {
            auto it = req.query.find("id");
            if (it == req.query.end() || it->second.empty()) return badRequest(res, "id required");
            Value r = simple("remove-peer");
            r.set("id", Value::str(it->second));
            LOG_INFO("s3mmc module: remove peer '", it->second, "'");
            reply(res, call(r));
        });
        router.add("GET", "/ext/s3mmc/visibility", [this](const RestRequest& req, RestResponse& res) {
            auto it = req.query.find("peer");
            if (it == req.query.end() || it->second.empty()) return badRequest(res, "peer required");
            Value r = simple("visibility");
            r.set("peer", Value::str(it->second));
            reply(res, call(r));
        });
        router.add("POST", "/ext/s3mmc/sync", [this](const RestRequest&, RestResponse& res) {
            LOG_INFO("s3mmc module: forced inventory sync");
            reply(res, call(simple("sync-inventory")));
        });
    }

private:
    static Value simple(const char* cmd) {
        Value v = Value::object();
        v.set("cmd", Value::str(cmd));
        return v;
    }

    static void badRequest(RestResponse& res, const std::string& why) {
        res.status = 400;
        res.json(Value::object().set("error", Value::str(why)));
    }

    static void reply(RestResponse& res, const Result<Value>& r) {
        if (!r) {
            res.status = 502;
            res.json(Value::object().set("error", Value::str(r.error())));
            return;
        }
        const Value* ok = r.value().find("ok");
        if (ok && !ok->asBool(false)) {
            res.status = 409;
            res.json(Value::object().set("error", Value::str(r.value().getString("error", "s3mmc error"))));
            return;
        }
        res.json(r.value());
    }

    /// One request line over the s3mmc control socket, one reply line back.
    Result<Value> call(const Value& request) const {
        log::Stopwatch sw;
        const std::string cmd = request.getString("cmd");
        LOG_DEBUG("s3mmc module: '", cmd, "' -> ", socket_);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (socket_.size() >= sizeof(addr.sun_path)) return Result<Value>::failure("socket path too long: " + socket_);
        std::strncpy(addr.sun_path, socket_.c_str(), sizeof(addr.sun_path) - 1);
        int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return Result<Value>::failure(std::string("socket: ") + std::strerror(errno));
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
            std::string err = std::strerror(errno);
            ::close(fd);
            LOG_ERROR("s3mmc module: cannot connect to ", socket_, ": ", err);
            return Result<Value>::failure("s3mmc is not reachable at " + socket_ + ": " + err);
        }
        std::string line = request.toJson(0) + "\n";
        if (::send(fd, line.data(), line.size(), MSG_NOSIGNAL) != (ssize_t)line.size()) {
            std::string err = std::strerror(errno);
            ::close(fd);
            LOG_ERROR("s3mmc module: send '", cmd, "' to ", socket_, " failed: ", err);
            return Result<Value>::failure("send to s3mmc failed: " + err);
        }
        std::string buf;
        char chunk[8192];
        while (buf.find('\n') == std::string::npos) {
            pollfd p{fd, POLLIN, 0};
            int rc = ::poll(&p, 1, timeoutMs_);
            if (rc <= 0) {
                ::close(fd);
                LOG_ERROR("s3mmc module: '", cmd, "' timed out after ", timeoutMs_, " ms");
                return Result<Value>::failure("s3mmc did not answer within " + std::to_string(timeoutMs_) + " ms");
            }
            ssize_t n = ::recv(fd, chunk, sizeof chunk, 0);
            if (n <= 0) break;
            buf.append(chunk, (size_t)n);
        }
        ::close(fd);
        std::string perr;
        Value v = Value::parseJson(buf.substr(0, buf.find('\n')), &perr);
        if (!perr.empty() || !v.isObject()) {
            LOG_ERROR("s3mmc module: unreadable reply to '", cmd, "': ", perr.empty() ? log::clip(buf) : perr);
            return Result<Value>::failure("unreadable reply from s3mmc");
        }
        LOG_DEBUG("s3mmc module: '", cmd, "' answered ", buf.size(), " bytes in ", sw.ms(), " ms");
        return v;
    }

    std::string socket_;
    int timeoutMs_ = 5000;
};

} // namespace
} // namespace s3mm::rest

S3MM_REST_MODULE_ENTRY(s3mm::rest::S3mmcModule)
