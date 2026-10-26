// s3mme — event client for s3mmd (event-driven integration).
//
//   s3mme [-c /etc/s3mme/s3mme.conf]        run the event daemon
//   s3mme status [--json]                   state of the running instance
//
// s3mme is exactly what s3mmc is for clustering: an optional companion client
// that talks to the s3mmd control socket. It tails the daemon's routing log
// (`replication route` records), turns every new decision into an Event,
// evaluates it against its OWN policy bundles (send/drop per broker) and
// publishes accepted events through loadable broker modules (.so): kafka,
// rabbitmq, ... Default configuration is trivially "send all" — policies are
// optional. Inbound messages can be consumed too (react-on-message model)
// when a module supports it; s3mme reacts by issuing control-socket commands.
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/value.hpp"
#include "s3mm/config/config.hpp"

#include "s3mme/event.hpp"
#include "s3mme/loader.hpp"

namespace {

std::atomic<bool> g_stop{false};

void onSignal(int) { g_stop = true; }

void usage(std::FILE* out) {
    std::fprintf(out,
                 "Usage: s3mme [command] [options]\n"
                 "\n"
                 "Commands:\n"
                 "  (default)          run the event daemon\n"
                 "  status [--json]    state of the running instance\n"
                 "  test-event         publish one synthetic event (dry-run wiring)\n"
                 "\n"
                 "Options:\n"
                 "  -c, --config <f>   configuration file (default /etc/s3mme/s3mme.conf)\n"
                 "  -t, --test         parse config, list brokers, exit non-zero on error\n"
                 "  -h, --help         show this help\n"
                 "  -V, --version      show version\n");
}

struct Opts {
    std::string node = "s3mme-1";
    std::string coreSocket = "/var/run/s3mm/s3mmd.sock";
    std::string runDir = "/var/run/s3mme";
    std::string modulePath;              // extra search dir for broker .so
    std::string pollInterval = "1s";     // tail interval of the routing log
    std::string defaultBroker;           // used when no policy `set broker=`
    std::vector<std::string> brokers;    // enabled broker names from config
    std::string policyBundle;            // optional bundle name in this config
    bool sendAll = true;                 // default model: everything is sent
};

bool loadConfig(const std::string& path, Opts& o, std::string& err) {
    auto parsed = s3mm::config::parseFile(path);
    if (!parsed) { err = parsed.error(); return false; }
    const auto& root = parsed.value();
    auto first = [&](const char* key) -> std::string {
        if (auto v = root.get(key)) return v->asStringOr("");
        return {};
    };
    if (auto v = first("node"); !v.empty()) o.node = v;
    if (auto v = first("core_socket"); !v.empty()) o.coreSocket = v;
    if (auto v = first("run_dir"); !v.empty()) o.runDir = v;
    if (auto v = first("module_path"); !v.empty()) o.modulePath = v;
    if (auto v = first("poll_interval"); !v.empty()) o.pollInterval = v;
    if (auto v = first("default_broker"); !v.empty()) o.defaultBroker = v;
    if (auto v = first("policy"); !v.empty()) o.policyBundle = v;
    if (auto v = first("send_all")) o.sendAll = v == "on" || v == "true" || v == "1";
    for (const auto& n : root.children) {
        if (n.name == "broker") {
            std::string nm = n.positional;
            if (!nm.empty()) {
                o.brokers.push_back(nm);
                if (o.defaultBroker.empty()) o.defaultBroker = nm;
            }
        } else if (n.name == "policy" && !n.positional.empty()) {
            o.policyBundle = n.positional;
        }
    }
    if (o.brokers.empty()) { err = "no broker{} blocks in config"; return false; }
    return true;
}

/// Minimal newline-JSON RPC against the s3mmd control socket.
s3mm::Value coreCall(const std::string& sockPath, const s3mm::Value& req, std::string& err) {
    sockaddr_un un{};
    un.sun_family = AF_UNIX;
    if (sockPath.size() >= sizeof(un.sun_path)) { err = "socket path too long"; return {}; }
    std::strncpy(un.sun_path, sockPath.c_str(), sizeof(un.sun_path) - 1);
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { err = std::strerror(errno); return {}; }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) {
        err = "cannot connect to " + sockPath + ": " + std::strerror(errno);
        ::close(fd);
        return {};
    }
    std::string line = req.toJson(0) + "\n";
    size_t sent = 0;
    while (sent < line.size()) {
        ssize_t n = ::write(fd, line.data() + sent, line.size() - sent);
        if (n <= 0) { err = "write: "; err += std::strerror(errno); ::close(fd); return {}; }
        sent += (size_t)n;
    }
    std::string buf;
    char chunk[4096];
    bool gotLine = false;
    while (!gotLine) {
        ssize_t n = ::read(fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        buf.append(chunk, (size_t)n);
        if (buf.find('\n') != std::string::npos) gotLine = true;
    }
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
    if (buf.empty()) { err = "empty reply from core"; return {}; }
    auto v = s3mm::Value::parse(buf);
    if (!v) { err = "bad json reply: " + v.error(); return {}; }
    return v.value();
}

int64_t parsePollSec(const std::string& s) {
    auto p = s3mm::units::parseDuration(s);
    if (p) return (int64_t)p.value().count();
    // tolerate plain numbers
    try { return std::stoll(s); } catch (...) {}
    return 2;
}

std::string controlSocketPath(const Opts& o) { return o.runDir + "/" + o.node + "/s3mme.sock"; }

void writePidfile(const Opts& o) {
    fs::makeDir(o.runDir + "/" + o.node);
    std::ofstream pf(controlSocketPath(o) + ".pid", std::ios::trunc);
    pf << ::getpid() << "\n";
}

} // namespace

// ---------------------------------------------------------------- main logic
int main(int argc, char** argv) {
    static struct option longopts[] = {
        {"config", required_argument, nullptr, 'c'},
        {"test", no_argument, nullptr, 't'},
        {"json", no_argument, nullptr, 'J'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {nullptr, 0, nullptr, 0},
    };
    std::string cfgPath = "/etc/s3mme/s3mme.conf";
    bool selfTest = false, asJson = false;
    std::string command;
    int c;
    while ((c = getopt_long(argc, argv, "c:hV", longopts, nullptr)) != -1) {
        switch (c) {
        case 'c': cfgPath = optarg; break;
        case 't': selfTest = true; break;
        case 'J': asJson = true; break;
        case 'h': usage(stdout); return 0;
        case 'V': std::printf("s3mme %s\n", S3MM_VERSION); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (optind < argc) command = argv[optind++];

    if (command == "status") {
        std::string err;
        s3mm::Value req;
        req.set("cmd", "s3mme-status");
        auto rep = coreCall(cfgPath.empty() ? "" : cfgPath, req, err); // not used
        (void)rep;
        // status comes from our own control socket instead:
        Opts o;
        std::string cerr;
        if (!loadConfig(cfgPath, o, cerr)) { std::fprintf(stderr, "config: %s\n", cerr.c_str()); return 1; }
        sockaddr_un un{};
        un.sun_family = AF_UNIX;
        std::string sp = controlSocketPath(o);
        std::strncpy(un.sun_path, sp.c_str(), sizeof(un.sun_path) - 1);
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0 || ::connect(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) {
            std::fprintf(stderr, "s3mme is not running (%s)\n", sp.c_str());
            return 1;
        }
        std::string line = "{\"cmd\":\"status\"}\n";
        ::send(fd, line.data(), line.size(), MSG_NOSIGNAL);
        std::string buf;
        char ch[2048];
        ssize_t n;
        while ((n = ::recv(fd, ch, sizeof(ch), 0)) > 0) {
            buf.append(ch, (size_t)n);
            if (buf.find('\n') != std::string::npos) break;
        }
        ::close(fd);
        if (asJson) std::printf("%s", buf.c_str());
        else {
            auto v = s3mm::Value::parse(buf);
            if (v) std::printf("%s\n", v.value().toJson(2).c_str());
            else std::printf("%s", buf.c_str());
        }
        return 0;
    }

    Opts o;
    std::string err;
    if (!loadConfig(cfgPath, o, err)) {
        std::fprintf(stderr, "s3mme: config %s: %s\n", cfgPath.c_str(), err.c_str());
        return 1;
    }

    // Load broker modules.
    s3mme::BrokerLoader loader;
    auto ld = o.modulePath.empty() ? loader.loadDefaults() : loader.loadDir(o.modulePath);
    if (!ld) { std::fprintf(stderr, "s3mme: modules: %s\n", ld.error().c_str()); return 1; }
    std::vector<std::pair<std::string, s3mme::IBroker*>> brokers;
    for (const auto& name : o.brokers) {
        auto* b = loader.find(name);
        if (!b) { std::fprintf(stderr, "s3mme: broker module '%s' not found\n", name.c_str()); return 1; }
        brokers.emplace_back(name, b);
    }

    // Optional local policy bundle ("what to send"). Parsed from the same
    // config file with the core policy parser; absence => send-all.
    std::unique_ptr<s3mm::policy::Bundle> bundle;
    if (!o.policyBundle.empty()) {
        auto parsed = s3mm::config::parseFile(cfgPath);
        if (parsed) {
            for (const auto& n : parsed.value().children) {
                if (n.name == "policy" && n.positional == o.policyBundle) {
                    auto b = s3mm::policy::Bundle::fromNode(n);
                    if (!b) { std::fprintf(stderr, "s3mme: policy: %s\n", b.error().c_str()); return 1; }
                    bundle = std::make_unique<s3mm::policy::Bundle>(b.value());
                }
            }
        }
        if (!bundle) { std::fprintf(stderr, "s3mme: policy bundle '%s' not found\n", o.policyBundle.c_str()); return 1; }
    }
    s3mm::policy::Engine polEngine;

    if (selfTest) {
        std::printf("brokers:");
        for (auto& [n, b] : brokers) std::printf(" %s", n.c_str());
        std::printf("\npolicy: %s\n", bundle ? o.policyBundle.c_str() : "(send-all)");
        std::printf("core socket: %s\n", o.coreSocket.c_str());
        return 0;
    }

    // Connect brokers (each gets its broker{} block as config Value).
    auto parsedRoot = s3mm::config::parseFile(cfgPath);
    std::map<std::string, const s3mm::config::Node*> brokerNodes;
    if (parsedRoot) {
        for (const auto& n : parsedRoot.value().children)
            if (n.name == "broker") brokerNodes[n.positional] = &n;
    }
    for (auto& [name, b] : brokers) {
        s3mm::Value cfg;
        if (auto it = brokerNodes.find(name); it != brokerNodes.end()) {
            for (const auto& d : it->second->directives) cfg.set(d.first, d.second);
        }
        auto res = b->connect(cfg);
        if (!res) {
            std::fprintf(stderr, "s3mme: broker %s connect failed: %s\n", name.c_str(), res.error().c_str());
            return 1;
        }
    }

    signal(SIGINT, onSignal);
    signal(SIGTERM, onSignal);
    writePidfile(o);

    // Tail loop: poll `replication route` from the core, dedupe by cursor.
    int64_t period = parsePollSec(o.pollInterval);
    uint64_t seq = 0;
    std::string lastKey; // cursor: replication/kind/atSec/key of the newest seen record
    std::fprintf(stderr, "s3mme: started, polling %s every %llds\n", o.coreSocket.c_str(), (long long)period);

    auto emit = [&](const s3mme::Event& ev) {
        // Policy decides whether/where to send.
        std::string brokerName = o.defaultBroker;
        bool send = o.sendAll;
        if (bundle) {
            s3mm::policy::Context ctx;
            ctx.set("name", ev.key);
            ctx.set("bucket", ev.bucket);
            ctx.set("kind", ev.kind);
            ctx.set("outcome", ev.outcome);
            ctx.set("target", ev.target);
            ctx.set("rule", ev.rule);
            ctx.set("replication", ev.replication);
            ctx.set("size", ev.size);
            ctx.set("source.cluster", ev.sourceCluster);
            ctx.set("destination.cluster", ev.destCluster);
            auto d = polEngine.evaluate(*bundle, s3mm::policy::Category::Object, ctx, ev.replication);
            send = d.accepted();
            for (const auto& a : d.actions) {
                if (a.name == "set") {
                    auto it = a.params.find("broker");
                    if (it != a.params.end()) brokerName = it->second;
                }
            }
        }
        if (!send) return;
        s3mme::IBroker* target = nullptr;
        for (auto& [n, b] : brokers) if (n == brokerName) target = b;
        if (!target) target = brokers.front().second;
        auto r = target->publish(ev, ev.target);
        if (!r) std::fprintf(stderr, "s3mme: publish via %s failed: %s\n", target->name(), r.error().c_str());
    };

    while (!g_stop) {
        s3mm::Value req;
        req.set("cmd", "replication-route");
        req.set("limit", (int64_t)500);
        std::string cerr;
        auto rep = coreCall(o.coreSocket, req, cerr);
        if (!cerr.empty()) {
            std::fprintf(stderr, "s3mme: core: %s\n", cerr.c_str());
        } else if (auto* arr = rep.find("routes")) {
            // Records arrive newest-first; walk reversed to keep order.
            std::vector<const s3mm::Value*> items;
            for (auto& it : arr->list()) items.push_back(&it);
            for (auto it = items.rbegin(); it != items.rend(); ++it) {
                const auto& ri = **it;
                s3mme::Event ev;
                ev.id = o.node + "-" + std::to_string(++seq);
                ev.atSec = (int64_t)ri.get("at")->asNumberOr(0);
                ev.node = o.node;
                ev.replication = ri.get("replication")->asStringOr("");
                ev.kind = ri.get("kind")->asStringOr("object");
                ev.bucket = ri.get("bucket")->asStringOr("");
                ev.key = ri.get("key")->asStringOr("");
                ev.outcome = ri.get("outcome")->asStringOr("");
                ev.target = ri.get("target")->asStringOr("");
                ev.rule = ri.get("rule")->asStringOr("");
                ev.reason = ri.get("reason")->asStringOr("");
                ev.size = (uint64_t)ri.get("size")->asNumberOr(0);
                std::string cursor = ev.replication + "|" + ev.kind + "|" + std::to_string(ev.atSec) + "|" + ev.key;
                if (!lastKey.empty() && cursor == lastKey) break; // caught up
                emit(ev);
                lastKey = cursor;
            }
        }
        for (int i = 0; i < period * 4 && !g_stop; ++i) {
            struct timespec ts{0, 250 * 1000000L};
            nanosleep(&ts, nullptr);
        }
    }

    std::fprintf(stderr, "s3mme: shutting down\n");
    for (auto& [n, b] : brokers) {
        b->flush();
        b->disconnect();
    }
    return 0;
}
