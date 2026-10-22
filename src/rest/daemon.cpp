#include "s3mm/rest/daemon.hpp"

#include <csignal>
#include <poll.h>
#include <unistd.h>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/registry/registry.hpp"

namespace s3mm::rest {

namespace {
volatile std::sig_atomic_t gStop = 0;
void onSignal(int) { gStop = 1; }
}

RestDaemon::RestDaemon(Options options)
    : options_(std::move(options)),
      daemonClient_(options_.socket.empty() ? "/run/s3mm/s3mm.sock" : options_.socket) {}

void RestDaemon::registerDefaults() {
    router_.add("GET", "/health", [](const RestRequest&, RestResponse& res) {
        res.json(Value::object());
        res.body = "{\"ok\":true}\n";
    });
    router_.add("GET", "/status", [this](const RestRequest&, RestResponse& res) {
        try {
            Value data = daemonClient_.call(Value::object().set("cmd", Value::str("status")));
            res.json(data);
        } catch (const std::exception& e) {
            res.status = 502;
            res.json(Value::object().set("error", Value::str(e.what())));
        }
    });
    router_.add("GET", "/modules", [this](const RestRequest&, RestResponse& res) {
        Value arr = Value::array();
        for (const auto* m : modules_) {
            Value v = Value::object();
            auto info = m->info();
            v.set("name", Value::str(info.name));
            v.set("version", Value::str(info.version));
            v.set("vendor", Value::str(info.vendor));
            arr.push(v);
        }
        res.json(arr);
    });
    router_.add("POST", "/rpc", [this](const RestRequest& req, RestResponse& res) {
        std::string parseError;
        Value parsed = Value::parseJson(req.body, &parseError);
        if (!parseError.empty() || !parsed.isObject()) {
            res.status = 400;
            res.json(Value::object().set("error", Value::str("bad request")));
            return;
        }
        try {
            Value data = daemonClient_.call(parsed);
            res.json(data);
        } catch (const std::exception& e) {
            res.status = 502;
            res.json(Value::object().set("error", Value::str(e.what())));
        }
    });
    router_.add("GET", "/replications", [this](const RestRequest&, RestResponse& res) {
        Value req = Value::object();
        req.set("cmd", Value::str("list"));
        req.set("kind", Value::str("replication"));
        try {
            res.json(daemonClient_.call(req));
        } catch (const std::exception& e) {
            res.status = 502;
            res.json(Value::object().set("error", Value::str(e.what())));
        }
    });
}

int RestDaemon::run() {
    // Load config (optional) for socket/modules defaults.
    if (!options_.config.empty()) {
        auto cfg = config::Config::load(options_.config);
        if (cfg) {
            if (options_.validateOnly) return 0;
            auto reg = registry::Registry::fromConfig(cfg.value());
            if (reg) {
                if (options_.socket.empty()) options_.socket = reg.value().settings().socket;
                if (options_.modulesDir.empty()) options_.modulesDir = reg.value().settings().modulesDir;
            }
        } else {
            if (options_.validateOnly) return 1;
        }
    }
    if (options_.validateOnly) return 0;

    if (options_.socket.empty()) options_.socket = "/run/s3mm/s3mm.sock";
    daemonClient_ = cli::Client(options_.socket);
    if (options_.modulesDir.empty()) options_.modulesDir = "./modules";

    auto loaded = loader_.loadDir(options_.modulesDir);
    if (!loaded) LOG_WARN("rest modules: ", loaded.error());

    RestContext ctx(daemonClient_, options_.modulesDir);
    for (auto* m : loader_.modules()) {
        m->onLoad(ctx);
        m->registerRoutes(router_);
        modules_.push_back(m);
    }

    registerDefaults();

    auto listened = http_.listen(options_.listen, options_.port);
    if (!listened) {
        LOG_ERROR("rest http: ", listened.error());
        return 1;
    }
    LOG_INFO("rest http on http://", options_.listen, ":", options_.port);

    if (options_.daemonize) {
        // Simple daemonize.
        pid_t pid = fork();
        if (pid < 0) return 1;
        if (pid > 0) return 0;
        setsid();
    }

    std::signal(SIGTERM, onSignal);
    std::signal(SIGINT, onSignal);
    std::signal(SIGPIPE, SIG_IGN);

    while (!gStop) {
        pollfd pfd{http_.fd(), POLLIN, 0};
        int rc = ::poll(&pfd, 1, 500);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (rc > 0 && (pfd.revents & POLLIN)) {
            http_.acceptOne([this](const RestRequest& req, RestResponse& res) {
                // Authentication chain.
                for (auto* m : modules_) {
                    if (!m->authenticate(req, res)) return;
                }
                // Request processing chain.
                for (auto* m : modules_) {
                    if (m->process(req, res)) return;
                }
                if (!router_.route(req, res)) {
                    res.status = 404;
                    res.json(Value::object().set("error", Value::str("not found")));
                }
            });
        }
    }
    http_.close();
    return 0;
}

} // namespace s3mm::rest
