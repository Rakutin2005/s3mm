#include "s3mm/daemon/daemon.hpp"

#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sstream>

#include "s3mm/common/error.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/secret.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/units.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/daemon/metrics.hpp"
#include "s3mm/daemon/server.hpp"
#include "s3mm/registry/mutate.hpp"

#ifndef S3MM_VERSION
#define S3MM_VERSION "0.0.0"
#endif

namespace s3mm::daemon {

namespace {

volatile std::sig_atomic_t gSignal = 0;
int gSignalFd = -1;

void signalHandler(int sig) {
    gSignal = sig;
    if (gSignalFd >= 0) {
        char c = (char)sig;
        ssize_t ignored = ::write(gSignalFd, &c, 1);
        (void)ignored;
    }
}

MetricsServer gMetrics;
ControlServer gControl;

// Shared field/entity helpers live in s3mm::registry (used by the CLI too).
using registry::actionValue;
using registry::bundleValue;
using registry::clusterValue;
using registry::credentialValue;
using registry::fdur;
using registry::fbool;
using registry::fieldsOf;
using registry::fint;
using registry::flist;
using registry::fsize;
using registry::fstr;
using registry::has;
using registry::normKind;
using registry::replicationValue;
using registry::ruleValue;
using registry::settingsValue;
using registry::targetValue;

// ------------------------------------------------------------ serialisation ---

Value timeValue(tm::TimePoint t) {
    return Value::str(t > tm::TimePoint{} ? tm::toIso8601(t) : std::string());
}

Value statValue(const repl::ReplicaStat& s) {
    Value v = Value::object();
    v.set("replication", Value::str(s.replication));
    v.set("scan_cycles", Value::number(s.scanCycles));
    v.set("buckets_scanned", Value::number(s.bucketsScanned));
    v.set("objects_scanned", Value::number(s.objectsScanned));
    v.set("delta_detected", Value::number(s.deltaDetected));
    v.set("accepted", Value::number(s.accepted));
    v.set("denied", Value::number(s.denied));
    v.set("warned", Value::number(s.warned));
    v.set("shipped", Value::number(s.shipped));
    v.set("failed", Value::number(s.failed));
    v.set("deleted", Value::number(s.deleted));
    v.set("accounts_synced", Value::number(s.accountsSynced));
    v.set("bytes_detected", Value::number(s.bytesDetected));
    v.set("bytes_shipped", Value::number(s.bytesShipped));
    v.set("pending_bytes", Value::number(s.pendingBytes));
    v.set("pending_objects", Value::number(s.pendingObjects));
    v.set("last_scan_ms", Value::number(s.lastScanMs));
    v.set("last_ship_ms", Value::number(s.lastShipMs));
    v.set("last_scan", timeValue(s.lastScan));
    v.set("last_ship", timeValue(s.lastShip));
    v.set("last_error", Value::str(s.lastErrorText));
    v.set("last_error_at", timeValue(s.lastError));
    v.set("last_lag_sec", Value::number(s.lastLagSec));
    v.set("max_lag_sec", Value::number(s.maxLagSec));
    v.set("in_flight", Value::boolean(s.inFlight));
    return v;
}

Value queueValue(const repl::QueueInfo& q) {
    Value v = Value::object();
    v.set("replication", Value::str(q.replication));
    v.set("objects", Value::number(q.objects));
    v.set("bytes", Value::number(q.bytes));
    v.set("size_threshold", Value::number(q.sizeThreshold));
    v.set("period", Value::number(q.periodSec));
    v.set("min_size", Value::number(q.minSizeBytes));
    v.set("age_sec", Value::number(q.ageSec));
    v.set("ready", Value::boolean(q.ready));
    v.set("scanning", Value::boolean(q.scanning));
    v.set("oldest", Value::str(q.oldest));
    return v;
}

Value routeValue(const repl::RouteInfo& r) {
    Value v = Value::object();
    v.set("at", Value::number(r.atSec));
    v.set("replication", Value::str(r.replication));
    v.set("kind", Value::str(r.kind));
    v.set("bucket", Value::str(r.bucket));
    v.set("key", Value::str(r.key));
    v.set("outcome", Value::str(r.outcome));
    v.set("target", Value::str(r.target));
    v.set("rule", Value::str(r.rule));
    v.set("reason", Value::str(r.reason));
    v.set("size", Value::number(r.size));
    return v;
}

Value changeValue(const repl::AccountChange& c) {
    Value v = Value::object();
    v.set("access_key", Value::str(c.accessKey));
    Value actions = Value::array();
    for (const auto& a : c.actions) actions.push(Value::str(a));
    v.set("actions", actions);
    v.set("applied", Value::boolean(c.applied));
    v.set("error", Value::str(c.error));
    return v;
}

Value syncReportValue(const repl::SyncReport& r) {
    Value v = Value::object();
    v.set("source_accounts", Value::number(r.sourceAccounts));
    v.set("destination_accounts", Value::number(r.destinationAccounts));
    v.set("matched", Value::number(r.matched));
    v.set("created", Value::number(r.created));
    v.set("updated", Value::number(r.updated));
    v.set("deleted", Value::number(r.deleted));
    v.set("failed", Value::number(r.failed));
    v.set("dry_run", Value::boolean(r.dryRun));
    Value changes = Value::array();
    for (const auto& c : r.changes) changes.push(changeValue(c));
    v.set("changes", changes);
    Value errors = Value::array();
    for (const auto& e : r.errors) errors.push(Value::str(e));
    v.set("errors", errors);
    return v;
}

Value moduleValue(const module::ModuleInfo& i) {
    Value v = Value::object();
    v.set("name", Value::str(i.name));
    v.set("version", Value::str(i.version));
    v.set("vendor", Value::str(i.vendor));
    return v;
}

} // namespace

Daemon::Daemon(Options options) : options_(std::move(options)) {}

Daemon::~Daemon() {
    stopServers();
    removePidFile();
}

void Daemon::requestStop() {
    char c = 'q';
    if (signalFd_ >= 0) {
        ssize_t ignored = ::write(signalFd_, &c, 1);
        (void)ignored;
    }
}

void Daemon::requestReload() { requestStop(); } // real implementation via SIGHUP path

void Daemon::requestKick() {}

// ----------------------------------------------------------------- config ---

Result<void> Daemon::loadConfig() {
    auto cfg = config::Config::load(options_.config);
    if (!cfg) return Result<void>(cfg.error());
    auto problems = cfg.value().validate();
    if (!problems.empty()) return Result<void>(str::join(problems, "; "));
    auto registry = registry::Registry::fromConfig(cfg.value());
    if (!registry) return Result<void>(registry.error());

    registry_ = std::make_unique<registry::Registry>(std::move(registry.value()));
    loadedConfigPath_ = cfg.value().path();

    // modules (fresh dlopen handles on every (re)load)
    loader_ = std::make_unique<module::Loader>();
    const auto& settings = registry_->settings();
    if (!settings.modulesDir.empty()) {
        auto loaded = loader_->loadDir(settings.modulesDir);
        if (!loaded) LOG_WARN("modules: ", loaded.error());
    } else {
        auto loaded = loader_->loadDefaults();
        if (!loaded) LOG_WARN("modules: ", loaded.error());
    }
    LOG_INFO("configuration loaded from ", options_.config, ": ", registry_->clusters().size(), " cluster(s), ",
             registry_->credentials().size(), " credential(s), ", registry_->replications().size(),
             " replication(s), ", registry_->targets().size(), " target(s), ", registry_->bundles().size(),
             " policy bundle(s), modules: ", str::join(loader_->names(), ", "));
    return Result<void>::success();
}

// --------------------------------------------------------------- lifecycle ---

void Daemon::daemonize() {
    pid_t pid = ::fork();
    if (pid < 0) return;
    if (pid > 0) ::_exit(0);
    ::setsid();
    pid = ::fork();
    if (pid < 0) return;
    if (pid > 0) ::_exit(0);
    ::umask(0027);
    if (::chdir("/") != 0) { /* non fatal */ }
    int devNull = ::open("/dev/null", O_RDWR);
    if (devNull >= 0) {
        ::dup2(devNull, STDIN_FILENO);
        ::dup2(devNull, STDOUT_FILENO);
        ::dup2(devNull, STDERR_FILENO);
        if (devNull > STDERR_FILENO) ::close(devNull);
    }
}

void Daemon::writePidFile() {
    const std::string& pidFile = options_.pidFile.empty() ? registry_->settings().pidFile : options_.pidFile;
    if (pidFile.empty()) return;
    fs::mkdirp(fs::dirname(pidFile));
    if (!fs::writeFileAtomic(pidFile, std::to_string(::getpid()) + "\n"))
        LOG_WARN("cannot write pid file ", pidFile);
}

void Daemon::removePidFile() {
    const std::string& pidFile =
        registry_ ? (options_.pidFile.empty() ? registry_->settings().pidFile : options_.pidFile) : options_.pidFile;
    if (!pidFile.empty()) fs::removeFile(pidFile);
}

void Daemon::installSignals() {
    int fds[2];
    if (::pipe(fds) != 0) {
        LOG_ERROR("pipe: ", std::strerror(errno));
        return;
    }
    signalFd_ = fds[0];
    int flags = ::fcntl(fds[0], F_GETFL, 0);
    ::fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
    ::fcntl(fds[1], F_SETFL, O_NONBLOCK);
    gSignalFd = fds[1];

    struct sigaction sa {};
    sa.sa_handler = signalHandler;
    ::sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // no SA_RESTART: poll must return EINTR promptly
    ::sigaction(SIGTERM, &sa, nullptr);
    ::sigaction(SIGINT, &sa, nullptr);
    ::sigaction(SIGHUP, &sa, nullptr);
    ::sigaction(SIGUSR1, &sa, nullptr);
    ::signal(SIGPIPE, SIG_IGN);
}

Result<void> Daemon::startServers() {
    const std::string& socket = options_.socket.empty() ? registry_->settings().socket : options_.socket;
    if (socket.find("://") != std::string::npos || (socket.find(':') != std::string::npos && socket.find('/') == std::string::npos)) {
        return Result<void>::failure("s3mmd control socket must be a Unix domain socket path, not a network address");
    }
    auto listened = gControl.listen(socket);
    if (!listened) return listened;
    LOG_INFO("control socket on ", socket);

    const std::string& metricsAddr = registry_->settings().metricsListen;
    if (!metricsAddr.empty()) {
        auto bound = gMetrics.listen(metricsAddr);
        if (!bound) LOG_WARN("metrics: ", bound.error());
        else LOG_INFO("metrics on http://", metricsAddr, "/metrics");
    }
    // Peer/cluster networking is delegated to the optional s3mmc cluster client
    // (s3mmc/ subproject). s3mmd only talks to remote clusters through their
    // endpoint (which may be a Unix socket published by s3mmc).
    return Result<void>::success();
}

void Daemon::stopServers() {
    gControl.close();
    gMetrics.close();
    if (signalFd_ >= 0) {
        ::close(signalFd_);
        signalFd_ = -1;
        gSignalFd = -1;
    }
}

// -------------------------------------------------------------- main loop ---

void Daemon::mainLoop() {
    std::vector<pollfd> fds;
    while (running_) {
        fds.clear();
        fds.push_back({signalFd_, POLLIN, 0});
        if (gControl.fd() >= 0) fds.push_back({gControl.fd(), POLLIN, 0});
        if (gMetrics.fd() >= 0) fds.push_back({gMetrics.fd(), POLLIN, 0});

        int rc = ::poll(fds.data(), (nfds_t)fds.size(), 500);
        if (rc < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("poll: ", std::strerror(errno));
            break;
        }

        if (!fds.empty() && (fds[0].revents & POLLIN)) {
            char c;
            while (::read(signalFd_, &c, 1) > 0) {
                if (c == 'q') {
                    running_ = false;
                    break;
                }
                if (c == SIGHUP) {
                    LOG_INFO("SIGHUP: reloading configuration");
                    auto res = reloadConfig();
                    if (!res) LOG_ERROR("reload failed: ", res.error(), " — keeping the previous configuration");
                } else if (c == SIGUSR1) {
                    LOG_INFO("SIGUSR1: rescanning all replications");
                    engine_->kick();
                }
            }
        }
        if (running_ && fds.size() > 1 && (fds[1].revents & POLLIN)) {
            gControl.acceptOne([this](const Value& request) { return dispatch(request); });
        }
        if (running_ && gMetrics.fd() >= 0 && fds.size() > 2 && (fds[2].revents & POLLIN)) {
            gMetrics.acceptOne([this] { return metricsText(); });
        }
    }
}

int Daemon::run() {
    if (options_.daemonize) daemonize();

    log::Options logOptions;
    logOptions.ident = "s3mmd";
    logOptions.toStderr = !options_.daemonize;
    log::init(logOptions);

    auto loaded = loadConfig();
    if (!loaded) {
        LOG_ERROR("configuration error: ", loaded.error());
        if (options_.validateOnly) {
            std::fprintf(stderr, "configuration error: %s\n", loaded.error().c_str());
            return 1;
        }
        std::fprintf(stderr, "s3mmd: configuration error: %s\n", loaded.error().c_str());
        return 1;
    }
    if (options_.validateOnly) {
        std::fprintf(stdout, "configuration OK: %s\n", options_.config.c_str());
        return 0;
    }

    log::Options tuned;
    tuned.ident = "s3mmd";
    tuned.toStderr = !options_.daemonize;
    tuned.level = log::levelFromString(registry_->settings().logLevel);
    if (!log::facilityFromString(registry_->settings().logFacility, tuned.facility))
        LOG_WARN("unknown log facility '", registry_->settings().logFacility, "', using daemon");
    tuned.socketPath = registry_->settings().logSocket;
    log::init(tuned);

    engine_ = std::make_unique<repl::Engine>(*registry_, *loader_);

    installSignals();
    auto servers = startServers();
    if (!servers) {
        std::fprintf(stderr, "s3mmd: %s\n", servers.error().c_str());
        return 1;
    }
    writePidFile();
    running_ = true;

    if (options_.runOnce) {
        LOG_INFO("running a single replication cycle");
        auto res = engine_->runOnce();
        if (!res) LOG_ERROR("cycle failed: ", res.error());
        stopServers();
        removePidFile();
        return res ? 0 : 1;
    }

    engine_->start();
    LOG_NOTICE("s3mmd started (pid ", ::getpid(), ")");
    mainLoop();
    LOG_NOTICE("s3mmd stopping");
    engine_->stop();
    stopServers();
    removePidFile();
    return 0;
}

// ------------------------------------------------------------ config flush ---

std::string Daemon::flushConfig() {
    std::string path = loadedConfigPath_.empty() ? options_.config : loadedConfigPath_;
    const auto& st = registry_->settings();

    // Materialise every credential secret that is stored outside the secrets
    // directory: sealed with the master key when available, plain otherwise.
    for (const auto& c : registry_->credentials()) {
        if (c.secretIsPlain) continue;
        std::string sp = fs::joinPath(st.secretsDir, c.name);
        if (fs::exists(sp)) continue;
        fs::mkdirp(st.secretsDir);
        std::string body = st.masterKey.empty() ? c.secretKey : secret::seal(c.secretKey, st.masterKey);
        if (!fs::writeFileAtomic(sp, body + "\n")) throw Error("cannot write secret file " + sp);
        fs::setPermissions(sp, 0400);
    }
    // A plain master key must be persisted too, otherwise sealed secrets can
    // never be reopened after a restart.
    if (!st.masterKey.empty() && st.masterKeyFile.empty()) {
        std::string mk = fs::joinPath(st.secretsDir, "master_key");
        fs::mkdirp(st.secretsDir);
        if (!fs::exists(mk)) {
            if (!fs::writeFileAtomic(mk, st.masterKey + "\n")) throw Error("cannot write master key file " + mk);
            fs::setPermissions(mk, 0400);
        }
        registry_->mutableSettings().masterKeyFile = mk;
    }

    std::string text = registry_->dump();
    unsigned mode = fs::permissions(path).value_or(0640);
    if (!fs::writeFileAtomic(path, text)) throw Error("cannot write " + path);
    fs::setPermissions(path, mode);
    audit("flushed runtime configuration to " + path);
    return path;
}

void Daemon::audit(const std::string& what) {
    log::write(log::Level::Notice, "audit: " + what, {{"topic", "audit"}});
}

// ----------------------------------------------------------------- reload ---

Result<void> Daemon::reloadConfig() {
    bool wasRunning = engine_ && engine_->running();
    if (engine_) engine_->stop();
    auto old = std::move(engine_); // stopped; kept only for its counters

    auto res = loadConfig();
    if (!res) {
        engine_ = std::move(old);
        if (engine_ && wasRunning) engine_->start();
        return res;
    }
    engine_ = std::make_unique<repl::Engine>(*registry_, *loader_);
    if (old) engine_->stats().absorb(old->stats());
    old.reset();
    if (wasRunning) engine_->start();
    audit("reloaded configuration from " + options_.config);
    return Result<void>::success();
}

// ---------------------------------------------------------------- metrics ---

std::string Daemon::metricsText() {
    std::vector<std::string> names;
    for (const auto& r : registry_->replications()) names.push_back(r.name);

    std::string out;
    if (engine_) {
        out += engine_->stats().prometheus(names);
        for (const auto& q : engine_->queues()) {
            const std::string lbl = "replication=\"" + q.replication + "\"";
            out += "s3mm_queue_objects{" + lbl + "} " + std::to_string(q.objects) + "\n";
            out += "s3mm_queue_bytes{" + lbl + "} " + std::to_string(q.bytes) + "\n";
            out += "s3mm_queue_ready{" + lbl + "} " + (q.ready ? "1" : "0") + "\n";
            out += "s3mm_queue_age_seconds{" + lbl + "} " + std::to_string(q.ageSec) + "\n";
        }
    }
    out += "s3mm_build_info{version=\"" S3MM_VERSION "\"} 1\n";
    out += "s3mm_up 1\n";
    out += "s3mm_replications " + std::to_string(registry_->replications().size()) + "\n";
    out += "s3mm_clusters " + std::to_string(registry_->clusters().size()) + "\n";
    out += "s3mm_credentials " + std::to_string(registry_->credentials().size()) + "\n";
    out += "s3mm_targets " + std::to_string(registry_->targets().size()) + "\n";
    out += "s3mm_policies " + std::to_string(registry_->bundles().size()) + "\n";
    out += "s3mm_modules " + std::to_string(loader_ ? loader_->modules().size() : 0) + "\n";
    return out;
}

// --------------------------------------------------------------- dispatch ---

Value Daemon::dispatch(const Value& req) {
    const std::string cmd = req.getString("cmd");
    if (cmd.empty()) throw UsageError("missing 'cmd'");

    const Value& fields = fieldsOf(req);
    const bool permanent =
        fbool(req, "permanent", false) || (registry_ && registry_->settings().permanent);

    /// stop -> mutate -> refreshState -> (re)start -> audit -> flush if permanent
    auto mutate = [&](const std::string& what, auto&& fn) {
        bool wasRunning = engine_ && engine_->running();
        if (engine_) engine_->stop();
        std::string error;
        try {
            auto res = fn();
            if (!res) error = res.error();
        } catch (const Error& e) {
            error = e.what();
        }
        if (engine_) engine_->refreshState();
        if (engine_ && wasRunning) engine_->start();
        if (!error.empty()) {
            audit(what + " FAILED: " + error);
            throw Error(error);
        }
        audit(what);
        if (permanent) {
            try {
                flushConfig();
            } catch (const Error& e) {
                throw Error("applied but flush-config failed: " + std::string(e.what()));
            }
        }
    };

    // ---------------------------------------------------------------- basics --
    if (cmd == "ping") {
        Value v = Value::object();
        v.set("version", Value::str(S3MM_VERSION));
        v.set("pid", Value::number((int64_t)::getpid()));
        return v;
    }

    if (cmd == "status") {
        Value v = Value::object();
        v.set("version", Value::str(S3MM_VERSION));
        v.set("pid", Value::number((int64_t)::getpid()));
        v.set("config", Value::str(options_.config));
        v.set("socket", Value::str(options_.socket.empty() ? registry_->settings().socket : options_.socket));
        v.set("metrics", Value::str(registry_->settings().metricsListen));
        v.set("engine", Value::boolean(engine_ && engine_->running()));
        v.set("clusters", Value::number((int64_t)registry_->clusters().size()));
        v.set("credentials", Value::number((int64_t)registry_->credentials().size()));
        v.set("replications", Value::number((int64_t)registry_->replications().size()));
        v.set("targets", Value::number((int64_t)registry_->targets().size()));
        v.set("policies", Value::number((int64_t)registry_->bundles().size()));
        Value mods = Value::array();
        for (const auto& n : loader_->names()) mods.push(Value::str(n));
        v.set("modules", mods);
        return v;
    }

    if (cmd == "modules") {
        Value arr = Value::array();
        for (auto* m : loader_->modules()) arr.push(moduleValue(m->info()));
        return arr;
    }

    if (cmd == "validate") {
        std::string path = fstr(req, "path", options_.config);
        std::vector<std::string> problems;
        auto cfg = config::Config::load(path);
        if (!cfg) {
            problems.push_back(cfg.error());
        } else {
            auto pr = cfg.value().validate();
            problems.insert(problems.end(), pr.begin(), pr.end());
            auto reg = registry::Registry::fromConfig(cfg.value());
            if (!reg) problems.push_back(reg.error());
        }
        Value v = Value::object();
        v.set("path", Value::str(path));
        v.set("valid", Value::boolean(problems.empty()));
        Value arr = Value::array();
        for (const auto& p : problems) arr.push(Value::str(p));
        v.set("problems", arr);
        return v;
    }

    if (cmd == "flush-config") {
        std::string path = flushConfig();
        Value v = Value::object();
        v.set("path", Value::str(path));
        return v;
    }

    if (cmd == "reload") {
        auto res = reloadConfig();
        if (!res) throw Error("reload failed: " + res.error());
        Value v = Value::object();
        v.set("reloaded", Value::boolean(true));
        v.set("config", Value::str(options_.config));
        return v;
    }

    // ------------------------------------------------------------- operations --
    if (cmd == "stat") {
        if (!engine_) throw Error("engine is not running");
        std::string rep = fstr(req, "replication");
        Value arr = Value::array();
        if (!rep.empty()) {
            arr.push(statValue(engine_->stats().snapshot(rep)));
        } else {
            for (const auto& s : engine_->stats().all()) arr.push(statValue(s));
        }
        return arr;
    }

    if (cmd == "queues") {
        if (!engine_) throw Error("engine is not running");
        Value arr = Value::array();
        for (const auto& q : engine_->queues(fstr(req, "replication"))) arr.push(queueValue(q));
        return arr;
    }

    if (cmd == "routes") {
        if (!engine_) throw Error("engine is not running");
        int64_t limit = fint(req, "limit", 50);
        Value arr = Value::array();
        for (const auto& r : engine_->routes(fstr(req, "replication"), (size_t)limit))
            arr.push(routeValue(r));
        return arr;
    }

    if (cmd == "scan") {
        if (!engine_) throw Error("engine is not running");
        std::string rep = fstr(req, "replication");
        if (fbool(req, "async", false)) {
            engine_->kick();
            Value v = Value::object();
            v.set("queued", Value::boolean(true));
            return v;
        }
        auto res = engine_->runOnce(rep, fbool(req, "force", false));
        if (!res) throw Error("scan failed: " + res.error());
        Value v = Value::object();
        v.set("replication", Value::str(rep.empty() ? "all" : rep));
        return v;
    }

    if (cmd == "flush") {
        if (!engine_) throw Error("engine is not running");
        std::string rep = fstr(req, "replication");
        int flushed = 0;
        if (!rep.empty()) {
            auto res = engine_->flush(rep);
            if (!res) throw Error("flush failed: " + res.error());
            flushed = 1;
        } else {
            for (const auto& r : registry_->replications()) {
                auto res = engine_->flush(r.name);
                if (!res) throw Error("flush of '" + r.name + "' failed: " + res.error());
                ++flushed;
            }
        }
        Value v = Value::object();
        v.set("flushed", Value::number((int64_t)flushed));
        return v;
    }

    if (cmd == "rescan") {
        if (!engine_) throw Error("engine is not running");
        std::string rep = fstr(req, "replication");
        int64_t reset = 0;
        mutate("reset delta cache" + (rep.empty() ? std::string(" (all)") : " for '" + rep + "'"), [&] {
            if (!rep.empty()) {
                auto res = engine_->state().reset(rep);
                if (!res) return res;
                ++reset;
            } else {
                for (const auto& r : registry_->replications()) {
                    auto res = engine_->state().reset(r.name);
                    if (!res) return res;
                    ++reset;
                }
            }
            return Result<void>::success();
        });
        Value v = Value::object();
        v.set("reset", Value::number(reset));
        return v;
    }

    if (cmd == "reset-stats") {
        if (!engine_) throw Error("engine is not running");
        std::string rep = fstr(req, "replication");
        int64_t reset = 0;
        if (!rep.empty()) {
            engine_->stats().reset(rep);
            reset = 1;
        } else {
            for (const auto& r : registry_->replications()) engine_->stats().reset(r.name);
            reset = (int64_t)registry_->replications().size();
        }
        audit("reset statistics" + (rep.empty() ? std::string() : " for '" + rep + "'"));
        Value v = Value::object();
        v.set("reset", Value::number(reset));
        return v;
    }

    if (cmd == "sync-accounts") {
        if (!engine_) throw Error("engine is not running");
        std::string rep = fstr(req, "replication");
        if (rep.empty()) throw UsageError("sync-accounts: replication name required");
        bool dryRun = fbool(req, "dry_run", true);
        bool prune = fbool(req, "prune", false);
        auto res = engine_->syncAccounts(rep, dryRun, prune);
        if (!res) throw Error("sync-accounts failed: " + res.error());
        audit("sync-accounts replication '" + rep + "'" + (dryRun ? " (dry run)" : ""));
        return syncReportValue(res.value());
    }

    // ------------------------------------------------------- list and show ---
    if (cmd == "list" || cmd == "show") {
        const bool show = cmd == "show";
        std::string kind = normKind(req.getString("kind"));
        if (kind.empty()) throw UsageError(cmd + ": 'kind' required");
        std::string name = fstr(req, "name");
        Value arr = Value::array();

        if (kind == "cluster") {
            if (show) {
                const auto* c = registry_->cluster(name);
                if (!c) throw Error("no cluster '" + name + "'");
                return clusterValue(*c);
            }
            for (const auto& c : registry_->clusters()) arr.push(clusterValue(c));
            return arr;
        }
        if (kind == "credential") {
            if (show) {
                const auto* c = registry_->credential(name);
                if (!c) throw Error("no credential '" + name + "'");
                return credentialValue(*c);
            }
            for (const auto& c : registry_->credentials()) arr.push(credentialValue(c));
            return arr;
        }
        if (kind == "replication") {
            if (show) {
                const auto* r = registry_->replication(name);
                if (!r) throw Error("no replication '" + name + "'");
                return replicationValue(*r);
            }
            for (const auto& r : registry_->replications()) arr.push(replicationValue(r));
            return arr;
        }
        if (kind == "target") {
            if (show) {
                const auto* t = registry_->target(name);
                if (!t) throw Error("no target '" + name + "'");
                return targetValue(*t);
            }
            for (const auto& t : registry_->targets()) arr.push(targetValue(t));
            return arr;
        }
        if (kind == "policy") {
            auto it = registry_->bundles().find(show ? name : std::string());
            if (show) {
                it = registry_->bundles().find(name);
                if (it == registry_->bundles().end()) throw Error("no policy bundle '" + name + "'");
                return bundleValue(it->second, true);
            }
            for (const auto& [n, b] : registry_->bundles()) arr.push(bundleValue(b, false));
            return arr;
        }
        if (kind == "rule") {
            std::string bundleName = fstr(req, "policy", fstr(req, "bundle"));
            if (bundleName.empty()) throw UsageError(cmd + " rules: 'policy' name required");
            auto it = registry_->bundles().find(bundleName);
            if (it == registry_->bundles().end()) throw Error("no policy bundle '" + bundleName + "'");
            for (const auto& r : it->second.rules) arr.push(ruleValue(r));
            return arr;
        }
        if (kind == "settings") return settingsValue(registry_->settings());
        throw UsageError(cmd + ": unknown kind '" + kind + "'");
    }

    // ------------------------------------------------------------ mutations --
    if (cmd == "add" || cmd == "edit" || cmd == "rm") {
        std::string kind = normKind(req.getString("kind"));
        if (kind.empty()) throw UsageError(cmd + ": 'kind' required");
        std::string name = fstr(req, "name", fstr(fields, "name"));
        if (name.empty() && kind != "settings") throw UsageError(cmd + ": 'name' required");

        // Validate against a scratch copy first: usage errors must not stop
        // the engine and must not leave partial side effects (secret files).
        {
            registry::Registry scratch = *registry_;
            registry::mutateEntity(scratch, cmd, kind, name, fields);
        }

        Value out;
        if (kind == "settings") {
            registry::Settings old = registry_->settings();
            mutate("edit settings", [&]() -> Result<void> {
                out = registry::mutateEntity(*registry_, cmd, kind, name, fields);
                if (registry_->settings().cacheDir != old.cacheDir) {
                    // The StateStore is bound to cache_dir: rebuild the engine
                    // while it is stopped; mutate() restarts it afterwards.
                    auto oldEngine = std::move(engine_);
                    engine_ = std::make_unique<repl::Engine>(*registry_, *loader_);
                    if (oldEngine) engine_->stats().absorb(oldEngine->stats());
                }
                return Result<void>::success();
            });
            const registry::Settings& st = registry_->settings();
            if (st.logLevel != old.logLevel || st.logFacility != old.logFacility ||
                st.logSocket != old.logSocket) {
                log::Options tuned;
                tuned.ident = "s3mmd";
                tuned.toStderr = !options_.daemonize;
                try {
                    tuned.level = log::levelFromString(st.logLevel);
                } catch (const Error&) {
                    LOG_WARN("unknown log level '", st.logLevel, "', keeping info");
                    tuned.level = log::Level::Info;
                }
                if (!log::facilityFromString(st.logFacility, tuned.facility))
                    LOG_WARN("unknown log facility '", st.logFacility, "', using daemon");
                tuned.socketPath = st.logSocket;
                log::init(tuned);
            }
            if (st.socket != old.socket || st.metricsListen != old.metricsListen) {
                stopServers();
                auto res = startServers();
                if (!res) throw Error("settings applied but servers failed: " + res.error());
            }
            return out;
        }

        mutate(cmd + " " + kind + " '" + name + "'", [&]() -> Result<void> {
            out = registry::mutateEntity(*registry_, cmd, kind, name, fields);
            return Result<void>::success();
        });
        return out;
    }

    // ----------------------------------------------------------------- rule --
    if (cmd == "rule") {
        std::string action = fstr(req, "action", "list");
        std::string bundleName = fstr(req, "policy", fstr(req, "bundle"));
        std::string ref = fstr(req, "ref", fstr(req, "name"));
        std::string line = fstr(req, "line");
        std::string before = fstr(req, "before");
        std::string after = fstr(req, "after");
        if (action == "list")
            return registry::applyRule(*registry_, action, bundleName, {}, {}, {}, {});
        {
            registry::Registry scratch = *registry_;
            registry::applyRule(scratch, action, bundleName, ref, line, before, after);
        }
        Value out;
        mutate("rule '" + action + "' on policy '" + bundleName + "'", [&]() -> Result<void> {
            out = registry::applyRule(*registry_, action, bundleName, ref, line, before, after);
            return Result<void>::success();
        });
        return out;
    }

    // Clustering (peers, mTLS, inventory exchange) is not part of the core:
    // it lives in the optional s3mmc cluster client. Nothing to dispatch here.

    throw UsageError("unknown command '" + cmd + "'");
}

} // namespace s3mm::daemon
