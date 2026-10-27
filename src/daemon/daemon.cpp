#include "s3mm/daemon/daemon.hpp"

#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
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
#include "s3mm/replication/probe.hpp"

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

/// Request summary for the log: command, kind, name and field names only
/// (field values may carry secrets).
std::string describeRequest(const Value& req) {
    std::string out = "cmd=" + req.getString("cmd");
    for (const char* k : {"kind", "name", "replication", "policy", "action", "path"}) {
        const Value* v = req.find(k);
        if (v && v->isString() && !v->asString().empty()) out += std::string(" ") + k + "=" + v->asString();
    }
    const Value* f = req.find("fields");
    if (f && f->isObject() && f->size() > 0) {
        std::vector<std::string> keys;
        for (const auto& [k, v] : f->members()) keys.push_back(k);
        out += " fields=[" + str::join(keys, ",") + "]";
    }
    return out;
}

} // namespace

Daemon::Daemon(Options options) : options_(std::move(options)) {}

Daemon::~Daemon() {
    waitForProbes();
    stopServers();
    removePidFile();
    if (signalFd_ >= 0) ::close(signalFd_);
    if (gSignalFd >= 0) ::close(gSignalFd);
    signalFd_ = gSignalFd = -1;
}

// Both requests go through the self-pipe so that they are handled by the
// main loop, exactly like the corresponding signals.
void Daemon::requestStop() {
    LOG_DEBUG("stop requested");
    char c = 'q';
    if (gSignalFd < 0 || ::write(gSignalFd, &c, 1) != 1) LOG_ERROR("stop request could not be queued: signal pipe unavailable");
}

void Daemon::requestReload() {
    LOG_DEBUG("reload requested");
    char c = SIGHUP;
    if (gSignalFd < 0 || ::write(gSignalFd, &c, 1) != 1) LOG_ERROR("reload request could not be queued: signal pipe unavailable");
}

void Daemon::requestKick() {}

// ---------------------------------------------------------- cluster probe ---

void Daemon::probeClustersAsync(std::vector<std::string> names, const std::string& why) {
    if (!registry_ || registry_->clusters().empty()) return;
    auto snapshot = std::make_shared<registry::Registry>(*registry_);
    if (names.empty())
        for (const auto& c : snapshot->clusters()) names.push_back(c.name);
    LOG_INFO("probe: checking ", names.size(), " cluster(s) in the background (", why, "): ", str::join(names, ", "));
    std::lock_guard<std::mutex> lock(probesMutex_);
    probes_.erase(std::remove_if(probes_.begin(), probes_.end(),
                                 [](std::future<void>& f) {
                                     return f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                                 }),
                  probes_.end());
    const module::Loader* loader = loader_.get();
    probes_.push_back(std::async(std::launch::async, [snapshot, names, loader] {
        for (const auto& name : names) {
            const registry::Cluster* c = snapshot->cluster(name);
            if (!c) {
                LOG_WARN("probe: cluster '", name, "' disappeared before it could be checked");
                continue;
            }
            repl::probeCluster(*snapshot, *c, loader);
        }
    }));
}

void Daemon::waitForProbes() {
    std::lock_guard<std::mutex> lock(probesMutex_);
    if (!probes_.empty()) LOG_DEBUG("probe: waiting for ", probes_.size(), " background probe(s)");
    for (auto& f : probes_)
        if (f.valid()) f.wait();
    probes_.clear();
}

// ----------------------------------------------------------------- config ---

Result<void> Daemon::loadConfig() {
    log::Stopwatch sw;
    LOG_DEBUG("loading configuration from ", options_.config);
    auto cfg = config::Config::load(options_.config);
    if (!cfg) {
        LOG_ERROR("cannot load configuration ", options_.config, ": ", cfg.error());
        return Result<void>(cfg.error());
    }
    auto problems = cfg.value().validate();
    if (!problems.empty()) {
        LOG_ERROR("configuration ", options_.config, " rejected: ", problems.size(), " problem(s): ",
                  str::join(problems, "; "));
        return Result<void>(str::join(problems, "; "));
    }
    LOG_DEBUG("configuration ", cfg.value().path(), " validated, building registry");
    auto registry = registry::Registry::fromConfig(cfg.value());
    if (!registry) {
        LOG_ERROR("cannot build registry from ", options_.config, ": ", registry.error());
        return Result<void>(registry.error());
    }

    registry_ = std::make_unique<registry::Registry>(std::move(registry.value()));
    loadedConfigPath_ = cfg.value().path();

    // modules (fresh dlopen handles on every (re)load)
    loader_ = std::make_unique<module::Loader>();
    const auto& settings = registry_->settings();
    if (!settings.modulesDir.empty()) {
        LOG_DEBUG("loading modules from configured modules_dir ", settings.modulesDir);
        auto loaded = loader_->loadDir(settings.modulesDir);
        if (!loaded) LOG_WARN("modules: ", loaded.error());
    } else {
        LOG_DEBUG("modules_dir not set, loading modules from default locations");
        auto loaded = loader_->loadDefaults();
        if (!loaded) LOG_WARN("modules: ", loaded.error());
    }
    LOG_INFO("configuration loaded from ", options_.config, ": ", registry_->clusters().size(), " cluster(s), ",
             registry_->credentials().size(), " credential(s), ", registry_->replications().size(),
             " replication(s), ", registry_->targets().size(), " target(s), ", registry_->bundles().size(),
             " policy bundle(s), modules: ", str::join(loader_->names(), ", "), " (", sw.ms(), " ms)");
    LOG_DEBUG("settings: socket=", settings.socket, " pid_file=", settings.pidFile, " metrics=", settings.metricsListen,
              " cache_dir=", settings.cacheDir, " secrets_dir=", settings.secretsDir, " log_level=", settings.logLevel,
              " log_facility=", settings.logFacility, " log_socket=", settings.logSocket,
              " permanent=", settings.permanent ? "yes" : "no",
              " master_key=", settings.masterKey.empty() ? std::string("none") : log::redact(settings.masterKey));
    return Result<void>::success();
}

// --------------------------------------------------------------- lifecycle ---

void Daemon::daemonize() {
    LOG_DEBUG("daemonizing (pid ", ::getpid(), ")");
    pid_t pid = ::fork();
    if (pid < 0) {
        LOG_ERROR("daemonize: first fork failed: ", std::strerror(errno), " — staying in the foreground");
        return;
    }
    if (pid > 0) ::_exit(0);
    if (::setsid() < 0) LOG_WARN("daemonize: setsid failed: ", std::strerror(errno));
    pid = ::fork();
    if (pid < 0) {
        LOG_ERROR("daemonize: second fork failed: ", std::strerror(errno));
        return;
    }
    if (pid > 0) ::_exit(0);
    ::umask(0027);
    if (::chdir("/") != 0) LOG_WARN("daemonize: chdir / failed: ", std::strerror(errno));
    int devNull = ::open("/dev/null", O_RDWR);
    if (devNull >= 0) {
        ::dup2(devNull, STDIN_FILENO);
        ::dup2(devNull, STDOUT_FILENO);
        ::dup2(devNull, STDERR_FILENO);
        if (devNull > STDERR_FILENO) ::close(devNull);
    } else {
        LOG_WARN("daemonize: cannot open /dev/null: ", std::strerror(errno));
    }
    LOG_INFO("daemonized, running in the background as pid ", ::getpid());
}

void Daemon::writePidFile() {
    const std::string& pidFile = options_.pidFile.empty() ? registry_->settings().pidFile : options_.pidFile;
    if (pidFile.empty()) {
        LOG_DEBUG("no pid file configured");
        return;
    }
    if (!fs::mkdirp(fs::dirname(pidFile))) LOG_WARN("cannot create pid file directory ", fs::dirname(pidFile));
    if (!fs::writeFileAtomic(pidFile, std::to_string(::getpid()) + "\n"))
        LOG_WARN("cannot write pid file ", pidFile);
    else
        LOG_INFO("pid file ", pidFile, " written (pid ", ::getpid(), ")");
}

void Daemon::removePidFile() {
    const std::string& pidFile =
        registry_ ? (options_.pidFile.empty() ? registry_->settings().pidFile : options_.pidFile) : options_.pidFile;
    if (pidFile.empty()) return;
    if (!fs::exists(pidFile)) return;
    if (fs::removeFile(pidFile)) LOG_DEBUG("pid file ", pidFile, " removed");
    else LOG_WARN("cannot remove pid file ", pidFile);
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
    for (int sig : {SIGTERM, SIGINT, SIGHUP, SIGUSR1}) {
        if (::sigaction(sig, &sa, nullptr) != 0)
            LOG_ERROR("sigaction(", ::strsignal(sig), "): ", std::strerror(errno));
    }
    ::signal(SIGPIPE, SIG_IGN);
    LOG_DEBUG("signal handlers installed (TERM, INT, HUP, USR1; PIPE ignored)");
}

Result<void> Daemon::startServers() {
    const std::string& socket = options_.socket.empty() ? registry_->settings().socket : options_.socket;
    if (socket.find("://") != std::string::npos || (socket.find(':') != std::string::npos && socket.find('/') == std::string::npos)) {
        LOG_ERROR("control socket '", socket, "' is not a Unix domain socket path");
        return Result<void>::failure("s3mmd control socket must be a Unix domain socket path, not a network address");
    }
    LOG_DEBUG("starting control socket on ", socket);
    auto listened = gControl.listen(socket);
    if (!listened) {
        LOG_ERROR("control socket ", socket, ": ", listened.error());
        return listened;
    }
    LOG_NOTICE("control socket listening on ", socket);

    const std::string& metricsAddr = registry_->settings().metricsListen;
    if (!metricsAddr.empty()) {
        LOG_DEBUG("starting metrics server on ", metricsAddr);
        auto bound = gMetrics.listen(metricsAddr);
        if (!bound) LOG_WARN("metrics: ", bound.error());
        else LOG_NOTICE("metrics listening on http://", metricsAddr, "/metrics");
    } else {
        LOG_DEBUG("metrics_listen not set, metrics server disabled");
    }
    // Peer/cluster networking is delegated to the optional s3mmc cluster client
    // (s3mmc/ subproject). s3mmd only talks to remote clusters through their
    // endpoint (which may be a Unix socket published by s3mmc).
    return Result<void>::success();
}

void Daemon::stopServers() {
    LOG_DEBUG("stopping control/metrics servers");
    gControl.close();
    gMetrics.close();
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
                    LOG_NOTICE("stop requested internally");
                    running_ = false;
                    break;
                }
                if (c == SIGHUP) {
                    LOG_NOTICE("SIGHUP: reloading configuration");
                    log::Stopwatch sw;
                    auto res = reloadConfig();
                    if (!res) LOG_ERROR("reload failed: ", res.error(), " — keeping the previous configuration");
                    else LOG_NOTICE("SIGHUP reload completed in ", sw.ms(), " ms");
                } else if (c == SIGUSR1) {
                    LOG_NOTICE("SIGUSR1: rescanning all replications");
                    engine_->kick();
                } else if (c == SIGTERM || c == SIGINT) {
                    LOG_NOTICE("received ", ::strsignal(c), ", shutting down");
                    running_ = false;
                    break;
                } else {
                    LOG_NOTICE("received signal ", (int)c, " (", ::strsignal(c), ")");
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
    log::Stopwatch startup;
    log::Options logOptions;
    logOptions.ident = "s3mmd";
    log::init(logOptions);
    LOG_NOTICE("s3mmd ", S3MM_VERSION, " starting (pid ", ::getpid(), ", config ", options_.config,
               options_.daemonize ? ", daemonize" : "", options_.validateOnly ? ", validate only" : "",
               options_.runOnce ? ", run once" : "", ")");
    LOG_DEBUG("options: socket=", options_.socket.empty() ? "<settings>" : options_.socket,
              " pid_file=", options_.pidFile.empty() ? "<settings>" : options_.pidFile);

    if (options_.daemonize) daemonize();

    auto loaded = loadConfig();
    if (!loaded) {
        LOG_CRITICAL("configuration error: ", loaded.error());
        if (options_.validateOnly) {
            std::fprintf(stderr, "configuration error: %s\n", loaded.error().c_str());
            return 1;
        }
        return 1;
    }
    if (options_.validateOnly) {
        LOG_NOTICE("configuration OK: ", options_.config);
        std::fprintf(stdout, "configuration OK: %s\n", options_.config.c_str());
        return 0;
    }

    log::Options tuned;
    tuned.ident = "s3mmd";
    try {
        tuned.level = log::levelFromString(registry_->settings().logLevel);
    } catch (const Error&) {
        LOG_CRITICAL("unknown log level '", registry_->settings().logLevel, "'");
        throw;
    }
    if (!log::facilityFromString(registry_->settings().logFacility, tuned.facility))
        LOG_WARN("unknown log facility '", registry_->settings().logFacility, "', using daemon");
    tuned.socketPath = registry_->settings().logSocket;
    log::init(tuned);
    LOG_INFO("logging re-initialised: level=", log::levelName(tuned.level), " facility=",
             log::facilityName(tuned.facility), " socket=", tuned.socketPath);

    LOG_DEBUG("creating replication engine");
    engine_ = std::make_unique<repl::Engine>(*registry_, *loader_);

    installSignals();
    auto servers = startServers();
    if (!servers) {
        LOG_CRITICAL("cannot start servers: ", servers.error());
        return 1;
    }
    writePidFile();
    running_ = true;

    if (options_.runOnce) {
        LOG_NOTICE("running a single replication cycle");
        log::Stopwatch sw;
        auto res = engine_->runOnce();
        if (!res) LOG_ERROR("cycle failed: ", res.error());
        else LOG_NOTICE("single replication cycle completed in ", sw.ms(), " ms");
        stopServers();
        removePidFile();
        return res ? 0 : 1;
    }

    engine_->start();
    LOG_NOTICE("s3mmd started (pid ", ::getpid(), ") in ", startup.ms(), " ms");
    probeClustersAsync({}, "startup");
    mainLoop();
    LOG_NOTICE("s3mmd stopping");
    log::Stopwatch stopping;
    waitForProbes();
    engine_->stop();
    stopServers();
    removePidFile();
    LOG_NOTICE("s3mmd stopped in ", stopping.ms(), " ms");
    return 0;
}

// ------------------------------------------------------------ config flush ---

std::string Daemon::flushConfig() {
    std::string path = loadedConfigPath_.empty() ? options_.config : loadedConfigPath_;
    const auto& st = registry_->settings();
    log::Stopwatch sw;
    LOG_DEBUG("flushing runtime configuration to ", path);

    // Materialise every credential secret that is stored outside the secrets
    // directory: sealed with the master key when available, plain otherwise.
    for (const auto& c : registry_->credentials()) {
        if (c.secretIsPlain) continue;
        std::string sp = fs::joinPath(st.secretsDir, c.name);
        if (fs::exists(sp)) {
            LOG_DEBUG("secret file for credential '", c.name, "' already present: ", sp);
            continue;
        }
        fs::mkdirp(st.secretsDir);
        std::string body = st.masterKey.empty() ? c.secretKey : secret::seal(c.secretKey, st.masterKey);
        if (!fs::writeFileAtomic(sp, body + "\n")) {
            LOG_ERROR("flush-config: cannot write secret file ", sp, " for credential '", c.name, "'");
            throw Error("cannot write secret file " + sp);
        }
        fs::setPermissions(sp, 0400);
        LOG_INFO("secret for credential '", c.name, "' written to ", sp, " (",
                 st.masterKey.empty() ? "plain" : "sealed", ", ", log::redact(c.secretKey), ")");
    }
    // A plain master key must be persisted too, otherwise sealed secrets can
    // never be reopened after a restart.
    if (!st.masterKey.empty() && st.masterKeyFile.empty()) {
        std::string mk = fs::joinPath(st.secretsDir, "master_key");
        fs::mkdirp(st.secretsDir);
        if (!fs::exists(mk)) {
            if (!fs::writeFileAtomic(mk, st.masterKey + "\n")) {
                LOG_ERROR("flush-config: cannot write master key file ", mk);
                throw Error("cannot write master key file " + mk);
            }
            fs::setPermissions(mk, 0400);
            LOG_INFO("master key persisted to ", mk, " (", log::redact(st.masterKey), ")");
        }
        registry_->mutableSettings().masterKeyFile = mk;
    }

    std::string text = registry_->dump();
    unsigned mode = fs::permissions(path).value_or(0640);
    if (!fs::writeFileAtomic(path, text)) {
        LOG_ERROR("flush-config: cannot write ", path);
        throw Error("cannot write " + path);
    }
    fs::setPermissions(path, mode);
    LOG_INFO("runtime configuration written to ", path, " (", text.size(), " bytes, mode ", std::oct, mode, std::dec,
             ") in ", sw.ms(), " ms");
    audit("flushed runtime configuration to " + path);
    return path;
}

void Daemon::audit(const std::string& what) {
    log::write(log::Level::Notice, "audit: " + what, {{"topic", "audit"}});
}

// ----------------------------------------------------------------- reload ---

Result<void> Daemon::reloadConfig() {
    log::Stopwatch sw;
    bool wasRunning = engine_ && engine_->running();
    LOG_INFO("reload: stopping engine (running=", wasRunning ? "yes" : "no", ")");
    if (engine_) engine_->stop();
    auto old = std::move(engine_); // stopped; kept only for its counters

    LOG_DEBUG("reload: loading configuration ", options_.config);
    auto res = loadConfig();
    if (!res) {
        LOG_ERROR("reload: configuration rejected: ", res.error(), "; restoring previous engine");
        engine_ = std::move(old);
        if (engine_ && wasRunning) engine_->start();
        return res;
    }
    const auto& st = registry_->settings();
    log::Options tuned;
    tuned.ident = "s3mmd";
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
    LOG_INFO("reload: logging re-initialised: level=", log::levelName(tuned.level), " facility=",
             log::facilityName(tuned.facility), " socket=", tuned.socketPath);
    LOG_DEBUG("reload: creating new engine");
    engine_ = std::make_unique<repl::Engine>(*registry_, *loader_);
    if (old) engine_->stats().absorb(old->stats());
    old.reset();
    if (wasRunning) engine_->start();
    LOG_NOTICE("reload: configuration ", options_.config, " applied in ", sw.ms(), " ms");
    audit("reloaded configuration from " + options_.config);
    probeClustersAsync({}, "configuration reloaded");
    return Result<void>::success();
}

// ---------------------------------------------------------------- metrics ---

std::string Daemon::metricsText() {
    LOG_DEBUG("rendering metrics");
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
    if (cmd.empty()) {
        LOG_WARN("control request without 'cmd'");
        throw UsageError("missing 'cmd'");
    }
    LOG_DEBUG("dispatch: ", describeRequest(req));

    const Value& fields = fieldsOf(req);
    const bool permanent =
        fbool(req, "permanent", false) || (registry_ && registry_->settings().permanent);

    /// stop -> mutate -> refreshState -> (re)start -> audit -> flush if permanent
    auto mutate = [&](const std::string& what, auto&& fn) {
        log::Stopwatch sw;
        bool wasRunning = engine_ && engine_->running();
        LOG_DEBUG("mutation '", what, "': stopping engine (running=", wasRunning ? "yes" : "no", ")");
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
            LOG_ERROR("mutation '", what, "' failed: ", error);
            audit(what + " FAILED: " + error);
            throw Error(error);
        }
        LOG_INFO("mutation '", what, "' applied in ", sw.ms(), " ms");
        audit(what);
        if (permanent) {
            LOG_DEBUG("mutation '", what, "': permanent, flushing configuration");
            try {
                flushConfig();
            } catch (const Error& e) {
                LOG_ERROR("mutation '", what, "' applied but flush-config failed: ", e.what());
                throw Error("applied but flush-config failed: " + std::string(e.what()));
            }
        }
    };

    // ---------------------------------------------------------------- basics --
    if (cmd == "check") {
        // Synchronous availability check of one cluster (name) or all of them.
        std::string name = fstr(req, "name");
        Value arr = Value::array();
        for (const auto& c : registry_->clusters()) {
            if (!name.empty() && c.name != name && c.alias != name) continue;
            arr.push(repl::probeCluster(*registry_, c, loader_.get()).toValue());
        }
        if (!name.empty() && arr.items().empty()) throw UsageError("check: no cluster '" + name + "'");
        return arr;
    }
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
        LOG_DEBUG("validate: checking ", path);
        if (!cfg) {
            problems.push_back(cfg.error());
        } else {
            auto pr = cfg.value().validate();
            problems.insert(problems.end(), pr.begin(), pr.end());
            auto reg = registry::Registry::fromConfig(cfg.value());
            if (!reg) problems.push_back(reg.error());
        }
        if (problems.empty()) LOG_INFO("validate: ", path, " is valid");
        for (const auto& p : problems) LOG_WARN("validate: ", path, ": ", p);
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
        LOG_NOTICE("reload requested over the control socket");
        auto res = reloadConfig();
        if (!res) {
            LOG_ERROR("reload failed: ", res.error(), " — keeping the previous configuration");
            throw Error("reload failed: " + res.error());
        }
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
            LOG_INFO("scan: asynchronous rescan of all replications queued");
            engine_->kick();
            Value v = Value::object();
            v.set("queued", Value::boolean(true));
            return v;
        }
        LOG_INFO("scan: running synchronous cycle for ", rep.empty() ? "all replications" : "'" + rep + "'",
                 fbool(req, "force", false) ? " (forced)" : "");
        log::Stopwatch sw;
        auto res = engine_->runOnce(rep, fbool(req, "force", false));
        if (!res) {
            LOG_ERROR("scan of ", rep.empty() ? "all replications" : "'" + rep + "'", " failed: ", res.error());
            throw Error("scan failed: " + res.error());
        }
        LOG_INFO("scan of ", rep.empty() ? "all replications" : "'" + rep + "'", " completed in ", sw.ms(), " ms");
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
            if (!res) {
                LOG_ERROR("flush of '", rep, "' failed: ", res.error());
                throw Error("flush failed: " + res.error());
            }
            flushed = 1;
        } else {
            for (const auto& r : registry_->replications()) {
                auto res = engine_->flush(r.name);
                if (!res) {
                    LOG_ERROR("flush of '", r.name, "' failed: ", res.error());
                    throw Error("flush of '" + r.name + "' failed: " + res.error());
                }
                ++flushed;
            }
        }
        LOG_INFO("flushed ", flushed, " replication queue(s)");
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
        LOG_INFO("sync-accounts '", rep, "' dry_run=", dryRun ? "yes" : "no", " prune=", prune ? "yes" : "no");
        auto res = engine_->syncAccounts(rep, dryRun, prune);
        if (!res) {
            LOG_ERROR("sync-accounts '", rep, "' failed: ", res.error());
            throw Error("sync-accounts failed: " + res.error());
        }
        LOG_INFO("sync-accounts '", rep, "': matched=", res.value().matched, " created=", res.value().created,
                 " updated=", res.value().updated, " deleted=", res.value().deleted, " failed=", res.value().failed);
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
        LOG_DEBUG(cmd, " ", kind, " '", name, "': validating on a scratch registry");
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
                    LOG_INFO("cache_dir changed ", old.cacheDir, " -> ", registry_->settings().cacheDir,
                             ", rebuilding engine");
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
                LOG_NOTICE("logging re-initialised: level=", log::levelName(tuned.level), " facility=",
                           log::facilityName(tuned.facility), " socket=", tuned.socketPath);
            }
            if (st.socket != old.socket || st.metricsListen != old.metricsListen) {
                LOG_NOTICE("server endpoints changed (socket ", old.socket, " -> ", st.socket, ", metrics ",
                           old.metricsListen, " -> ", st.metricsListen, "), restarting servers");
                stopServers();
                auto res = startServers();
                if (!res) {
                    LOG_ERROR("settings applied but servers failed: ", res.error());
                    throw Error("settings applied but servers failed: " + res.error());
                }
            }
            return out;
        }

        mutate(cmd + " " + kind + " '" + name + "'", [&]() -> Result<void> {
            out = registry::mutateEntity(*registry_, cmd, kind, name, fields);
            return Result<void>::success();
        });
        if (kind == "cluster" && cmd != "rm") probeClustersAsync({name}, cmd + " cluster");
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
        LOG_DEBUG("rule ", action, " on policy '", bundleName, "' ref='", ref, "': validating on a scratch registry");
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

    LOG_WARN("unknown control command '", cmd, "'");
    throw UsageError("unknown command '" + cmd + "'");
}

} // namespace s3mm::daemon
