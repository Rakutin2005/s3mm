#pragma once
#include <atomic>
#include <memory>
#include <string>

#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"
#include "s3mm/module/loader.hpp"
#include "s3mm/registry/registry.hpp"
#include "s3mm/replication/engine.hpp"

namespace s3mm::daemon {

struct Options {
    std::string config = "/etc/s3mm/s3mm.conf";
    std::string socket;      // empty => settings.socket
    std::string pidFile;     // empty => settings.pidFile
    bool daemonize = false;
    bool runOnce = false;    // single scan+ship cycle and exit (cron/testing)
    bool validateOnly = false;
};

/// The s3mmd process: configuration, module loading, the replication engine
/// and the two servers (CLI control socket + Prometheus metrics).
///
/// Cluster / peer networking is NOT part of the core daemon: it lives in the
/// optional s3mmc cluster client (see the s3mmc/ subproject). s3mmd treats a
/// remote cluster as just another S3 endpoint; when that endpoint is a Unix
/// socket published by s3mmc (remote-<cluster>.sock), s3mmc transparently
/// routes the traffic over mTLS to the peer instance that owns the cluster.
/// If the user does not need clustering, they simply do not run s3mmc.
class Daemon {
public:
    explicit Daemon(Options options);
    ~Daemon();

    /// Load configuration, start everything; returns the process exit code.
    int run();
    void requestStop();
    void requestReload();
    void requestKick();

private:
    Result<void> loadConfig();
    /// Stop the engine, reload the configuration and (re)start the engine,
    /// carrying operational counters over to the new engine instance.
    Result<void> reloadConfig();
    Result<void> startServers();
    void stopServers();
    void daemonize();
    void writePidFile();
    void removePidFile();
    void installSignals();
    void mainLoop();

    /// Dispatch one CLI control request (see daemon/server.hpp for the protocol).
    Value dispatch(const Value& request);
    /// Prometheus text exposition for /metrics.
    std::string metricsText();
    /// Write the runtime configuration back to the main config file.
    std::string flushConfig();
    /// Log a configuration change (audit trail, answer #58).
    void audit(const std::string& what);

    Options options_;
    std::unique_ptr<module::Loader> loader_;
    std::unique_ptr<registry::Registry> registry_;
    std::unique_ptr<repl::Engine> engine_;

    int serverFd_ = -1;
    int metricsFd_ = -1;
    int signalFd_ = -1; // self-pipe for signal handling
    bool running_ = false;
    std::string loadedConfigPath_;
};

} // namespace s3mm::daemon
