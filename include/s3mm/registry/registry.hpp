#pragma once
#include <map>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/policy/bundle.hpp"

namespace s3mm::registry {

struct Cluster {
    std::string name;                    // canonical name used in policies
    std::string alias;                   // inventory alias accepted by --source/--destination
    std::vector<std::string> endpoints;  // scheme://host:port
    bool pathStyle = true;
    bool insecure = false;
    std::string vendor = "generic";      // module name for vendor specific behaviour
    std::string zone;                    // free-form tag for grouping
    std::vector<std::string> credentials;// credential names (first resolvable wins)
    std::string location;                // region
    int timeoutSec = 120;
    int connectTimeoutSec = 10;
    double rateLimitPerSec = 0;
    int parallel = 4;                    // parallel transfers per cluster
    uint64_t partSize = 16ull * 1024 * 1024;
    int retries = 5;
    std::string description;
    /// Managed cluster: s3mmd drives its management (admin) API through the
    /// vendor module (account/IAM sync). Unmanaged clusters are used through
    /// the S3 data plane only.
    bool managed = true;
    /// Management API endpoints (scheme://host:port); empty => same as `endpoints`.
    std::vector<std::string> adminEndpoints;
};

struct Credential {
    std::string name;
    std::string cluster;      // empty => global credential usable on any cluster
    std::string accessKey;
    std::string secretKey;    // decrypted at load time
    std::string sessionToken;
    std::string region = "us-east-1";
    std::string zone;
    bool readOnly = false;
    bool secretIsPlain = false; // stored inline instead of a sealed PEM file
};

struct Replication {
    std::string name;
    std::string source;
    std::string destination;
    std::vector<std::string> buckets;   // include/exclude filter (!pattern)
    std::vector<std::string> accounts;  // access key filter
    std::string policy;                 // policy bundle name
    int64_t retentionSec = 0;           // -r/--retention: delete propagation window
    bool deletePropagation = false;
    // thresholds (see 3.8): ship when either is reached
    int64_t queueSizeBytes = 0;         // 0 => from [s3mm] defaults
    int64_t queuePeriodSec = 0;         // "replication period"
    int64_t minSizeBytes = 0;
    int64_t maxDiskBytes = 0;
    int scanEverySec = 0;
    int64_t metadataEverySec = 300; // re-read tags/HTTP metadata; 0 => only on content changes
    bool paused = false;
};

struct Target {
    std::string name;
    std::string kind;      // null | file | s3 | http | db
    std::string uri;       // file:/path | s3://cluster/bucket/prefix | http(s)://host/path
    std::string pathTemplate; // {bucket}/{key}/{action}/{ts}/{reason}
    std::string description;
};

struct Settings {
    std::string socket = "/run/s3mm/s3mm.sock";
    std::string pidFile = "/run/s3mm/s3mmd.pid";
    std::string cacheDir = "/var/cache/s3mm";
    std::string secretsDir = "/etc/s3mm/secrets";
    std::string modulesDir;             // empty => default search path
    std::string masterKey;              // passphrase used to unseal secret_key_file blocks
    std::string masterKeyFile;
    int workerCount = 0;                // 0 => one dedicated worker per policy
    std::string logLevel = "info";
    std::string logFacility = "daemon";
    std::string logSocket = "/dev/log";
    std::string metricsListen;          // "127.0.0.1:9108", empty => disabled
    int transferParallel = 4;
    uint64_t partSize = 16ull * 1024 * 1024;
    int retries = 5;
    int backoffSec = 5;
    double rateLimitPerSec = 0;
    int64_t queueSizeBytes = 1024ll * 1024 * 1024;
    int64_t queuePeriodSec = 300;
    int64_t minSizeBytes = 1024ll * 1024; // minimum batch for the time trigger
    int64_t maxDiskBytes = 10ll * 1024 * 1024 * 1024;
    int scanEverySec = 300;
    int bucketScanEverySec = 0;         // 0 => same as scanEverySec
    bool permanent = false;             // --permanent: write changes to config files
};

/// Runtime model of the whole configuration. Built from config::Config, mutated
/// by CLI commands (via the daemon) and serialised back by `s3mm flush-config`.
class Registry {
public:
    static Result<Registry> fromConfig(const config::Config& cfg);

    // accessors -----------------------------------------------------------------
    const Settings& settings() const { return settings_; }
    const std::vector<Cluster>& clusters() const { return clusters_; }
    const std::vector<Credential>& credentials() const { return credentials_; }
    const std::vector<Replication>& replications() const { return replications_; }
    const std::vector<Target>& targets() const { return targets_; }
    const std::map<std::string, policy::Bundle>& bundles() const { return bundles_; }

    const Cluster* cluster(const std::string& nameOrAlias) const;
    const Credential* credential(const std::string& name) const;
    /// Resolve a credential for a cluster: cluster-bound credentials win over global ones.
    const Credential* credentialFor(const Cluster& cluster, const std::string& name) const;
    /// Best read/write credential of a cluster (first non-read-only, else first).
    const Credential* bestCredential(const Cluster& cluster) const;
    const Replication* replication(const std::string& name) const;
    const Target* target(const std::string& name) const;
    const policy::Bundle* bundle(const std::string& name) const;
    /// Bundles are materialised on demand: "drop-all" and "default" always exist.
    policy::Bundle bundleOrBuiltin(const std::string& name) const;
    const std::vector<std::string>& sources() const { return sources_; }

    // mutation ------------------------------------------------------------------
    Result<void> addCluster(Cluster c);
    Result<void> updateCluster(const std::string& name, Cluster c);
    Result<void> removeCluster(const std::string& name);

    Result<void> addCredential(Credential c);
    Result<void> updateCredential(const std::string& name, Credential c);
    Result<void> removeCredential(const std::string& name);

    Result<void> addReplication(Replication r);
    Result<void> updateReplication(const std::string& name, Replication r);
    Result<void> removeReplication(const std::string& name);

    Result<void> addTarget(Target t);
    Result<void> updateTarget(const std::string& name, Target t);
    Result<void> removeTarget(const std::string& name);

    Result<void> addBundle(policy::Bundle bundle);
    Result<void> updateBundle(const std::string& name, policy::Bundle bundle);
    Result<void> removeBundle(const std::string& name);

    Result<void> addRule(const std::string& bundleName, policy::Rule rule, const std::string& before,
                         const std::string& after);
    Result<void> removeRule(const std::string& bundleName, const std::string& nameOrNumber);
    Result<void> replaceRule(const std::string& bundleName, const std::string& nameOrNumber, policy::Rule rule);

    Settings& mutableSettings() { return settings_; }

    // serialisation -------------------------------------------------------------
    /// Render the whole runtime configuration in s3mm.conf syntax.
    std::string dump() const;
    std::string dumpCluster(const Cluster& c) const;
    std::string dumpCredential(const Credential& c) const;
    std::string dumpReplication(const Replication& r) const;
    std::string dumpTarget(const Target& t) const;
    std::string dumpSettings() const;

private:
    Settings settings_;
    std::vector<Cluster> clusters_;
    std::vector<Credential> credentials_;
    std::vector<Replication> replications_;
    std::vector<Target> targets_;
    std::map<std::string, policy::Bundle> bundles_;
    std::vector<std::string> sources_; // config files that were loaded (for flush-config)

    Result<void> parseSettings(const config::Node& node);
    Result<void> parseCluster(const config::Node& node);
    Result<void> parseCredential(const config::Node& node);
    Result<void> parseReplication(const config::Node& node);
    Result<void> parseTarget(const config::Node& node);
    Result<void> parsePolicy(const config::Node& node);
    Result<void> parseQueueBlock(const config::Node& node);
    Result<void> parseTransferBlock(const config::Node& node);
};

} // namespace s3mm::registry
