#pragma once
#include <string>
#include <vector>

#include "s3mm/common/value.hpp"
#include "s3mm/module/loader.hpp"
#include "s3mm/registry/registry.hpp"

namespace s3mm::repl {

/// Result of probing one endpoint of a cluster.
struct EndpointProbe {
    std::string endpoint;
    std::string plane;        // "s3" (data plane) | "admin" (management API)
    bool reachable = false;   // an HTTP answer was received
    bool authorized = false;  // the credential was accepted (data plane only)
    long status = 0;          // HTTP status, 0 = transport error
    long long ms = 0;
    std::string error;
};

/// Availability of a cluster: every data endpoint is asked for ListBuckets
/// with the cluster's best credential (one attempt, no retries); for managed
/// clusters every management endpoint is checked for an HTTP answer and the
/// vendor module is asked to create its admin provider.
struct ClusterProbe {
    std::string cluster;
    std::string vendor;
    bool managed = true;
    std::string credential;   // credential name used
    std::string accessKey;
    bool moduleLoaded = false;
    std::string adminError;   // admin provider creation failure (managed only)
    int64_t buckets = -1;     // from the first authorized data endpoint, -1 = unknown
    std::vector<EndpointProbe> endpoints;
    long long ms = 0;

    /// At least one data endpoint answered and accepted the credential.
    bool available() const;
    /// Every data endpoint answered and accepted the credential.
    bool healthy() const;
    Value toValue() const;
    std::string summary() const;
};

/// Probe one cluster. `loader` may be null (vendor checks are skipped).
/// Logs the outcome (INFO when available, WARNING/ERROR otherwise).
ClusterProbe probeCluster(const registry::Registry& registry, const registry::Cluster& cluster,
                          const module::Loader* loader);

} // namespace s3mm::repl
