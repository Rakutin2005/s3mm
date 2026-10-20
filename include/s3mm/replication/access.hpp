#pragma once
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "s3mm/common/glob.hpp"
#include "s3mm/common/result.hpp"
#include "s3mm/module/loader.hpp"
#include "s3mm/module/module.hpp"
#include "s3mm/registry/registry.hpp"

namespace s3mm::repl {

/// One planned/applied change on the destination cluster.
struct AccountChange {
    std::string accessKey;
    std::vector<std::string> actions; // "create", "secret", "status", "grants", "policy:x", "delete"
    bool applied = false;
    std::string error;
};

/// Result of comparing source and destination accounts of one replication.
struct SyncReport {
    int64_t sourceAccounts = 0;
    int64_t destinationAccounts = 0;
    int64_t matched = 0;     // identical, nothing to do
    int64_t created = 0;
    int64_t updated = 0;
    int64_t deleted = 0;
    int64_t failed = 0;
    bool dryRun = false;
    std::vector<AccountChange> changes;
    std::vector<std::string> errors;

    bool empty() const { return changes.empty(); }
    std::string toJson() const;
    std::string toText() const;
};

/// Synchronises S3 accounts (access keys, secrets, status, bucket grants,
/// inline policies) from the source cluster to the destination cluster
/// through the vendor admin modules, with delta comparison: only the
/// differences are sent.
class AccountSync {
public:
    AccountSync(const registry::Registry& registry, module::Loader& loader);

    /// Open the admin provider of a cluster (module must support credentials).
    Result<std::unique_ptr<module::IAdminProvider>> adminFor(const registry::Cluster& cluster) const;

    /// Compute the delta (and apply it unless dryRun). `prune` deletes
    /// destination accounts that do not exist on the source. `accept` is an
    /// optional policy predicate: only accounts it accepts are propagated.
    Result<SyncReport> sync(const registry::Replication& replication, bool dryRun, bool prune = false,
                            const std::function<bool(const module::Account&)>& accept = {}) const;

    /// Build a Client bound to the cluster (module-adjusted options).
    Result<std::shared_ptr<s3::Client>> clientFor(const registry::Cluster& cluster,
                                                  const std::string& credentialName = {}) const;

    /// Is the access key selected by the replication's account filter?
    static bool selected(const registry::Replication& replication, const std::string& accessKey);

private:
    const registry::Registry& registry_;
    module::Loader& loader_;
};

} // namespace s3mm::repl
