#pragma once
#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "s3mm/module/loader.hpp"
#include "s3mm/policy/engine.hpp"
#include "s3mm/registry/registry.hpp"
#include "s3mm/replication/access.hpp"
#include "s3mm/replication/basket.hpp"
#include "s3mm/replication/cache.hpp"
#include "s3mm/replication/stat.hpp"
#include "s3mm/replication/target.hpp"

namespace s3mm::repl {

/// One object waiting in the (in-memory) send queue of a replication.
struct QueuedItem {
    Candidate candidate;
    int64_t queuedAtSec = 0;
};

/// Live view of one replication's queue (CLI `replication queue`).
struct QueueInfo {
    std::string replication;
    int64_t objects = 0;
    uint64_t bytes = 0;
    int64_t sizeThreshold = 0; // bytes that trigger shipment (size check first)
    int64_t periodSec = 0;     // max waiting time before the time trigger
    int64_t minSizeBytes = 0;  // minimum batch for the time trigger
    int64_t ageSec = 0;        // age of the oldest queued item
    bool ready = false;        // thresholds reached right now
    bool scanning = false;     // scan in flight
    std::string oldest;
};

/// One recorded routing decision (CLI `replication route`).
struct RouteInfo {
    int64_t atSec = 0;
    std::string replication;
    std::string kind;    // bucket | object | delete | account
    std::string bucket;
    std::string key;     // object key or access key for accounts
    std::string outcome; // success | denied | warning
    std::string target;
    std::string rule;
    std::string reason;
    uint64_t size = 0;
};

/// The replication pipeline: delta scan of source buckets, policy evaluation,
/// threshold-based shipment and delete propagation. Non-persistent queue and
/// baskets; persistent delta cache under <cacheDir>/state.
class Engine {
public:
    Engine(const registry::Registry& registry, module::Loader& loader);
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    /// Scan every (or one) replication once and ship whatever reached thresholds.
    Result<void> runOnce(const std::string& onlyReplication = {}, bool forceShip = false);
    /// Ship the pending queue of one replication ignoring thresholds.
    Result<void> flush(const std::string& replication);

    /// Background scheduler + worker pool. worker_count == 0 means one
    /// dedicated worker per policy bundle.
    Result<void> start();
    void stop();
    /// Recreate workers (called after CLI mutations add/remove replications).
    Result<void> rebuild();

    /// Re-synchronise per-replication state with the registry after a CLI
    /// mutation: re-point RepState::rep, drop states of removed replications,
    /// invalidate lazy init (clients/bundle/routes). Call while stopped.
    void refreshState();

    /// Manual account synchronisation (`s3mm sync-accounts`); applies the same
    /// access policy filtering as the scan path. Engine should be stopped.
    Result<SyncReport> syncAccounts(const std::string& replication, bool dryRun, bool prune);
    /// Ask for an immediate rescan (SIGHUP, `s3mm replication scan`).
    void kick();
    bool running() const { return scheduler_.joinable(); }

    Stats& stats() { return stats_; }
    const Stats& stats() const { return stats_; }
    StateStore& state() { return state_; }
    AccountSync& accounts() { return accounts_; }

    std::vector<QueueInfo> queues(const std::string& onlyReplication = {}) const;
    std::vector<RouteInfo> routes(const std::string& replication = {}, size_t limit = 200) const;

private:
    struct RepState;

    struct Thresholds {
        int64_t sizeBytes = 0;
        int64_t periodSec = 0;
        int64_t minSizeBytes = 0;
        int64_t maxDiskBytes = 0;
    };
    struct WorkItem {
        std::string replication;
        bool scan = false;
        bool force = false;
    };

    Thresholds thresholds(const registry::Replication& rep) const;
    RepState* ensureState(const registry::Replication& rep);
    std::string policyName(const registry::Replication& rep) const;

    void schedulerLoop();
    void workerLoop(const std::string& policyFilter);
    void queueWork(const std::string& replication, bool scan, bool force);
    void processScan(const std::string& name);
    void processShip(const std::string& name, bool force);

    Result<void> scanReplication(RepState& st);
    Result<void> scanBucket(RepState& st, const s3::BucketInfo& bucket);
    Result<void> propagateBucketSettings(RepState& st, const std::string& bucket, const std::string& versioning,
                                         const std::string& location, const std::string& policyJson);
    /// Deliver one classified item to its target; updates stats and the delta cache.
    Result<void> deliver(RepState& st, Candidate& candidate);
    Result<void> shipReady(RepState& st, bool force);
    TargetGroupPtr resolveTarget(RepState& st, const Candidate& candidate);
    void markDirty(const std::string& replication, const std::string& source, const std::string& bucket);
    void persistDirty();
    void record(RouteInfo info);

    /// OR-trigger: size first, then time with the minimum batch guard.
    static bool thresholdsReached(const Thresholds& th, uint64_t bytes, uint64_t qualifying, int64_t age);

    const registry::Registry& registry_;
    module::Loader& loader_;
    Stats stats_;
    StateStore state_;
    AccountSync accounts_;
    policy::Engine policyEngine_;
    TargetFactory targets_;

    mutable std::mutex stateMutex_;
    std::map<std::string, std::unique_ptr<RepState>> reps_;
    mutable std::mutex routeMutex_;
    std::deque<RouteInfo> routeLog_;

    std::mutex dirtyMutex_;
    std::set<std::string> dirty_; // "<replication>/<bucket>" caches awaiting a save

    std::atomic<bool> stop_{false};
    std::thread scheduler_;
    std::vector<std::thread> workers_;
    std::mutex workMutex_;
    std::condition_variable workCv_;
    bool poolMode_ = false;
    std::deque<WorkItem> sharedQueue_;
    std::map<std::string, std::deque<WorkItem>> policyQueues_;

    static bool mentionsRule(const policy::Bundle& bundle, policy::Category category, const std::string& needle);
};

} // namespace s3mm::repl
