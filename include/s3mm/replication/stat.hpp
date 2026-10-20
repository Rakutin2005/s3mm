#pragma once
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "s3mm/common/time.hpp"

namespace s3mm::repl {

/// Per-replication operational counters (basis for `s3mm stat` and /metrics).
struct ReplicaStat {
    std::string replication;

    int64_t scanCycles = 0;
    int64_t bucketsScanned = 0;
    int64_t objectsScanned = 0;
    int64_t deltaDetected = 0;

    int64_t accepted = 0;   // routed to success
    int64_t denied = 0;     // routed to denied (null)
    int64_t warned = 0;     // routed to warning (quarantine)
    int64_t shipped = 0;    // successfully delivered
    int64_t failed = 0;     // delivery failures
    int64_t deleted = 0;    // propagated deletions
    int64_t accountsSynced = 0;

    uint64_t bytesDetected = 0;
    uint64_t bytesShipped = 0;
    uint64_t pendingBytes = 0;
    int64_t pendingObjects = 0;

    int64_t lastScanMs = 0;
    int64_t lastShipMs = 0;
    tm::TimePoint lastScan;
    tm::TimePoint lastShip;
    tm::TimePoint lastError;
    std::string lastErrorText;

    /// Seconds between "changed on source" and "delivered" for the last item.
    double lastLagSec = 0;
    double maxLagSec = 0;

    bool inFlight = false;
};

class Stats {
public:
    ReplicaStat& forReplication(const std::string& name);
    ReplicaStat snapshot(const std::string& name) const;
    std::vector<ReplicaStat> all() const;
    void reset(const std::string& name);
    /// Carry counters over from another Stats (used across config reloads).
    /// Entries present in `other` but missing here are inserted.
    void absorb(const Stats& other);

    /// Prometheus text exposition (also embedded in `s3mm stat -o json`).
    std::string prometheus(const std::vector<std::string>& replicationNames) const;

private:
    mutable std::mutex mutex_;
    std::map<std::string, ReplicaStat> stats_;
};

} // namespace s3mm::repl
