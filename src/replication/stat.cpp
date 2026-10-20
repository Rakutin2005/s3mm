#include "s3mm/replication/stat.hpp"

#include <sstream>

namespace s3mm::repl {

ReplicaStat& Stats::forReplication(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& s = stats_[name];
    if (s.replication.empty()) s.replication = name;
    return s;
}

ReplicaStat Stats::snapshot(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = stats_.find(name);
    if (it == stats_.end()) {
        ReplicaStat empty;
        empty.replication = name;
        return empty;
    }
    return it->second;
}

std::vector<ReplicaStat> Stats::all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ReplicaStat> out;
    for (const auto& [name, s] : stats_) out.push_back(s);
    return out;
}

void Stats::reset(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.erase(name);
}

void Stats::absorb(const Stats& other) {
    if (this == &other) return;
    std::scoped_lock lock(mutex_, other.mutex_);
    for (const auto& [name, s] : other.stats_) stats_.try_emplace(name, s);
}

std::string Stats::prometheus(const std::vector<std::string>& replicationNames) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream os;
    auto emit = [&os](const char* name, const char* help, const char* type,
                      const std::vector<std::pair<std::string, long double>>& values) {
        if (values.empty()) return;
        os << "# HELP " << name << " " << help << "\n";
        os << "# TYPE " << name << " " << type << "\n";
        for (const auto& [label, v] : values)
            os << name << "{replication=\"" << label << "\"} " << (long double)v << "\n";
    };
    auto forNames = [&](auto getter) {
        std::vector<std::pair<std::string, long double>> out;
        for (const auto& rn : replicationNames) {
            auto it = stats_.find(rn);
            long double value = it == stats_.end() ? 0 : (long double)getter(it->second);
            out.emplace_back(rn, value);
        }
        return out;
    };
    emit("s3mm_scan_cycles_total", "Completed scan cycles", "counter", forNames([](const ReplicaStat& s) { return s.scanCycles; }));
    emit("s3mm_buckets_scanned_total", "Buckets scanned", "counter", forNames([](const ReplicaStat& s) { return s.bucketsScanned; }));
    emit("s3mm_objects_scanned_total", "Objects scanned", "counter", forNames([](const ReplicaStat& s) { return s.objectsScanned; }));
    emit("s3mm_delta_objects_total", "Objects detected as changed", "counter", forNames([](const ReplicaStat& s) { return s.deltaDetected; }));
    emit("s3mm_accepted_total", "Items routed to success", "counter", forNames([](const ReplicaStat& s) { return s.accepted; }));
    emit("s3mm_denied_total", "Items routed to denied", "counter", forNames([](const ReplicaStat& s) { return s.denied; }));
    emit("s3mm_warning_total", "Items routed to warning", "counter", forNames([](const ReplicaStat& s) { return s.warned; }));
    emit("s3mm_shipped_total", "Items delivered", "counter", forNames([](const ReplicaStat& s) { return s.shipped; }));
    emit("s3mm_ship_failed_total", "Delivery failures", "counter", forNames([](const ReplicaStat& s) { return s.failed; }));
    emit("s3mm_deleted_total", "Deletions propagated", "counter", forNames([](const ReplicaStat& s) { return s.deleted; }));
    emit("s3mm_accounts_synced_total", "Accounts synchronised", "counter", forNames([](const ReplicaStat& s) { return s.accountsSynced; }));
    emit("s3mm_bytes_shipped_total", "Bytes delivered", "counter", forNames([](const ReplicaStat& s) { return (long double)s.bytesShipped; }));
    emit("s3mm_pending_bytes", "Bytes waiting in the queue", "gauge", forNames([](const ReplicaStat& s) { return (long double)s.pendingBytes; }));
    emit("s3mm_pending_objects", "Objects waiting in the queue", "gauge", forNames([](const ReplicaStat& s) { return (long double)s.pendingObjects; }));
    emit("s3mm_lag_seconds", "Replication lag of the last delivery", "gauge", forNames([](const ReplicaStat& s) { return (long double)s.lastLagSec; }));
    emit("s3mm_last_scan_duration_ms", "Duration of the last scan", "gauge", forNames([](const ReplicaStat& s) { return (long double)s.lastScanMs; }));
    emit("s3mm_in_flight", "Scan/ship currently running", "gauge", forNames([](const ReplicaStat& s) { return s.inFlight ? 1.0L : 0.0L; }));
    return os.str();
}

} // namespace s3mm::repl
