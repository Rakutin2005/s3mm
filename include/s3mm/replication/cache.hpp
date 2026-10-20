#pragma once
#include <map>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/common/time.hpp"
#include "s3mm/s3/client.hpp"

namespace s3mm::repl {

/// One tracked object of the delta cache.
struct CacheEntry {
    std::string key;
    uint64_t size = 0;
    std::string etag;
    tm::TimePoint lastModified;
    std::string versionId;
    bool deleted = false;      // tombstone observed on the source
    tm::TimePoint deletedAt;
    bool shipped = false;      // replicated to the destination at least once

    bool sameAs(const s3::ObjectInfo& o) const {
        return !deleted && size == o.size && etag == o.etag && lastModified == o.lastModified;
    }
};

/// Per (replication, cluster, bucket) delta cache, persisted as a TSV file.
class BucketCache {
public:
    BucketCache() = default;
    explicit BucketCache(std::string path) : path_(std::move(path)) {}

    const std::string& path() const { return path_; }
    const std::map<std::string, CacheEntry>& entries() const { return entries_; }
    size_t size() const { return entries_.size(); }

    /// True when the object differs from the cache (or is unknown, or was seen
    /// but never shipped — such objects must stay eligible for replication).
    bool changed(const s3::ObjectInfo& o) const;
    /// True when a key known to the cache disappeared on the source.
    std::vector<CacheEntry> missingSince(const std::map<std::string, s3::ObjectInfo>& current) const;

    /// Record an observed source state without marking it as replicated.
    void observe(const s3::ObjectInfo& info);
    void markShipped(const s3::ObjectInfo& info);
    void markDeleted(const std::string& key, tm::TimePoint when);
    void forget(const std::string& key);
    void clear();

    Result<void> load();
    Result<void> save() const;

private:
    std::string path_;
    std::map<std::string, CacheEntry> entries_;
};

/// Filesystem-backed state store: <root>/<replication>/<cluster>/<bucket>/
class StateStore {
public:
    explicit StateStore(std::string root) : root_(std::move(root)) {}

    const std::string& root() const { return root_; }
    BucketCache& bucket(const std::string& replication, const std::string& source, const std::string& bucket);

    std::string bucketSettingsHash(const std::string& replication, const std::string& bucket) const;
    void setBucketSettingsHash(const std::string& replication, const std::string& bucket, const std::string& hash);

    /// Persist every loaded cache + settings hashes.
    Result<void> persist();
    /// Drop state of a replication (used by `rescan`).
    Result<void> reset(const std::string& replication);

private:
    std::string root_;
    std::map<std::string, BucketCache> caches_;
    std::map<std::string, std::string> settingsHashes_;

    std::string cachePath(const std::string& replication, const std::string& source, const std::string& bucket) const;
    std::string settingsPath(const std::string& replication) const;
};

} // namespace s3mm::repl
