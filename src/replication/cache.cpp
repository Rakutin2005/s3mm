#include "s3mm/replication/cache.hpp"

#include <sstream>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::repl {

static const char* kMagic = "s3mm-cache-v1";

bool BucketCache::changed(const s3::ObjectInfo& o) const {
    auto it = entries_.find(o.key);
    if (it == entries_.end()) return true;
    if (!it->second.shipped) return true; // seen before, still waiting for delivery
    return !it->second.sameAs(o);
}

std::vector<CacheEntry> BucketCache::missingSince(const std::map<std::string, s3::ObjectInfo>& current) const {
    std::vector<CacheEntry> out;
    for (const auto& [key, entry] : entries_) {
        if (entry.deleted) continue;
        if (!current.count(key)) out.push_back(entry);
    }
    return out;
}

void BucketCache::observe(const s3::ObjectInfo& info) {
    // "settled": the item was routed to its target (denied/warning records too),
    // so the next scan does not re-evaluate it unless the source state changes.
    markShipped(info);
}

void BucketCache::markShipped(const s3::ObjectInfo& info) {
    CacheEntry& e = entries_[info.key];
    e.key = info.key;
    e.size = info.size;
    e.etag = info.etag;
    e.lastModified = info.lastModified;
    e.versionId = info.versionId;
    e.deleted = false;
    e.deletedAt = tm::TimePoint{};
    e.shipped = true;
}

void BucketCache::markDeleted(const std::string& key, tm::TimePoint when) {
    CacheEntry& e = entries_[key];
    e.key = key;
    e.deleted = true;
    e.deletedAt = when;
    e.shipped = false;
}

void BucketCache::forget(const std::string& key) { entries_.erase(key); }
void BucketCache::clear() { entries_.clear(); }

Result<void> BucketCache::load() {
    entries_.clear();
    if (path_.empty() || !fs::exists(path_)) return Result<void>::success();
    auto content = fs::readFile(path_);
    if (!content) return Result<void>::failure("cannot read cache " + path_);
    std::istringstream is(*content);
    std::string line;
    if (!std::getline(is, line) || line != kMagic) return Result<void>::failure("unsupported cache format in " + path_);
    while (std::getline(is, line)) {
        auto cols = str::split(line, '\t', true);
        if (cols.size() < 8) continue;
        CacheEntry e;
        e.size = std::strtoull(cols[1].c_str(), nullptr, 10);
        e.etag = cols[2];
        if (auto t = tm::fromIso8601(cols[3])) e.lastModified = *t;
        e.versionId = cols[4];
        e.shipped = cols[5] == "shipped";
        e.deleted = cols[6] == "deleted";
        if (e.deleted && cols[7] != "-") {
            if (auto t = tm::fromIso8601(cols[7])) e.deletedAt = *t;
        }
        // column 8.. holds the key (may itself contain tabs)
        std::string key = cols.size() > 8 ? cols[8] : std::string();
        for (size_t i = 9; i < cols.size(); ++i) key += "\t" + cols[i];
        if (!key.empty()) {
            e.key = std::move(key);
            entries_[e.key] = std::move(e);
        }
    }
    return Result<void>::success();
}

Result<void> BucketCache::save() const {
    if (path_.empty()) return Result<void>::failure("cache has no path");
    std::ostringstream os;
    os << kMagic << "\n";
    for (const auto& [key, e] : entries_) {
        os << "1\t" << e.size << "\t" << e.etag << "\t" << tm::toIso8601(e.lastModified) << "\t" << e.versionId << "\t"
           << (e.shipped ? "shipped" : "pending") << "\t" << (e.deleted ? "deleted" : "live") << "\t"
           << (e.deleted ? tm::toIso8601(e.deletedAt) : std::string("-")) << "\t" << e.key << "\n";
    }
    if (!fs::writeFileAtomic(path_, os.str()))
        return Result<void>::failure("cannot write cache " + path_);
    return Result<void>::success();
}

// ------------------------------------------------------------- StateStore ---

std::string StateStore::cachePath(const std::string& replication, const std::string& source,
                                  const std::string& bucket) const {
    return fs::joinPath(fs::joinPath(fs::joinPath(root_, replication), source), bucket + ".state");
}

std::string StateStore::settingsPath(const std::string& replication) const {
    return fs::joinPath(fs::joinPath(root_, replication), "buckets.settings");
}

BucketCache& StateStore::bucket(const std::string& replication, const std::string& source, const std::string& bucket) {
    std::string key = replication + "/" + source + "/" + bucket;
    auto it = caches_.find(key);
    if (it != caches_.end()) return it->second;
    BucketCache cache(cachePath(replication, source, bucket));
    auto loaded = cache.load();
    if (!loaded) LOG_WARN("delta cache: ", loaded.error());
    return caches_.emplace(key, std::move(cache)).first->second;
}

std::string StateStore::bucketSettingsHash(const std::string& replication, const std::string& bucket) const {
    auto it = settingsHashes_.find(replication + "/" + bucket);
    return it == settingsHashes_.end() ? std::string() : it->second;
}

void StateStore::setBucketSettingsHash(const std::string& replication, const std::string& bucket,
                                       const std::string& hash) {
    settingsHashes_[replication + "/" + bucket] = hash;
}

Result<void> StateStore::persist() {
    std::error_code ec;
    fs::mkdirp(root_);
    for (const auto& [key, cache] : caches_) {
        auto res = cache.save();
        if (!res) return res;
    }
    // write per replication to keep flushes isolated
    std::map<std::string, std::string> perReplication;
    for (const auto& [key, hash] : settingsHashes_) {
        auto slash = key.find('/');
        std::string rep = slash == std::string::npos ? key : key.substr(0, slash);
        perReplication[rep] += key + "\t" + hash + "\n";
    }
    for (const auto& [rep, body] : perReplication) {
        std::string path = settingsPath(rep);
        if (!fs::writeFileAtomic(path, std::string("s3mm-bucket-settings-v1\n") + body))
            return Result<void>::failure("cannot write " + path);
    }
    return Result<void>::success();
}

Result<void> StateStore::reset(const std::string& replication) {
    for (auto it = caches_.begin(); it != caches_.end();) {
        if (str::startsWith(it->first, replication + "/")) it = caches_.erase(it);
        else ++it;
    }
    for (auto it = settingsHashes_.begin(); it != settingsHashes_.end();) {
        if (str::startsWith(it->first, replication + "/")) it = settingsHashes_.erase(it);
        else ++it;
    }
    fs::removeTree(fs::joinPath(root_, replication));
    return Result<void>::success();
}

} // namespace s3mm::repl
