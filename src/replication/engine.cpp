#include "s3mm/replication/engine.hpp"

#include <algorithm>
#include <chrono>

#include "s3mm/common/crypto.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/glob.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/s3/xml.hpp"

namespace s3mm::repl {

namespace {

int64_t nowSec() { return (int64_t)tm::toSeconds(tm::now()); }

int64_t elapsed(int64_t sinceSec) {
    int64_t n = nowSec();
    return n >= sinceSec ? n - sinceSec : 0;
}

std::string isoFromSec(int64_t sec) {
    if (sec <= 0) return "never";
    return tm::toIso8601(tm::Clock::time_point(std::chrono::duration_cast<tm::Clock::duration>(
        std::chrono::seconds(sec))));
}

std::string objectExtension(const std::string& key) {
    auto slash = key.find_last_of('/');
    std::string name = slash == std::string::npos ? key : key.substr(slash + 1);
    auto dot = name.find_last_of('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 == name.size()) return {};
    return str::toLower(name.substr(dot + 1));
}

const char* kindName(Candidate::Kind k) {
    switch (k) {
        case Candidate::Kind::Bucket: return "bucket";
        case Candidate::Kind::Object: return "object";
        case Candidate::Kind::Account: return "account";
        case Candidate::Kind::Delete: return "delete";
    }
    return "object";
}

/// Bucket context: plain attributes plus source./destination. prefixed aliases.
policy::Context bucketContext(const std::string& bucket, const std::string& cluster, const std::string& zone,
                              const std::string& vendor, const std::string& location, const std::string& versioning,
                              const std::string& type, const std::string& owner, const std::string& encryption,
                              const std::string& policyHash, tm::TimePoint created, uint64_t objectCount,
                              uint64_t totalSize) {
    policy::Context ctx;
    auto base = [&](const std::string& k, const std::string& v) {
        ctx.set(k, v);
        ctx.setAlias(k, "source." + k);
    };
    base("name", bucket);
    base("cluster", cluster);
    base("vendor", vendor);
    base("zone", zone);
    base("type", type);
    base("owner", owner);
    base("versioning", versioning.empty() ? "disabled" : versioning);
    base("location", location);
    base("encryption", encryption.empty() ? "none" : encryption);
    base("bucket-policy-hash", policyHash);
    ctx.set("object-count", (uint64_t)objectCount);
    ctx.setAlias("object-count", "source.object-count");
    ctx.set("total-size", (uint64_t)totalSize);
    ctx.setAlias("total-size", "source.total-size");
    ctx.setTime("created", created);
    ctx.setAlias("created", "source.created");
    ctx.setTime("last-modified", created);
    ctx.setAlias("last-modified", "source.last-modified");
    return ctx;
}

policy::Context objectContext(const std::string& bucket, const std::string& key, uint64_t size,
                              const std::string& etag, tm::TimePoint lastModified, const std::string& storageClass,
                              const std::string& versionId, const std::string& contentType, int parts,
                              const std::map<std::string, std::string>& tags, bool deleted) {
    policy::Context ctx;
    auto base = [&](const std::string& k, const std::string& v) {
        ctx.set(k, v);
        ctx.setAlias(k, "source." + k);
    };
    base("name", key);
    base("full", bucket + "/" + key);
    base("relative", key);
    base("bucket", bucket);
    base("extension", objectExtension(key));
    base("etag", etag);
    base("storage-class", storageClass);
    base("version-id", versionId);
    if (!contentType.empty()) base("content-type", contentType);
    ctx.set("size", (uint64_t)size);
    ctx.setAlias("size", "source.size");
    ctx.set("chunk-count", parts);
    ctx.setAlias("chunk-count", "source.chunk-count");
    ctx.setBool("deleted", deleted);
    ctx.setAlias("deleted", "source.deleted");
    ctx.setTime("last-modified", lastModified > tm::TimePoint{} ? lastModified : tm::now());
    ctx.setAlias("last-modified", "source.last-modified");
    ctx.setTags("tags.", tags);
    for (const auto& [k, v] : tags) ctx.setAlias("tags." + k, "source.tags." + k);
    return ctx;
}

policy::Context accountContext(const module::Account& account) {
    policy::Context ctx;
    auto base = [&](const std::string& k, const std::string& v) {
        ctx.set(k, v);
        ctx.setAlias(k, "source." + k);
    };
    base("subject", account.accessKey);
    base("access-key", account.accessKey);
    base("status", account.status);
    std::vector<std::string> buckets, groups = account.groups, permissions;
    for (const auto& [bucket, grants] : account.buckets) {
        buckets.push_back(bucket);
        for (const auto& p : str::split(grants, ',', true)) {
            std::string perm = str::trim(p);
            if (!perm.empty()) permissions.push_back(perm);
        }
    }
    ctx.set("groups", policy::PValue::list(groups));
    ctx.set("buckets", policy::PValue::list(buckets));
    ctx.set("permissions", policy::PValue::list(permissions));
    return ctx;
}

} // namespace

// --------------------------------------------------------------- RepState ---

struct Engine::RepState {
    const registry::Replication* rep = nullptr;

    std::mutex opMutex;     // serialises scan/ship of one replication
    std::mutex initMutex;   // guards lazy initialisation
    bool initialized = false;
    std::shared_ptr<s3::Client> source;
    std::shared_ptr<s3::Client> destination;
    policy::Bundle bundle;
    TargetFactory::Routes routes;

    std::atomic<bool> inScan{false};
    std::atomic<int64_t> lastScanSec{0};
    std::atomic<bool> scanQueued{false};
    std::atomic<bool> shipQueued{false};

    std::mutex queueMutex; // guards queue + queuedKeys + queueSinceSec
    std::vector<QueuedItem> queue;
    std::set<std::string> queuedKeys; // "<bucket>\x1f<key>"
    int64_t queueSinceSec = 0;
};

// ------------------------------------------------------------------ Engine ---

Engine::Engine(const registry::Registry& registry, module::Loader& loader)
    : registry_(registry),
      loader_(loader),
      state_(fs::joinPath(registry.settings().cacheDir, "state")),
      accounts_(registry, loader),
      targets_(registry, &loader) {}

Engine::~Engine() { stop(); }

std::string Engine::policyName(const registry::Replication& rep) const {
    return rep.policy.empty() ? std::string("default") : rep.policy;
}

Engine::Thresholds Engine::thresholds(const registry::Replication& rep) const {
    const auto& s = registry_.settings();
    Thresholds t;
    t.sizeBytes = rep.queueSizeBytes > 0 ? rep.queueSizeBytes : s.queueSizeBytes;
    t.periodSec = rep.queuePeriodSec > 0 ? rep.queuePeriodSec : s.queuePeriodSec;
    t.minSizeBytes = rep.minSizeBytes > 0 ? rep.minSizeBytes : s.minSizeBytes;
    t.maxDiskBytes = rep.maxDiskBytes > 0 ? rep.maxDiskBytes : s.maxDiskBytes;
    return t;
}

bool Engine::thresholdsReached(const Thresholds& th, uint64_t bytes, uint64_t qualifying, int64_t age) {
    // size trigger is checked first (per answers #39)
    if (th.sizeBytes > 0 && bytes >= (uint64_t)th.sizeBytes) return true;
    if (th.periodSec > 0 && age >= th.periodSec) {
        if (th.minSizeBytes <= 0 || qualifying >= (uint64_t)th.minSizeBytes) return true;
        // grace: never hold a small batch forever
        if (age >= th.periodSec * 4) return true;
    }
    if (th.maxDiskBytes > 0 && bytes >= (uint64_t)th.maxDiskBytes) return true;
    return false;
}

bool Engine::mentionsRule(const policy::Bundle& bundle, policy::Category category, const std::string& needle) {
    for (const auto* rule : bundle.rulesOf(category))
        if (rule->conditionText().find(needle) != std::string::npos) return true;
    return false;
}

Engine::RepState* Engine::ensureState(const registry::Replication& rep) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    auto it = reps_.find(rep.name);
    if (it != reps_.end()) {
        it->second->rep = &rep; // registry entries may move on reload
        return it->second.get();
    }
    auto st = std::make_unique<RepState>();
    st->rep = &rep;
    auto* raw = st.get();
    reps_[rep.name] = std::move(st);
    return raw;
}

void Engine::markDirty(const std::string& replication, const std::string& source, const std::string& bucket) {
    std::lock_guard<std::mutex> lock(dirtyMutex_);
    dirty_.insert(replication + "/" + source + "/" + bucket);
}

void Engine::persistDirty() {
    std::set<std::string> pending;
    {
        std::lock_guard<std::mutex> lock(dirtyMutex_);
        pending.swap(dirty_);
    }
    for (const auto& key : pending) {
        auto slash = key.find('/');
        auto slash2 = slash == std::string::npos ? std::string::npos : key.find('/', slash + 1);
        if (slash2 == std::string::npos) continue;
        std::string rep = key.substr(0, slash);
        std::string source = key.substr(slash + 1, slash2 - slash - 1);
        std::string bucket = key.substr(slash2 + 1);
        // StateStore::bucket loads (and caches) the bucket state on demand
        auto res = state_.bucket(rep, source, bucket).save();
        if (!res) LOG_WARN("delta cache save: ", res.error());
    }
    if (!pending.empty()) {
        auto res = state_.persist();
        if (!res) LOG_WARN("state persist: ", res.error());
    }
}

void Engine::record(RouteInfo info) {
    std::lock_guard<std::mutex> lock(routeMutex_);
    routeLog_.push_back(std::move(info));
    while (routeLog_.size() > 2000) routeLog_.pop_front();
}

std::vector<RouteInfo> Engine::routes(const std::string& replication, size_t limit) const {
    std::lock_guard<std::mutex> lock(routeMutex_);
    std::vector<RouteInfo> out;
    for (auto it = routeLog_.rbegin(); it != routeLog_.rend() && out.size() < limit; ++it) {
        if (replication.empty() || it->replication == replication) out.push_back(*it);
    }
    std::reverse(out.begin(), out.end());
    return out;
}

std::vector<QueueInfo> Engine::queues(const std::string& only) const {
    std::vector<QueueInfo> out;
    std::lock_guard<std::mutex> state(stateMutex_);
    for (const auto& [name, st] : reps_) {
        if (!only.empty() && name != only) continue;
        if (!st->rep) continue;
        const Thresholds th = thresholds(*st->rep);
        QueueInfo info;
        info.replication = name;
        uint64_t bytes = 0, qualifying = 0;
        std::lock_guard<std::mutex> lock(st->queueMutex);
        for (const auto& item : st->queue) {
            bytes += item.candidate.size;
            if ((int64_t)item.candidate.size >= th.minSizeBytes) qualifying += item.candidate.size;
        }
        info.objects = (int64_t)st->queue.size();
        info.bytes = bytes;
        info.sizeThreshold = th.sizeBytes;
        info.periodSec = th.periodSec;
        info.minSizeBytes = th.minSizeBytes;
        info.ageSec = st->queue.empty() ? 0 : elapsed(st->queueSinceSec);
        info.ready = !st->queue.empty() && thresholdsReached(th, bytes, qualifying, info.ageSec);
        info.scanning = st->inScan;
        info.oldest = isoFromSec(st->queue.empty() ? 0 : st->queueSinceSec);
        out.push_back(std::move(info));
    }
    std::sort(out.begin(), out.end(), [](const QueueInfo& a, const QueueInfo& b) { return a.replication < b.replication; });
    return out;
}

// ---------------------------------------------------------------- pipeline ---

TargetGroupPtr Engine::resolveTarget(RepState& st, const Candidate& candidate) {
    auto same = [](const TargetGroupPtr& group, const std::string& n) { return group && group->name() == n; };
    if (same(st.routes.success, candidate.target)) return st.routes.success;
    if (same(st.routes.denied, candidate.target)) return st.routes.denied;
    if (same(st.routes.warning, candidate.target)) return st.routes.warning;
    if (auto created = targets_.create(candidate.target)) {
        auto group = created.value();
        if (auto s3target = std::dynamic_pointer_cast<S3Target>(group)) s3target->bind(st.destination, st.source.get());
        return group;
    }
    LOG_WARN("unknown target '", candidate.target, "' for replication '", candidate.replication,
             "': falling back to the outcome route");
    if (candidate.outcome == "denied") return st.routes.denied;
    if (candidate.outcome == "warning") return st.routes.warning;
    return st.routes.success;
}

Result<void> Engine::deliver(RepState& st, Candidate& candidate) {
    auto& stat = stats_.forReplication(candidate.replication);
    TargetGroupPtr target = resolveTarget(st, candidate);
    if (!target) {
        stat.failed++;
        return Result<void>::failure("no target resolved for " + candidate.bucket + "/" + candidate.key);
    }

    ShipRecord rec;
    rec.replication = candidate.replication;
    rec.outcome = candidate.outcome;
    rec.kind = kindName(candidate.kind);
    rec.rule = candidate.rule;
    rec.reason = candidate.reason;
    if (const registry::Replication* rep = registry_.replication(candidate.replication)) {
        rec.sourceCluster = rep->source;
        rec.destinationCluster = rep->destination;
    }
    rec.bucket = candidate.bucket;
    rec.key = candidate.key;
    rec.account = candidate.account;
    rec.size = candidate.size;
    rec.etag = candidate.etag;
    rec.lastModified = candidate.lastModified;
    rec.contentType = candidate.contentType;
    rec.meta = candidate.meta;

    Result<void> res = target->ship(rec, "");
    if (res) {
        if (candidate.kind == Candidate::Kind::Object) {
            stat.shipped++;
            stat.bytesShipped += candidate.size;
            s3::ObjectInfo info;
            info.key = candidate.key;
            info.size = candidate.size;
            info.etag = candidate.etag;
            info.lastModified = candidate.lastModified;
            info.versionId = candidate.versionId;
            if (const registry::Replication* rep = registry_.replication(candidate.replication)) {
                state_.bucket(candidate.replication, rep->source, candidate.bucket).markShipped(info);
                markDirty(candidate.replication, rep->source, candidate.bucket);
            }
            if (candidate.lastModified > tm::TimePoint{}) {
                double lag = (double)std::chrono::duration_cast<std::chrono::seconds>(tm::now() - candidate.lastModified).count();
                stat.lastLagSec = lag;
                stat.maxLagSec = std::max(stat.maxLagSec, lag);
            }
            LOG_DEBUG("shipped ", candidate.bucket, "/", candidate.key, " (", candidate.size, " bytes) via ",
                      target->name());
        } else if (candidate.kind == Candidate::Kind::Delete) {
            stat.deleted++;
            if (const registry::Replication* rep = registry_.replication(candidate.replication)) {
                state_.bucket(candidate.replication, rep->source, candidate.bucket).forget(candidate.key);
                markDirty(candidate.replication, rep->source, candidate.bucket);
            }
            LOG_INFO("propagated deletion of ", candidate.bucket, "/", candidate.key);
        } else {
            stat.shipped++;
        }
    } else {
        stat.failed++;
        stat.lastErrorText = res.error();
        stat.lastError = tm::now();
        candidate.attempts++;
        LOG_WARN("delivery of ", kindName(candidate.kind), " ", candidate.bucket, "/",
                 candidate.key.empty() ? candidate.account : candidate.key, " failed: ", res.error());
    }
    return res;
}

Result<void> Engine::propagateBucketSettings(RepState& st, const std::string& bucket, const std::string& versioning,
                                             const std::string& location, const std::string& policyJson) {
    const auto& rep = *st.rep;
    auto tagging = st.source->getBucketTagging(bucket);
    s3::BucketTagging tags = tagging ? tagging.value() : s3::BucketTagging{};
    std::string tagText;
    for (const auto& [k, v] : tags.tags) tagText += k + "=" + v + "\n";
    std::string hash = crypto::sha256Hex(versioning + "\n" + tagText + "\n" + location + "\n" + policyJson);
    if (state_.bucketSettingsHash(rep.name, bucket) == hash) return Result<void>::success(); // no delta

    auto exists = st.destination->headBucket(bucket);
    if (!exists) return Result<void>(exists.error());
    if (!exists.value()) {
        auto created = st.destination->createBucket(bucket, location);
        if (!created) return Result<void>(created.error());
    }
    if (!versioning.empty()) {
        auto res = st.destination->putBucketVersioning(bucket, versioning);
        if (!res) LOG_WARN("propagate versioning to ", bucket, ": ", res.error());
    }
    if (!tags.tags.empty()) {
        auto res = st.destination->putBucketTagging(bucket, tags);
        if (!res) LOG_WARN("propagate tagging to ", bucket, ": ", res.error());
    }
    if (!policyJson.empty()) {
        auto res = st.destination->putBucketPolicy(bucket, policyJson);
        if (!res) LOG_WARN("propagate bucket policy to ", bucket, ": ", res.error());
    }
    state_.setBucketSettingsHash(rep.name, bucket, hash);
    auto saved = state_.persist();
    if (!saved) LOG_WARN("persist bucket settings hash: ", saved.error());
    LOG_INFO("replication '", rep.name, "': propagated settings of bucket ", bucket, " to ", rep.destination);
    return Result<void>::success();
}

Result<void> Engine::scanBucket(RepState& st, const s3::BucketInfo& bucket) {
    const auto& rep = *st.rep;
    auto& stat = stats_.forReplication(rep.name);
    BucketCache& cache = state_.bucket(rep.name, rep.source, bucket.name);

    // ---- bucket metadata
    std::string location = st.source->getBucketLocation(bucket.name).valueOr("");
    std::string versioning = st.source->getBucketVersioning(bucket.name).valueOr("");
    std::string policyJson = st.source->getBucketPolicy(bucket.name).valueOr("");
    std::string policyHash = policyJson.empty() ? std::string("-") : crypto::sha256Hex(policyJson);
    std::string zone, srcVendor, destZone, destVendor, destLocation;
    if (const registry::Cluster* c = registry_.cluster(rep.source)) {
        zone = c->zone;
        srcVendor = c->vendor;
    }
    if (const registry::Cluster* c = registry_.cluster(rep.destination)) {
        destZone = c->zone;
        destVendor = c->vendor;
        destLocation = c->location;
    }

    const bool needCounts = mentionsRule(st.bundle, policy::Category::Bucket, "object-count") ||
                            mentionsRule(st.bundle, policy::Category::Bucket, "total-size");
    std::string type = "private";
    if (mentionsRule(st.bundle, policy::Category::Bucket, "type")) {
        auto isPublic = st.source->isBucketPublic(bucket.name);
        if (isPublic && isPublic.value()) type = "public";
    }
    std::string owner;
    if (mentionsRule(st.bundle, policy::Category::Bucket, "owner")) {
        auto acl = st.source->getBucketAcl(bucket.name);
        if (acl) owner = acl.value().owner;
    }
    std::string encryption;
    if (mentionsRule(st.bundle, policy::Category::Bucket, "encryption")) {
        http::Request req;
        req.method = "GET";
        req.url = st.source->primaryEndpoint() + "/" + bucket.name;
        req.query["encryption"] = "";
        auto resp = st.source->raw(req);
        if (resp.status == 200) {
            auto doc = xml::parse(resp.body);
            if (doc) {
                const xml::Element* rule = doc.value().child("Rule");
                const xml::Element* def = rule ? rule->child("ApplyServerSideEncryptionByDefault") : nullptr;
                if (def) encryption = def->childText("SSEAlgorithm");
            }
        }
    }
    std::map<std::string, std::string> tags;
    if (mentionsRule(st.bundle, policy::Category::Bucket, "tags")) {
        auto tagging = st.source->getBucketTagging(bucket.name);
        if (tagging) tags = tagging.value().tags;
    }

    // ---- listing (only when needed for the bucket decision or for the delta)
    std::map<std::string, s3::ObjectInfo> current;
    uint64_t totalCount = 0, totalSize = 0;
    bool listed = false;
    auto listPass = [&]() -> Result<void> {
        std::string token;
        do {
            auto page = st.source->listObjects(bucket.name, {}, {}, token, 1000);
            if (!page) return Result<void>::failure(page.error());
            for (const auto& o : page.value().objects) {
                current[o.key] = o;
                totalCount++;
                totalSize += o.size;
            }
            token = page.value().truncated ? page.value().nextToken : std::string();
        } while (!token.empty());
        listed = true;
        return Result<void>::success();
    };
    if (needCounts) {
        auto res = listPass();
        if (!res) return res;
    }

    policy::Context bctx = bucketContext(bucket.name, rep.source, zone, srcVendor, location, versioning, type, owner,
                                         encryption, policyHash, bucket.created, totalCount, totalSize);
    bctx.setTags("tags.", tags);
    for (const auto& [k, v] : tags) bctx.setAlias("tags." + k, "source.tags." + k);
    bctx.set("destination.name", rep.destination);
    bctx.set("destination.zone", destZone);
    bctx.set("destination.location", destLocation);

    policy::Decision bdec = policyEngine_.evaluate(st.bundle, policy::Category::Bucket, bctx, rep.name);

    {
        RouteInfo ri;
        ri.atSec = nowSec();
        ri.replication = rep.name;
        ri.kind = "bucket";
        ri.bucket = bucket.name;
        ri.outcome = bdec.outcome;
        ri.target = bdec.target;
        ri.rule = bdec.rule ? (bdec.rule->name.empty() ? std::to_string(bdec.rule->order) : bdec.rule->name)
                            : std::string("default");
        ri.reason = bdec.toString();
        record(std::move(ri));
    }
    if (bdec.outcome == "success") stat.accepted++;
    else if (bdec.outcome == "denied") stat.denied++;
    else stat.warned++;

    if (bdec.outcome != "success") {
        // the bucket does not replicate at all: no object listing, no delta
        Candidate c;
        c.kind = Candidate::Kind::Bucket;
        c.replication = rep.name;
        c.bucket = bucket.name;
        c.lastModified = bucket.created;
        c.outcome = bdec.outcome;
        c.target = bdec.target;
        c.rule = bdec.rule ? (bdec.rule->name.empty() ? std::to_string(bdec.rule->order) : bdec.rule->name)
                           : std::string("default");
        c.reason = bdec.toString();
        return deliver(st, c);
    }

    // ---- bucket settings propagation (delta by settings hash)
    bool propagateSettings = false;
    for (const auto& a : bdec.actions) {
        if (a.name != "propagate") continue;
        if (a.positional == "settings" || a.param("settings", "true") == "true" || a.param("settings", "yes") == "yes")
            propagateSettings = true;
    }
    if (propagateSettings) {
        auto res = propagateBucketSettings(st, bucket.name, versioning, location, policyJson);
        if (!res) LOG_WARN("bucket ", bucket.name, ": propagate settings: ", res.error());
    }

    if (!listed) {
        auto res = listPass();
        if (!res) return res;
    }

    // ---- deletions observed on the source
    std::vector<std::string> gone;
    for (const auto& [key, entry] : cache.entries())
        if (!entry.deleted && !current.count(key)) gone.push_back(key);
    for (const auto& key : gone) {
        cache.markDeleted(key, tm::now());
        stat.deltaDetected++;
        LOG_DEBUG("replication '", rep.name, "': deletion of ", bucket.name, "/", key, " observed on the source");
    }
    std::vector<std::string> tombstones;
    for (const auto& [key, entry] : cache.entries())
        if (entry.deleted) tombstones.push_back(key);
    for (const auto& key : tombstones) {
        if (!rep.deletePropagation) {
            cache.forget(key); // propagation disabled: just forget
            continue;
        }
        const CacheEntry& entry = cache.entries().at(key);
        int64_t age = elapsed((int64_t)tm::toSeconds(entry.deletedAt));
        if (rep.retentionSec > 0 && age < rep.retentionSec) continue; // wait out the retention window

        s3::ObjectInfo info;
        info.key = key;
        info.size = entry.size;
        info.etag = entry.etag;
        info.lastModified = entry.lastModified;
        info.versionId = entry.versionId;
        policy::Context dctx = objectContext(bucket.name, key, info.size, info.etag, info.lastModified,
                                             info.storageClass, info.versionId, {}, 0, {}, true);
        policy::Decision d = policyEngine_.evaluate(st.bundle, policy::Category::Object, dctx, rep.name);

        Candidate c;
        c.kind = Candidate::Kind::Delete;
        c.replication = rep.name;
        c.bucket = bucket.name;
        c.key = key;
        c.versionId = info.versionId;
        c.lastModified = entry.deletedAt;
        c.outcome = d.outcome;
        c.target = d.target;
        c.rule = d.rule ? (d.rule->name.empty() ? std::to_string(d.rule->order) : d.rule->name) : std::string("default");
        c.reason = d.toString();

        RouteInfo ri;
        ri.atSec = nowSec();
        ri.replication = rep.name;
        ri.kind = "delete";
        ri.bucket = bucket.name;
        ri.key = key;
        ri.outcome = d.outcome;
        ri.target = d.target;
        ri.rule = c.rule;
        ri.reason = c.reason;
        record(std::move(ri));
        if (d.outcome == "success") stat.accepted++;
        else if (d.outcome == "denied") stat.denied++;
        else stat.warned++;

        if (d.outcome == "success") {
            std::string qk = bucket.name + "\x1f" + key;
            std::lock_guard<std::mutex> lock(st.queueMutex);
            if (st.queuedKeys.insert(qk).second) {
                if (st.queue.empty()) st.queueSinceSec = nowSec();
                st.queue.push_back(QueuedItem{std::move(c), nowSec()});
            }
        } else {
            auto res = deliver(st, c);
            if (res) cache.forget(key); // settled elsewhere: drop the tombstone
        }
    }

    // ---- object delta
    const bool needHead = mentionsRule(st.bundle, policy::Category::Object, "content-type") ||
                          mentionsRule(st.bundle, policy::Category::Object, "chunk-count");
    for (const auto& [key, o] : current) {
        stat.objectsScanned++;
        if (!cache.changed(o)) continue;

        std::string qk = bucket.name + "\x1f" + key;
        {
            std::lock_guard<std::mutex> lock(st.queueMutex);
            if (st.queuedKeys.count(qk)) continue; // already waiting for shipment
        }
        stat.deltaDetected++;
        stat.bytesDetected += o.size;

        s3::ObjectMeta meta;
        if (needHead) {
            auto head = st.source->headObject(bucket.name, key);
            if (head) meta = head.value();
        }
        policy::Context octx = objectContext(bucket.name, key, o.size, o.etag, o.lastModified, o.storageClass,
                                             o.versionId, meta.contentType, meta.parts, meta.userMeta, false);
        policy::Decision d = policyEngine_.evaluate(st.bundle, policy::Category::Object, octx, rep.name);

        Candidate c = Candidate::fromDecision(d, o, rep.name, bucket.name);
        c.versionId = o.versionId;
        c.contentType = meta.contentType;
        c.meta = d.transforms();

        RouteInfo ri;
        ri.atSec = nowSec();
        ri.replication = rep.name;
        ri.kind = "object";
        ri.bucket = bucket.name;
        ri.key = key;
        ri.outcome = d.outcome;
        ri.target = d.target;
        ri.rule = c.rule;
        ri.reason = c.reason;
        ri.size = o.size;
        record(std::move(ri));

        if (d.outcome == "success") {
            stat.accepted++;
            std::lock_guard<std::mutex> lock(st.queueMutex);
            if (st.queuedKeys.insert(qk).second) {
                if (st.queue.empty()) st.queueSinceSec = nowSec();
                st.queue.push_back(QueuedItem{std::move(c), nowSec()});
            }
        } else {
            if (d.outcome == "denied") stat.denied++;
            else stat.warned++;
            auto res = deliver(st, c);
            if (res) cache.observe(o); // settled: do not re-evaluate until the source changes
        }
    }

    return Result<void>::success();
}

Result<void> Engine::shipReady(RepState& st, bool force) {
    const auto& rep = *st.rep;
    auto& stat = stats_.forReplication(rep.name);
    const Thresholds th = thresholds(rep);

    std::vector<QueuedItem> items;
    {
        std::lock_guard<std::mutex> lock(st.queueMutex);
        if (st.queue.empty()) return Result<void>::success();
        uint64_t bytes = 0, qualifying = 0;
        for (const auto& item : st.queue) {
            bytes += item.candidate.size;
            if ((int64_t)item.candidate.size >= th.minSizeBytes) qualifying += item.candidate.size;
        }
        int64_t age = st.queue.empty() ? 0 : elapsed(st.queueSinceSec);
        if (!force && !thresholdsReached(th, bytes, qualifying, age)) return Result<void>::success();
        items = std::move(st.queue);
        st.queue.clear();
        st.queuedKeys.clear();
    }

    LOG_DEBUG("replication '", rep.name, "': shipping ", items.size(), " item(s)",
              force ? " (forced)" : "");
    tm::TimePoint shipStarted = tm::now();

    std::vector<QueuedItem> retry;
    for (auto& item : items) {
        auto res = deliver(st, item.candidate);
        if (!res && item.candidate.attempts < registry_.settings().retries) retry.push_back(std::move(item));
        else if (!res)
            LOG_ERROR("replication '", rep.name, "': giving up on ", item.candidate.bucket, "/",
                      item.candidate.key, " after ", item.candidate.attempts, " attempts: ", res.error());
    }
    if (!retry.empty()) {
        std::lock_guard<std::mutex> lock(st.queueMutex);
        for (auto& item : retry) {
            std::string qk = item.candidate.bucket + "\x1f" + item.candidate.key;
            if (st.queuedKeys.insert(qk).second) {
                if (st.queue.empty()) st.queueSinceSec = nowSec();
                st.queue.push_back(std::move(item));
            }
        }
    }
    stat.lastShipMs = std::chrono::duration_cast<std::chrono::milliseconds>(tm::now() - shipStarted).count();
    stat.lastShip = tm::now();
    persistDirty();
    return Result<void>::success();
}

Result<void> Engine::scanReplication(RepState& st) {
    const auto& rep = *st.rep;
    auto& stat = stats_.forReplication(rep.name);

    {
        std::lock_guard<std::mutex> lock(st.initMutex);
        if (!st.initialized) {
            const registry::Cluster* srcCluster = registry_.cluster(rep.source);
            const registry::Cluster* dstCluster = registry_.cluster(rep.destination);
            if (!srcCluster) return Result<void>::failure("unknown source cluster '" + rep.source + "'");
            if (!dstCluster) return Result<void>::failure("unknown destination cluster '" + rep.destination + "'");
            auto src = accounts_.clientFor(*srcCluster);
            if (!src) return Result<void>(src.error());
            auto dst = accounts_.clientFor(*dstCluster);
            if (!dst) return Result<void>(dst.error());
            st.source = src.value();
            st.destination = dst.value();
            st.bundle = registry_.bundleOrBuiltin(rep.policy);
            auto routes = targets_.routesFor(rep);
            if (!routes) return Result<void>(routes.error());
            st.routes = routes.value();
            for (TargetGroupPtr* group : {&st.routes.success, &st.routes.denied, &st.routes.warning}) {
                if (auto s3target = std::dynamic_pointer_cast<S3Target>(*group))
                    s3target->bind(st.destination, st.source.get());
            }
            st.initialized = true;
        }
    }

    // ---- accounts (access policies + admin sync through vendor modules)
    auto accept = [&](const module::Account& account) {
        policy::Context actx = accountContext(account);
        policy::Decision d = policyEngine_.evaluate(st.bundle, policy::Category::Access, actx, rep.name);
        RouteInfo ri;
        ri.atSec = nowSec();
        ri.replication = rep.name;
        ri.kind = "account";
        ri.key = account.accessKey;
        ri.outcome = d.outcome;
        ri.target = d.target;
        ri.rule = d.rule ? (d.rule->name.empty() ? std::to_string(d.rule->order) : d.rule->name) : std::string("default");
        ri.reason = d.toString();
        record(std::move(ri));
        if (d.outcome == "success") {
            stat.accepted++;
            return true;
        }
        if (d.outcome == "denied") stat.denied++;
        else stat.warned++;
        Candidate c;
        c.kind = Candidate::Kind::Account;
        c.replication = rep.name;
        c.account = account.accessKey;
        c.outcome = d.outcome;
        c.target = d.target;
        c.rule = ri.rule;
        c.reason = d.toString();
        deliver(st, c);
        return false;
    };
    auto sync = accounts_.sync(rep, false, rep.deletePropagation, accept);
    if (sync) {
        stat.accountsSynced += sync.value().created + sync.value().updated;
        if (!sync.value().empty())
            LOG_INFO("replication '", rep.name, "': account sync created=", sync.value().created,
                     " updated=", sync.value().updated, " deleted=", sync.value().deleted,
                     " matched=", sync.value().matched);
    } else {
        LOG_DEBUG("replication '", rep.name, "': account sync skipped: ", sync.error());
    }

    // ---- buckets
    auto buckets = st.source->listBuckets();
    if (!buckets) {
        stat.lastError = tm::now();
        stat.lastErrorText = buckets.error();
        return Result<void>(buckets.error());
    }
    for (const auto& bucket : buckets.value()) {
        if (!glob::matchFilter(rep.buckets, bucket.name)) continue;
        stat.bucketsScanned++;
        auto res = scanBucket(st, bucket);
        if (!res) {
            LOG_WARN("replication '", rep.name, "': bucket ", bucket.name, ": ", res.error());
            stat.lastError = tm::now();
            stat.lastErrorText = res.error();
        }
    }
    stat.scanCycles++;
    stat.lastScan = tm::now();
    return Result<void>::success();
}

// ------------------------------------------------------------- scheduling ---

void Engine::processScan(const std::string& name) {
    RepState* st = nullptr;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        auto it = reps_.find(name);
        if (it == reps_.end()) return;
        st = it->second.get();
    }
    std::lock_guard<std::mutex> op(st->opMutex);
    st->scanQueued.store(false); // allow the scheduler to queue the next scan
    auto& stat = stats_.forReplication(name);
    stat.inFlight = true;
    st->inScan.store(true);
    int64_t t0 = nowSec();
    auto res = scanReplication(*st);
    if (!res) {
        LOG_ERROR("replication '", name, "': scan failed: ", res.error());
        stat.lastError = tm::now();
        stat.lastErrorText = res.error();
    }
    stat.lastScanMs = (nowSec() - t0) * 1000;
    stat.inFlight = false;
    st->inScan.store(false);
    st->lastScanSec = nowSec();
    shipReady(*st, false);
}

void Engine::processShip(const std::string& name, bool force) {
    RepState* st = nullptr;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        auto it = reps_.find(name);
        if (it == reps_.end()) return;
        st = it->second.get();
    }
    std::lock_guard<std::mutex> op(st->opMutex);
    st->shipQueued.store(false); // allow the scheduler to queue the next shipment
    auto res = shipReady(*st, force);
    if (!res) LOG_ERROR("replication '", name, "': shipment failed: ", res.error());
}

void Engine::queueWork(const std::string& replication, bool scan, bool force) {
    WorkItem item{replication, scan, force};
    std::lock_guard<std::mutex> lock(workMutex_);
    if (poolMode_) {
        sharedQueue_.push_back(item);
    } else {
        const registry::Replication* rep = registry_.replication(replication);
        policyQueues_[rep ? policyName(*rep) : std::string("default")].push_back(item);
    }
    workCv_.notify_all();
}

void Engine::schedulerLoop() {
    while (!stop_) {
        for (int i = 0; i < 10 && !stop_; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (stop_) break;
        for (const auto& rep : registry_.replications()) {
            if (rep.paused) continue;
            RepState* st = ensureState(rep);
            if (!st) continue;
            int64_t scanEvery = rep.scanEverySec > 0 ? rep.scanEverySec
                                                     : (registry_.settings().bucketScanEverySec > 0
                                                            ? registry_.settings().bucketScanEverySec
                                                            : registry_.settings().scanEverySec);
            if (scanEvery <= 0) scanEvery = 300;
            if (elapsed(st->lastScanSec) >= scanEvery) {
                bool expected = false;
                if (st->scanQueued.compare_exchange_strong(expected, true)) queueWork(rep.name, true, false);
                continue;
            }
            // time/size trigger between scans
            const Thresholds th = thresholds(rep);
            bool due = false;
            {
                std::lock_guard<std::mutex> lock(st->queueMutex);
                if (!st->queue.empty()) {
                    uint64_t bytes = 0, qualifying = 0;
                    for (const auto& item : st->queue) {
                        bytes += item.candidate.size;
                        if ((int64_t)item.candidate.size >= th.minSizeBytes) qualifying += item.candidate.size;
                    }
                    due = thresholdsReached(th, bytes, qualifying, elapsed(st->queueSinceSec));
                }
            }
            if (due) {
                bool expected = false;
                if (st->shipQueued.compare_exchange_strong(expected, true)) queueWork(rep.name, false, false);
            }
        }
    }
}

void Engine::workerLoop(const std::string& policyFilter) {
    std::unique_lock<std::mutex> lock(workMutex_);
    while (!stop_) {
        WorkItem item;
        bool have = false;
        if (poolMode_) {
            workCv_.wait_for(lock, std::chrono::milliseconds(500),
                             [this] { return stop_.load() || !sharedQueue_.empty(); });
            if (!sharedQueue_.empty()) {
                item = sharedQueue_.front();
                sharedQueue_.pop_front();
                have = true;
            }
        } else {
            auto& queue = policyQueues_[policyFilter];
            workCv_.wait_for(lock, std::chrono::milliseconds(500),
                             [&] { return stop_.load() || !queue.empty(); });
            if (!queue.empty()) {
                item = queue.front();
                queue.pop_front();
                have = true;
            }
        }
        if (!have) continue;
        lock.unlock();
        if (item.scan) {
            processScan(item.replication);
        } else {
            processShip(item.replication, item.force);
        }
        lock.lock();
    }
}

Result<void> Engine::start() {
    if (scheduler_.joinable()) return Result<void>::success();
    stop_ = false;
    poolMode_ = registry_.settings().workerCount > 0;
    if (poolMode_) {
        int n = std::max(1, registry_.settings().workerCount);
        for (int i = 0; i < n; ++i) workers_.emplace_back([this] { workerLoop(std::string()); });
    } else {
        std::set<std::string> policies;
        for (const auto& rep : registry_.replications()) policies.insert(policyName(rep));
        if (policies.empty()) policies.insert("default");
        for (const auto& policy : policies) {
            std::lock_guard<std::mutex> lock(workMutex_);
            policyQueues_[policy];
            workers_.emplace_back([this, policy] { workerLoop(policy); });
        }
    }
    scheduler_ = std::thread([this] { schedulerLoop(); });
    LOG_INFO("replication engine started: ", workers_.size(), " worker(s)",
             poolMode_ ? " (shared pool)" : " (dedicated per policy)");
    return Result<void>::success();
}

void Engine::stop() {
    if (!scheduler_.joinable() && workers_.empty()) return;
    stop_ = true;
    workCv_.notify_all();
    if (scheduler_.joinable()) scheduler_.join();
    for (auto& worker : workers_)
        if (worker.joinable()) worker.join();
    workers_.clear();
    persistDirty();
    LOG_INFO("replication engine stopped");
}

Result<void> Engine::rebuild() {
    bool wasRunning = running();
    stop();
    stop_ = false;
    if (wasRunning) return start();
    return Result<void>::success();
}

void Engine::kick() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    for (auto& [name, st] : reps_) st->lastScanSec = 0;
}

Result<void> Engine::flush(const std::string& replication) {
    RepState* st = nullptr;
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        auto it = reps_.find(replication);
        if (it != reps_.end()) st = it->second.get();
    }
    if (!st) {
        // unknown to the engine yet: create the state so a flush still works
        const registry::Replication* rep = registry_.replication(replication);
        if (!rep) return Result<void>::failure("unknown replication '" + replication + "'");
        st = ensureState(*rep);
    }
    std::lock_guard<std::mutex> op(st->opMutex);
    auto res = shipReady(*st, true);
    if (!res) LOG_ERROR("replication '", replication, "': forced shipment failed: ", res.error());
    return res;
}

Result<void> Engine::runOnce(const std::string& onlyReplication, bool forceShip) {
    for (const auto& rep : registry_.replications()) {
        if (!onlyReplication.empty() && rep.name != onlyReplication) continue;
        if (rep.paused) continue;
        RepState* st = ensureState(rep);
        if (!st) continue;
        std::lock_guard<std::mutex> op(st->opMutex);
        auto& stat = stats_.forReplication(rep.name);
        stat.inFlight = true;
        auto res = scanReplication(*st);
        stat.inFlight = false;
        if (!res) {
            LOG_ERROR("replication '", rep.name, "': scan failed: ", res.error());
            stat.lastError = tm::now();
            stat.lastErrorText = res.error();
        }
        st->lastScanSec = nowSec();
        auto shipped = shipReady(*st, forceShip);
        if (!shipped) LOG_ERROR("replication '", rep.name, "': shipment failed: ", shipped.error());
    }
    persistDirty();
    return Result<void>::success();
}

void Engine::refreshState() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    for (auto it = reps_.begin(); it != reps_.end();) {
        const registry::Replication* rep = registry_.replication(it->first);
        if (!rep) { // removed by the CLI mutation: drop the whole state
            it = reps_.erase(it);
            continue;
        }
        it->second->rep = rep;
        // force re-resolution of clients/bundle/routes on the next scan
        std::lock_guard<std::mutex> init(it->second->initMutex);
        it->second->initialized = false;
        ++it;
    }
}

Result<SyncReport> Engine::syncAccounts(const std::string& replication, bool dryRun, bool prune) {
    const registry::Replication* rep = registry_.replication(replication);
    if (!rep) return Result<SyncReport>::failure("unknown replication '" + replication + "'");
    RepState* st = ensureState(*rep);
    if (!st) return Result<SyncReport>::failure("no state for replication '" + replication + "'");
    std::lock_guard<std::mutex> op(st->opMutex);
    {
        std::lock_guard<std::mutex> lock(st->initMutex);
        if (!st->initialized) {
            st->bundle = registry_.bundleOrBuiltin(rep->policy);
            st->initialized = true;
        }
    }
    auto& stat = stats_.forReplication(replication);
    auto accept = [&](const module::Account& account) {
        policy::Context actx = accountContext(account);
        policy::Decision d = policyEngine_.evaluate(st->bundle, policy::Category::Access, actx, rep->name);
        RouteInfo ri;
        ri.atSec = nowSec();
        ri.replication = rep->name;
        ri.kind = "account";
        ri.key = account.accessKey;
        ri.outcome = d.outcome;
        ri.target = d.target;
        ri.rule = d.rule ? (d.rule->name.empty() ? std::to_string(d.rule->order) : d.rule->name) : std::string("default");
        ri.reason = d.toString();
        record(std::move(ri));
        if (d.outcome == "success") {
            stat.accepted++;
            return true;
        }
        if (d.outcome == "denied") stat.denied++;
        else stat.warned++;
        Candidate c;
        c.kind = Candidate::Kind::Account;
        c.replication = rep->name;
        c.account = account.accessKey;
        c.outcome = d.outcome;
        c.target = d.target;
        c.rule = ri.rule;
        c.reason = d.toString();
        deliver(*st, c);
        return false;
    };
    auto report = accounts_.sync(*rep, dryRun, prune, accept);
    if (report) stat.accountsSynced += report.value().created + report.value().updated;
    return report;
}

} // namespace s3mm::repl
