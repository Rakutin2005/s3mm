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

void hashField(std::string& out, const std::string& value) {
    out += std::to_string(value.size());
    out += ':';
    out += value;
    out += '\n';
}

std::string metadataFingerprint(const s3::ObjectMeta& meta) {
    std::string canonical;
    hashField(canonical, meta.contentType);
    hashField(canonical, meta.contentEncoding);
    hashField(canonical, meta.contentLanguage);
    hashField(canonical, meta.contentDisposition);
    hashField(canonical, meta.cacheControl);
    hashField(canonical, meta.expires);
    hashField(canonical, meta.storageClass);
    for (const auto& [k, v] : meta.userMeta) {
        hashField(canonical, k);
        hashField(canonical, v);
    }
    return crypto::sha256Hex(canonical);
}

std::string tagsFingerprint(const std::map<std::string, std::string>& tags) {
    std::string canonical;
    for (const auto& [k, v] : tags) {
        hashField(canonical, k);
        hashField(canonical, v);
    }
    return crypto::sha256Hex(canonical);
}

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
      targets_(registry, &loader) {
    LOG_DEBUG("replication engine created: state dir ", fs::joinPath(registry.settings().cacheDir, "state"),
              ", ", registry.replications().size(), " replication(s) configured");
}

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
    LOG_DEBUG("replication '", rep.name, "': state created (source=", rep.source, " destination=", rep.destination,
              " policy=", policyName(rep), ")");
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
    if (pending.empty()) return;
    log::Stopwatch sw;
    size_t saved = 0, failed = 0;
    for (const auto& key : pending) {
        auto slash = key.find('/');
        auto slash2 = slash == std::string::npos ? std::string::npos : key.find('/', slash + 1);
        if (slash2 == std::string::npos) {
            LOG_WARN("delta cache save: malformed dirty key '", key, "' ignored");
            continue;
        }
        std::string rep = key.substr(0, slash);
        std::string source = key.substr(slash + 1, slash2 - slash - 1);
        std::string bucket = key.substr(slash2 + 1);
        // StateStore::bucket loads (and caches) the bucket state on demand
        auto res = state_.bucket(rep, source, bucket).save();
        if (!res) {
            failed++;
            LOG_WARN("delta cache save for replication '", rep, "' source ", source, " bucket ", bucket, ": ",
                     res.error());
        } else {
            saved++;
            LOG_DEBUG("delta cache saved: replication '", rep, "' source ", source, " bucket ", bucket);
        }
    }
    if (!pending.empty()) {
        auto res = state_.persist();
        if (!res) LOG_WARN("state persist (", state_.root(), "): ", res.error());
    }
    LOG_DEBUG("persisted ", saved, " dirty delta cache(s), ", failed, " failed, in ", sw.ms(), " ms");
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
        if (auto s3target = std::dynamic_pointer_cast<S3Target>(group)) s3target->bind(st.destination, st.source.get(), registry_.settings().cacheDir);
        LOG_DEBUG("replication '", candidate.replication, "': resolved ad-hoc target '", candidate.target,
                  "' (", group->kind(), ")");
        return group;
    } else {
        LOG_DEBUG("replication '", candidate.replication, "': target '", candidate.target,
                  "' cannot be created: ", created.error());
    }
    // Unknown target: never silently ship into a basket the operator did not name.
    // denied/warning keep their explicit routes (quarantine must stay reachable);
    // success-side unknowns are dropped to the denied route and reported.
    LOG_WARN("unknown target '", candidate.target, "' for replication '", candidate.replication,
             "': refusing to fall back to the success route");
    if (candidate.outcome == "warning" && st.routes.warning) return st.routes.warning;
    if (st.routes.denied) return st.routes.denied;
    return nullptr; // no denied route -> deliver() reports "no target resolved"
}

Result<void> Engine::deliver(RepState& st, Candidate& candidate) {
    auto& stat = stats_.forReplication(candidate.replication);
    TargetGroupPtr target = resolveTarget(st, candidate);
    if (!target) {
        stat.failed++;
        LOG_ERROR("replication '", candidate.replication, "': no target resolved for ", kindName(candidate.kind), " ",
                  candidate.bucket, "/", candidate.key.empty() ? candidate.account : candidate.key, " (target '",
                  candidate.target, "', outcome ", candidate.outcome, ")");
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
    rec.versionId = candidate.versionId;
    rec.lastModified = candidate.lastModified;
    rec.contentType = candidate.contentType;
    rec.meta = candidate.meta;

    LOG_DEBUG("replication '", candidate.replication, "': delivering ", rec.kind, " ", candidate.bucket, "/",
              candidate.key.empty() ? candidate.account : candidate.key, " (", candidate.size, " bytes, outcome ",
              candidate.outcome, ", rule ", candidate.rule, ", attempt ", candidate.attempts + 1, ") to ",
              target->name());
    log::Stopwatch sw;
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
                auto& cache = state_.bucket(candidate.replication, rep->source, candidate.bucket);
                cache.markShipped(info);
                if (!candidate.metadataHash.empty())
                    cache.noteMetadata(candidate.key, candidate.metadataHash, candidate.tagsHash, tm::now());
                markDirty(candidate.replication, rep->source, candidate.bucket);
            }
            if (candidate.lastModified > tm::TimePoint{}) {
                double lag = (double)std::chrono::duration_cast<std::chrono::seconds>(tm::now() - candidate.lastModified).count();
                stat.lastLagSec = lag;
                stat.maxLagSec = std::max(stat.maxLagSec, lag);
            }
            LOG_DEBUG("replication '", candidate.replication, "': shipped ", candidate.bucket, "/", candidate.key,
                      " (", candidate.size, " bytes) via ", target->name(), " in ", sw.ms(), " ms");
        } else if (candidate.kind == Candidate::Kind::Delete) {
            stat.deleted++;
            if (const registry::Replication* rep = registry_.replication(candidate.replication)) {
                state_.bucket(candidate.replication, rep->source, candidate.bucket).forget(candidate.key);
                markDirty(candidate.replication, rep->source, candidate.bucket);
            }
            LOG_INFO("replication '", candidate.replication, "': propagated deletion of ", candidate.bucket, "/",
                     candidate.key, " via ", target->name());
        } else {
            stat.shipped++;
            LOG_DEBUG("replication '", candidate.replication, "': delivered ", rec.kind, " ",
                      candidate.kind == Candidate::Kind::Account ? candidate.account : candidate.bucket, " to ",
                      target->name(), " (outcome ", candidate.outcome, ") in ", sw.ms(), " ms");
        }
    } else {
        stat.failed++;
        stat.lastErrorText = res.error();
        stat.lastError = tm::now();
        candidate.attempts++;
        LOG_WARN("replication '", candidate.replication, "': delivery of ", kindName(candidate.kind), " ",
                 candidate.bucket, "/", candidate.key.empty() ? candidate.account : candidate.key, " to ",
                 target->name(), " failed (attempt ", candidate.attempts, ", ", sw.ms(), " ms): ", res.error());
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
    if (!tagging) LOG_DEBUG("replication '", rep.name, "': bucket ", bucket, " tagging unavailable: ", tagging.error());
    if (state_.bucketSettingsHash(rep.name, bucket) == hash) { // no delta
        LOG_DEBUG("replication '", rep.name, "': bucket ", bucket, " settings unchanged, nothing to propagate");
        return Result<void>::success();
    }
    LOG_DEBUG("replication '", rep.name, "': bucket ", bucket, " settings changed (versioning=",
              versioning.empty() ? "-" : versioning, " location=", location.empty() ? "-" : location, " tags=",
              tags.tags.size(), " policy=", policyJson.empty() ? "none" : "set", "), propagating to ", rep.destination);

    auto exists = st.destination->headBucket(bucket);
    if (!exists) {
        LOG_ERROR("replication '", rep.name, "': HEAD bucket ", bucket, " on ", rep.destination, ": ", exists.error());
        return Result<void>(exists.error());
    }
    if (!exists.value()) {
        LOG_DEBUG("replication '", rep.name, "': creating bucket ", bucket, " on ", rep.destination,
                  location.empty() ? "" : " in ", location);
        auto created = st.destination->createBucket(bucket, location);
        if (!created) {
            LOG_ERROR("replication '", rep.name, "': create bucket ", bucket, " on ", rep.destination, ": ",
                      created.error());
            return Result<void>(created.error());
        }
        LOG_INFO("replication '", rep.name, "': created bucket ", bucket, " on ", rep.destination);
    }
    bool ok = true;
    std::string firstError;
    auto remember = [&](const std::string& what, const std::string& err) {
        LOG_WARN("replication '", rep.name, "': propagate ", what, " to ", rep.destination, "/", bucket, ": ", err);
        if (ok) firstError = what + ": " + err;
        ok = false;
    };
    if (!versioning.empty()) {
        auto res = st.destination->putBucketVersioning(bucket, versioning);
        if (!res) remember("versioning", res.error());
    }
    // Always apply the full tag/policy state so removals also propagate.
    auto tagRes = st.destination->putBucketTagging(bucket, tags);
    if (!tagRes) remember("tagging", tagRes.error());
    if (!policyJson.empty()) {
        auto res = st.destination->putBucketPolicy(bucket, policyJson);
        if (!res) remember("bucket policy", res.error());
    } else {
        auto res = st.destination->deleteBucketPolicy(bucket);
        if (!res) remember("bucket policy removal", res.error());
    }
    if (!ok) return Result<void>::failure(firstError);
    state_.setBucketSettingsHash(rep.name, bucket, hash);
    auto saved = state_.persist();
    if (!saved) LOG_WARN("replication '", rep.name, "': persist bucket settings hash of ", bucket, ": ", saved.error());
    LOG_INFO("replication '", rep.name, "': propagated settings of bucket ", bucket, " to ", rep.destination);
    return Result<void>::success();
}

Result<void> Engine::scanBucket(RepState& st, const s3::BucketInfo& bucket) {
    const auto& rep = *st.rep;
    auto& stat = stats_.forReplication(rep.name);
    BucketCache& cache = state_.bucket(rep.name, rep.source, bucket.name);
    log::Stopwatch sw;
    LOG_DEBUG("replication '", rep.name, "': scanning bucket ", rep.source, "/", bucket.name, " (", cache.size(),
              " cached entries)");

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
            } else {
                LOG_WARN("replication '", rep.name, "': bucket ", bucket.name, " encryption response unparsable: ",
                         doc.error(), "; body ", log::clip(resp.body));
            }
        } else {
            LOG_DEBUG("replication '", rep.name, "': bucket ", bucket.name, " GET ?encryption -> HTTP ", resp.status,
                      " (treated as none)");
        }
    }
    std::map<std::string, std::string> tags;
    if (mentionsRule(st.bundle, policy::Category::Bucket, "tags")) {
        auto tagging = st.source->getBucketTagging(bucket.name);
        if (tagging) tags = tagging.value().tags;
    }

    // ---- listing. Bucket decisions only need counts; the delta pass below
    // streams objects page by page instead of materialising the whole bucket.
    std::set<std::string> seen;
    uint64_t totalCount = 0, totalSize = 0;
    auto listCounts = [&]() -> Result<void> {
        std::string token;
        do {
            auto page = st.source->listObjects(bucket.name, {}, {}, token, 1000);
            if (!page) {
                LOG_ERROR("replication '", rep.name, "': list objects of ", bucket.name, " (counting): ", page.error());
                return Result<void>::failure(page.error());
            }
            for (const auto& o : page.value().objects) {
                totalCount++;
                totalSize += o.size;
            }
            token = page.value().truncated ? page.value().nextToken : std::string();
        } while (!token.empty());
        return Result<void>::success();
    };
    if (needCounts) {
        auto res = listCounts();
        if (!res) return res;
        LOG_DEBUG("replication '", rep.name, "': bucket ", bucket.name, " holds ", totalCount, " object(s), ",
                  totalSize, " bytes");
    }
    LOG_DEBUG("replication '", rep.name, "': bucket ", bucket.name, " metadata: location=",
              location.empty() ? "-" : location, " versioning=", versioning.empty() ? "-" : versioning, " type=", type,
              " owner=", owner.empty() ? "-" : owner, " encryption=", encryption.empty() ? "none" : encryption,
              " tags=", tags.size(), " policy-hash=", policyHash);

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
    LOG_DEBUG("replication '", rep.name, "': bucket ", bucket.name, " decision: ", bdec.toString());

    if (bdec.outcome != "success") {
        LOG_INFO("replication '", rep.name, "': bucket ", bucket.name, " not replicated (outcome ", bdec.outcome,
                 ", target ", bdec.target, ")");
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

    // ---- object delta (streamed)
    const bool needHead = mentionsRule(st.bundle, policy::Category::Object, "content-type") ||
                          mentionsRule(st.bundle, policy::Category::Object, "chunk-count");
    const bool needTags = mentionsRule(st.bundle, policy::Category::Object, "tags.");
    const tm::TimePoint scanNow = tm::now();
    uint64_t listed = 0, unchanged = 0, alreadyQueued = 0, metaOnly = 0, changedCount = 0, queued = 0, routed = 0,
             routeFailed = 0, pages = 0;
    std::string token;
    do {
        auto page = st.source->listObjects(bucket.name, {}, {}, token, 1000);
        if (!page) {
            LOG_ERROR("replication '", rep.name, "': list objects of ", bucket.name, " (page ", pages + 1,
                      "): ", page.error());
            return Result<void>::failure(page.error());
        }
        pages++;
        LOG_DEBUG("replication '", rep.name, "': bucket ", bucket.name, " page ", pages, ": ",
                  page.value().objects.size(), " object(s)", page.value().truncated ? " (truncated)" : "");
        for (const auto& o : page.value().objects) {
            const std::string& key = o.key;
            seen.insert(key);
            stat.objectsScanned++;
            listed++;

            bool contentChanged = cache.changed(o);
            std::string qk = bucket.name + "\x1f" + key;
            {
                std::lock_guard<std::mutex> lock(st.queueMutex);
                if (st.queuedKeys.count(qk)) { // already waiting for shipment
                    alreadyQueued++;
                    LOG_DEBUG("replication '", rep.name, "': skip ", bucket.name, "/", key, ": already queued");
                    continue;
                }
            }
            bool due = contentChanged ||
                       (rep.metadataEverySec > 0 && cache.metadataDue(key, scanNow, rep.metadataEverySec));
            bool checkMeta = due || needHead || needTags;
            if (!checkMeta) {
                unchanged++;
                continue;
            }

            s3::ObjectMeta meta;
            auto head = st.source->headObject(bucket.name, key);
            if (head && head.value().exists) meta = head.value();
            else if (!head) LOG_DEBUG("replication '", rep.name, "': cannot read metadata of ", bucket.name, "/", key,
                                      ": ", head.error());
            auto tagging = st.source->getObjectTagging(bucket.name, key);
            if (tagging) meta.tags = tagging.value().tags;
            else LOG_DEBUG("replication '", rep.name, "': cannot read tags of ", bucket.name, "/", key, ": ",
                           tagging.error());

            std::string metaHash = metadataFingerprint(meta);
            std::string tagHash = tagsFingerprint(meta.tags);
            if (!contentChanged && !cache.metadataChanged(key, metaHash, tagHash)) {
                cache.noteMetadata(key, metaHash, tagHash, scanNow);
                unchanged++;
                continue;
            }
            if (contentChanged) changedCount++;
            else metaOnly++;
            LOG_DEBUG("replication '", rep.name, "': delta ", bucket.name, "/", key, " (",
                      contentChanged ? "content" : "metadata/tags", " changed, ", o.size, " bytes, etag ", o.etag, ")");

            stat.deltaDetected++;
            stat.bytesDetected += o.size;

            policy::Context octx = objectContext(bucket.name, key, o.size, o.etag, o.lastModified, o.storageClass,
                                                 o.versionId, meta.contentType, meta.parts, meta.tags, false);
            policy::Decision d = policyEngine_.evaluate(st.bundle, policy::Category::Object, octx, rep.name);

            Candidate c = Candidate::fromDecision(d, o, rep.name, bucket.name);
            c.versionId = o.versionId;
            c.contentType = meta.contentType;
            c.meta = d.transforms();
            c.metadataHash = metaHash;
            c.tagsHash = tagHash;

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
                    LOG_DEBUG("replication '", rep.name, "': queued ", bucket.name, "/", key, " (", o.size,
                              " bytes, rule ", c.rule, ", target ", c.target, "), queue depth ", st.queue.size() + 1);
                    st.queue.push_back(QueuedItem{std::move(c), nowSec()});
                    queued++;
                }
            } else {
                if (d.outcome == "denied") stat.denied++;
                else stat.warned++;
                LOG_DEBUG("replication '", rep.name, "': ", bucket.name, "/", key, " routed to ", d.outcome,
                          " target ", d.target, " (rule ", c.rule, ")");
                auto res = deliver(st, c);
                if (res) {
                    // settled: do not re-evaluate until the source changes
                    cache.observe(o);
                    cache.noteMetadata(key, metaHash, tagHash, scanNow);
                    routed++;
                } else {
                    routeFailed++;
                }
            }
        }
        token = page.value().truncated ? page.value().nextToken : std::string();
    } while (!token.empty());

    // ---- deletions observed on the source
    std::vector<std::string> gone;
    for (const auto& [key, entry] : cache.entries())
        if (!entry.deleted && !seen.count(key)) gone.push_back(key);
    if (!gone.empty())
        LOG_DEBUG("replication '", rep.name, "': bucket ", bucket.name, ": ", gone.size(),
                  " object(s) disappeared from the source");
    for (const auto& key : gone) {
        cache.markDeleted(key, tm::now());
        stat.deltaDetected++;
        LOG_DEBUG("replication '", rep.name, "': deletion of ", bucket.name, "/", key, " observed on the source");
    }
    std::vector<std::string> tombstones;
    for (const auto& [key, entry] : cache.entries())
        if (entry.deleted) tombstones.push_back(key);
    uint64_t tombForgotten = 0, tombWaiting = 0, tombQueued = 0, tombRouted = 0;
    for (const auto& key : tombstones) {
        if (!rep.deletePropagation) {
            cache.forget(key); // propagation disabled: just forget
            tombForgotten++;
            LOG_DEBUG("replication '", rep.name, "': forget tombstone ", bucket.name, "/", key,
                      " (delete propagation disabled)");
            continue;
        }
        const CacheEntry& entry = cache.entries().at(key);
        int64_t age = elapsed((int64_t)tm::toSeconds(entry.deletedAt));
        if (rep.retentionSec > 0 && age < rep.retentionSec) { // wait out the retention window
            tombWaiting++;
            LOG_DEBUG("replication '", rep.name, "': tombstone ", bucket.name, "/", key, " in retention (", age, "/",
                      rep.retentionSec, " s)");
            continue;
        }

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

        LOG_DEBUG("replication '", rep.name, "': deletion of ", bucket.name, "/", key, " decision: ", c.reason);
        if (d.outcome == "success") {
            std::string qk = bucket.name + "\x1f" + key;
            std::lock_guard<std::mutex> lock(st.queueMutex);
            if (st.queuedKeys.insert(qk).second) {
                if (st.queue.empty()) st.queueSinceSec = nowSec();
                st.queue.push_back(QueuedItem{std::move(c), nowSec()});
                tombQueued++;
                LOG_DEBUG("replication '", rep.name, "': queued deletion of ", bucket.name, "/", key);
            }
        } else {
            auto res = deliver(st, c);
            if (res) { // settled elsewhere: drop the tombstone
                cache.forget(key);
                tombRouted++;
            }
        }
    }

    LOG_INFO("replication '", rep.name, "': bucket ", bucket.name, " scanned in ", sw.ms(), " ms: listed=", listed,
             " pages=", pages, " unchanged=", unchanged, " changed=", changedCount, " metadata-changed=", metaOnly,
             " already-queued=", alreadyQueued, " queued=", queued, " routed-elsewhere=", routed,
             " route-failed=", routeFailed, " gone=", gone.size(), " deletions-queued=", tombQueued,
             " deletions-routed=", tombRouted, " deletions-waiting=", tombWaiting, " tombstones-forgotten=",
             tombForgotten);
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
        bool hasDeletes = false;
        for (const auto& item : st.queue) {
            bytes += item.candidate.size;
            if ((int64_t)item.candidate.size >= th.minSizeBytes) qualifying += item.candidate.size;
            if (item.candidate.kind == Candidate::Kind::Delete) hasDeletes = true;
        }
        int64_t age = st.queue.empty() ? 0 : elapsed(st.queueSinceSec);
        // Tombstones have size 0 and are already past the retention window when
        // they enter the queue. Size/min-size thresholds would otherwise keep
        // them pending forever (notably with --run-once).
        if (!force && !hasDeletes && !thresholdsReached(th, bytes, qualifying, age)) {
            LOG_DEBUG("replication '", rep.name, "': holding ", st.queue.size(), " item(s), ", bytes, " bytes (",
                      qualifying, " qualifying), age ", age, " s: thresholds not reached (size ", th.sizeBytes,
                      ", period ", th.periodSec, " s, min ", th.minSizeBytes, ", max-disk ", th.maxDiskBytes, ")");
            return Result<void>::success();
        }
        LOG_DEBUG("replication '", rep.name, "': flushing queue of ", st.queue.size(), " item(s), ", bytes,
                  " bytes, age ", age, " s: ", force ? "forced" : hasDeletes ? "deletions pending" : "thresholds reached");
        items = std::move(st.queue);
        st.queue.clear();
        st.queuedKeys.clear();
    }

    LOG_DEBUG("replication '", rep.name, "': shipping ", items.size(), " item(s)",
              force ? " (forced)" : "");
    tm::TimePoint shipStarted = tm::now();

    std::vector<QueuedItem> retry;
    size_t delivered = 0, gaveUp = 0;
    uint64_t deliveredBytes = 0;
    for (auto& item : items) {
        auto res = deliver(st, item.candidate);
        if (res) {
            delivered++;
            deliveredBytes += item.candidate.size;
        } else if (item.candidate.attempts < registry_.settings().retries) {
            LOG_WARN("replication '", rep.name, "': will retry ", item.candidate.bucket, "/", item.candidate.key,
                     " on the next shipment (attempt ", item.candidate.attempts, "/", registry_.settings().retries,
                     ")");
            retry.push_back(std::move(item));
        } else {
            gaveUp++;
            LOG_ERROR("replication '", rep.name, "': giving up on ", item.candidate.bucket, "/",
                      item.candidate.key, " after ", item.candidate.attempts, " attempts: ", res.error());
        }
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
    if (gaveUp > 0 || !retry.empty())
        LOG_WARN("replication '", rep.name, "': shipment of ", items.size(), " item(s) in ", stat.lastShipMs,
                 " ms: delivered=", delivered, " (", deliveredBytes, " bytes) retry=", retry.size(), " failed=",
                 gaveUp);
    else
        LOG_INFO("replication '", rep.name, "': shipped ", delivered, " item(s), ", deliveredBytes, " bytes in ",
                 stat.lastShipMs, " ms");
    persistDirty();
    return Result<void>::success();
}

Result<void> Engine::scanReplication(RepState& st) {
    const auto& rep = *st.rep;
    auto& stat = stats_.forReplication(rep.name);

    {
        std::lock_guard<std::mutex> lock(st.initMutex);
        if (!st.initialized) {
            LOG_DEBUG("replication '", rep.name, "': initialising clients, policy and routes");
            const registry::Cluster* srcCluster = registry_.cluster(rep.source);
            const registry::Cluster* dstCluster = registry_.cluster(rep.destination);
            if (!srcCluster) {
                LOG_ERROR("replication '", rep.name, "': unknown source cluster '", rep.source, "'");
                return Result<void>::failure("unknown source cluster '" + rep.source + "'");
            }
            if (!dstCluster) {
                LOG_ERROR("replication '", rep.name, "': unknown destination cluster '", rep.destination, "'");
                return Result<void>::failure("unknown destination cluster '" + rep.destination + "'");
            }
            auto src = accounts_.clientFor(*srcCluster);
            if (!src) {
                LOG_ERROR("replication '", rep.name, "': source client for ", rep.source, ": ", src.error());
                return Result<void>(src.error());
            }
            auto dst = accounts_.clientFor(*dstCluster);
            if (!dst) {
                LOG_ERROR("replication '", rep.name, "': destination client for ", rep.destination, ": ", dst.error());
                return Result<void>(dst.error());
            }
            st.source = src.value();
            st.destination = dst.value();
            st.bundle = registry_.bundleOrBuiltin(rep.policy);
            LOG_DEBUG("replication '", rep.name, "': policy bundle '", st.bundle.name, "' (", st.bundle.rules.size(),
                      " rule(s))");
            auto routes = targets_.routesFor(rep);
            if (!routes) {
                LOG_ERROR("replication '", rep.name, "': resolve target routes: ", routes.error());
                return Result<void>(routes.error());
            }
            st.routes = routes.value();
            for (TargetGroupPtr* group : {&st.routes.success, &st.routes.denied, &st.routes.warning}) {
                if (auto s3target = std::dynamic_pointer_cast<S3Target>(*group))
                    s3target->bind(st.destination, st.source.get(), registry_.settings().cacheDir);
            }
            st.initialized = true;
            LOG_INFO("replication '", rep.name, "': initialised ", rep.source, " -> ", rep.destination, ", policy '",
                     policyName(rep), "', routes success=", st.routes.success ? st.routes.success->name() : "-",
                     " denied=", st.routes.denied ? st.routes.denied->name() : "-",
                     " warning=", st.routes.warning ? st.routes.warning->name() : "-");
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
        LOG_DEBUG("replication '", rep.name, "': account ", account.accessKey, " access decision: ", d.toString());
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
    // delete_propagation governs objects/buckets only. Removing accounts is an
    // explicit, destructive operation (`sync-accounts --prune`), otherwise a
    // narrow accounts filter would delete unrelated destination accounts.
    auto sync = accounts_.sync(rep, false, false, accept);
    if (sync) {
        stat.accountsSynced += sync.value().created + sync.value().updated;
        if (!sync.value().empty())
            LOG_INFO("replication '", rep.name, "': account sync created=", sync.value().created,
                     " updated=", sync.value().updated, " deleted=", sync.value().deleted,
                     " matched=", sync.value().matched);
        else
            LOG_DEBUG("replication '", rep.name, "': account sync: no changes (matched=", sync.value().matched, ")");
    } else {
        LOG_DEBUG("replication '", rep.name, "': account sync skipped: ", sync.error());
    }

    // ---- buckets
    log::Stopwatch listSw;
    auto buckets = st.source->listBuckets();
    if (!buckets) {
        LOG_ERROR("replication '", rep.name, "': list buckets on ", rep.source, ": ", buckets.error());
        stat.lastError = tm::now();
        stat.lastErrorText = buckets.error();
        return Result<void>(buckets.error());
    }
    LOG_DEBUG("replication '", rep.name, "': ", buckets.value().size(), " bucket(s) on ", rep.source, " listed in ",
              listSw.ms(), " ms");
    size_t bucketsMatched = 0, bucketsFailed = 0;
    for (const auto& bucket : buckets.value()) {
        if (!glob::matchFilter(rep.buckets, bucket.name)) {
            LOG_DEBUG("replication '", rep.name, "': bucket ", bucket.name, " skipped by bucket filter");
            continue;
        }
        bucketsMatched++;
        stat.bucketsScanned++;
        auto res = scanBucket(st, bucket);
        if (!res) {
            bucketsFailed++;
            LOG_WARN("replication '", rep.name, "': bucket ", bucket.name, ": ", res.error());
            stat.lastError = tm::now();
            stat.lastErrorText = res.error();
        }
    }
    LOG_DEBUG("replication '", rep.name, "': ", bucketsMatched, " bucket(s) matched the filter, ", bucketsFailed,
              " failed");

    // ---- bucket deletions observed on the source
    if (rep.deletePropagation) {
        bool stateChanged = false;
        std::set<std::string> current;
        for (const auto& bucket : buckets.value()) {
            if (!glob::matchFilter(rep.buckets, bucket.name)) continue;
            current.insert(bucket.name);
            if (state_.bucketDeleteSince(rep.name, rep.source, bucket.name) != tm::TimePoint{}) {
                state_.clearBucketMissing(rep.name, rep.source, bucket.name);
                stateChanged = true;
            }
        }
        for (const auto& name : state_.knownBuckets(rep.name, rep.source)) {
            if (current.count(name) || !glob::matchFilter(rep.buckets, name)) continue;
            // Persist the first observation so a short source outage cannot
            // delete a bucket immediately after a daemon restart.
            if (state_.bucketDeleteSince(rep.name, rep.source, name) == tm::TimePoint{}) {
                state_.markBucketMissing(rep.name, rep.source, name, tm::now());
                stateChanged = true;
                LOG_INFO("replication '", rep.name, "': bucket ", name, " disappeared from ", rep.source);
            }
            auto since = state_.bucketDeleteSince(rep.name, rep.source, name);
            int64_t age = elapsed((int64_t)tm::toSeconds(since));
            if (rep.retentionSec > 0 && age < rep.retentionSec) {
                LOG_DEBUG("replication '", rep.name, "': bucket ", name, " deletion in retention (", age, "/",
                          rep.retentionSec, " s)");
                continue;
            }
            LOG_DEBUG("replication '", rep.name, "': propagating deletion of bucket ", name, " to ", rep.destination);
            auto exists = st.destination->headBucket(name);
            if (!exists) {
                LOG_WARN("replication '", rep.name, "': bucket ", name, " deletion: ", exists.error());
                continue;
            }
            if (!exists.value()) {
                LOG_DEBUG("replication '", rep.name, "': bucket ", name, " already absent on ", rep.destination);
                state_.forgetBucket(rep.name, rep.source, name);
                stateChanged = true;
                continue;
            }
            // Delete every version and delete marker, not only the current
            // object. Otherwise DeleteBucket fails on a versioned destination.
            bool ok = true;
            auto versions = st.destination->forEachObjectVersion(name, [&](const s3::ObjectVersion& v) {
                auto del = st.destination->deleteObject(name, v.key, v.versionId);
                if (!del && v.versionId == "null") del = st.destination->deleteObject(name, v.key);
                if (!del) {
                    LOG_WARN("replication '", rep.name, "': cannot delete version ", name, "/", v.key,
                             " (", v.versionId, "): ", del.error());
                    return Result<void>::failure(del.error());
                }
                return Result<void>::success();
            });
            if (!versions) {
                // Some gateways reject ListObjectVersions. Fall back to
                // deleting current objects; versioned buckets may need a
                // second scan if old versions remain.
                LOG_WARN("replication '", rep.name, "': cannot list versions of deleted bucket ", name,
                         ": ", versions.error(), "; falling back to current objects");
                auto objects = st.destination->forEachObject(name, {}, [&](const s3::ObjectInfo& o) {
                    auto del = st.destination->deleteObject(name, o.key);
                    if (!del) {
                        LOG_WARN("replication '", rep.name, "': cannot delete ", name, "/", o.key, ": ", del.error());
                        return Result<void>::failure(del.error());
                    }
                    return Result<void>::success();
                });
                if (!objects) {
                    ok = false;
                    LOG_WARN("replication '", rep.name, "': emptying deleted bucket ", name, " failed: ",
                             objects.error(), "; will retry on the next scan");
                }
            }
            if (!ok) continue;
            auto del = st.destination->deleteBucket(name);
            if (!del) {
                LOG_WARN("replication '", rep.name, "': cannot delete bucket ", name, ": ", del.error());
                continue;
            }
            state_.forgetBucket(rep.name, rep.source, name);
            stateChanged = true;
            LOG_INFO("replication '", rep.name, "': propagated deletion of bucket ", name);
        }
        if (stateChanged) {
            auto saved = state_.persist();
            if (!saved) LOG_WARN("replication '", rep.name, "': persist bucket deletion state: ", saved.error());
        }
    }
    stat.scanCycles++;
    stat.lastScan = tm::now();
    LOG_DEBUG("replication '", rep.name, "': stats scans=", stat.scanCycles, " buckets=", stat.bucketsScanned,
              " objects=", stat.objectsScanned, " delta=", stat.deltaDetected, " accepted=", stat.accepted, " denied=",
              stat.denied, " warned=", stat.warned, " shipped=", stat.shipped, " failed=", stat.failed, " deleted=",
              stat.deleted, " bytes-shipped=", stat.bytesShipped);
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
    int64_t t0 = tm::nowMs();
    log::Stopwatch sw;
    LOG_INFO("replication '", name, "': scan cycle ", stat.scanCycles + 1, " started");
    auto res = scanReplication(*st);
    if (!res) {
        LOG_ERROR("replication '", name, "': scan failed after ", sw.ms(), " ms: ", res.error());
        stat.lastError = tm::now();
        stat.lastErrorText = res.error();
    } else {
        size_t depth;
        {
            std::lock_guard<std::mutex> lock(st->queueMutex);
            depth = st->queue.size();
        }
        LOG_INFO("replication '", name, "': scan cycle finished in ", sw.ms(), " ms, queue depth ", depth);
    }
    stat.lastScanMs = tm::nowMs() - t0;
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
        if (it == reps_.end()) {
            LOG_WARN("ship request for unknown replication '", name, "' ignored");
            return;
        }
        st = it->second.get();
    }
    std::lock_guard<std::mutex> op(st->opMutex);
    LOG_DEBUG("replication '", name, "': processing shipment", force ? " (forced)" : "");
    st->shipQueued.store(false); // allow the scheduler to queue the next shipment
    auto res = shipReady(*st, force);
    if (!res) LOG_ERROR("replication '", name, "': shipment failed: ", res.error());
}

void Engine::queueWork(const std::string& replication, bool scan, bool force) {
    WorkItem item{replication, scan, force};
    std::lock_guard<std::mutex> lock(workMutex_);
    if (poolMode_) {
        sharedQueue_.push_back(item);
        LOG_DEBUG("queued ", scan ? "scan" : "shipment", " of replication '", replication,
                  "' to the shared pool (depth ", sharedQueue_.size(), ")");
    } else {
        const registry::Replication* rep = registry_.replication(replication);
        std::string policy = rep ? policyName(*rep) : std::string("default");
        auto& queue = policyQueues_[policy];
        queue.push_back(item);
        LOG_DEBUG("queued ", scan ? "scan" : "shipment", " of replication '", replication, "' to policy worker '",
                  policy, "' (depth ", queue.size(), ")");
    }
    workCv_.notify_all();
}

void Engine::schedulerLoop() {
    LOG_DEBUG("replication scheduler thread started");
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
                if (st->scanQueued.compare_exchange_strong(expected, true)) {
                    LOG_DEBUG("scheduler: replication '", rep.name, "' scan due (every ", scanEvery, " s, last ",
                              isoFromSec(st->lastScanSec), ")");
                    queueWork(rep.name, true, false);
                }
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
                if (st->shipQueued.compare_exchange_strong(expected, true)) {
                    LOG_DEBUG("scheduler: replication '", rep.name, "' queue thresholds reached, shipment due");
                    queueWork(rep.name, false, false);
                }
            }
        }
    }
    LOG_DEBUG("replication scheduler thread stopped");
}

void Engine::workerLoop(const std::string& policyFilter) {
    LOG_DEBUG("replication worker started (", poolMode_ ? std::string("shared pool") : "policy '" + policyFilter + "'",
              ")");
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
        LOG_DEBUG("worker ", poolMode_ ? std::string("[pool]") : "[" + policyFilter + "]", " picked ",
                  item.scan ? "scan" : "shipment", " of replication '", item.replication, "'");
        try {
            if (item.scan) {
                processScan(item.replication);
            } else {
                processShip(item.replication, item.force);
            }
        } catch (const std::exception& e) {
            LOG_ERROR("worker: ", item.scan ? "scan" : "shipment", " of replication '", item.replication,
                      "' threw: ", e.what());
            throw;
        }
        lock.lock();
    }
    LOG_DEBUG("replication worker stopped (", poolMode_ ? std::string("shared pool") : "policy '" + policyFilter + "'",
              ")");
}

Result<void> Engine::start() {
    if (scheduler_.joinable()) {
        LOG_DEBUG("replication engine already running");
        return Result<void>::success();
    }
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
            LOG_DEBUG("starting dedicated worker for policy '", policy, "'");
            policyQueues_[policy];
            workers_.emplace_back([this, policy] { workerLoop(policy); });
        }
    }
    scheduler_ = std::thread([this] { schedulerLoop(); });
    LOG_NOTICE("replication engine started: ", workers_.size(), " worker(s)",
               poolMode_ ? " (shared pool)" : " (dedicated per policy)", ", ", registry_.replications().size(),
               " replication(s), retries ", registry_.settings().retries);
    return Result<void>::success();
}

void Engine::stop() {
    if (!scheduler_.joinable() && workers_.empty()) return;
    log::Stopwatch sw;
    LOG_INFO("stopping replication engine (", workers_.size(), " worker(s))");
    stop_ = true;
    workCv_.notify_all();
    if (scheduler_.joinable()) scheduler_.join();
    for (auto& worker : workers_)
        if (worker.joinable()) worker.join();
    workers_.clear();
    persistDirty();
    LOG_NOTICE("replication engine stopped in ", sw.ms(), " ms");
}

Result<void> Engine::rebuild() {
    bool wasRunning = running();
    LOG_INFO("rebuilding replication engine workers (was ", wasRunning ? "running" : "stopped", ")");
    stop();
    stop_ = false;
    if (wasRunning) return start();
    return Result<void>::success();
}

void Engine::kick() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    LOG_INFO("rescan requested for ", reps_.size(), " replication(s)");
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
        if (!rep) {
            LOG_ERROR("flush: unknown replication '", replication, "'");
            return Result<void>::failure("unknown replication '" + replication + "'");
        }
        st = ensureState(*rep);
    }
    LOG_INFO("replication '", replication, "': forced flush requested");
    std::lock_guard<std::mutex> op(st->opMutex);
    auto res = shipReady(*st, true);
    if (!res) LOG_ERROR("replication '", replication, "': forced shipment failed: ", res.error());
    return res;
}

Result<void> Engine::runOnce(const std::string& onlyReplication, bool forceShip) {
    log::Stopwatch total;
    LOG_INFO("single pass started", onlyReplication.empty() ? std::string() : " for replication '" + onlyReplication + "'",
             forceShip ? " (forced shipment)" : "");
    size_t ran = 0;
    for (const auto& rep : registry_.replications()) {
        if (!onlyReplication.empty() && rep.name != onlyReplication) continue;
        if (rep.paused) {
            LOG_INFO("replication '", rep.name, "' is paused, skipped");
            continue;
        }
        RepState* st = ensureState(rep);
        if (!st) continue;
        ran++;
        std::lock_guard<std::mutex> op(st->opMutex);
        auto& stat = stats_.forReplication(rep.name);
        stat.inFlight = true;
        log::Stopwatch sw;
        LOG_INFO("replication '", rep.name, "': scan started");
        auto res = scanReplication(*st);
        stat.inFlight = false;
        if (res) LOG_INFO("replication '", rep.name, "': scan finished in ", sw.ms(), " ms");
        if (!res) {
            LOG_ERROR("replication '", rep.name, "': scan failed after ", sw.ms(), " ms: ", res.error());
            stat.lastError = tm::now();
            stat.lastErrorText = res.error();
        }
        st->lastScanSec = nowSec();
        auto shipped = shipReady(*st, forceShip);
        if (!shipped) LOG_ERROR("replication '", rep.name, "': shipment failed: ", shipped.error());
    }
    if (ran == 0 && !onlyReplication.empty())
        LOG_WARN("single pass: replication '", onlyReplication, "' not found or paused");
    persistDirty();
    LOG_INFO("single pass finished: ", ran, " replication(s) in ", total.ms(), " ms");
    return Result<void>::success();
}

void Engine::refreshState() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    for (auto it = reps_.begin(); it != reps_.end();) {
        const registry::Replication* rep = registry_.replication(it->first);
        if (!rep) { // removed by the CLI mutation: drop the whole state
            LOG_INFO("replication '", it->first, "' removed: dropping its engine state");
            it = reps_.erase(it);
            continue;
        }
        LOG_DEBUG("replication '", it->first, "': state invalidated, will re-initialise on next scan");
        it->second->rep = rep;
        // force re-resolution of clients/bundle/routes on the next scan
        std::lock_guard<std::mutex> init(it->second->initMutex);
        it->second->initialized = false;
        ++it;
    }
}

Result<SyncReport> Engine::syncAccounts(const std::string& replication, bool dryRun, bool prune) {
    const registry::Replication* rep = registry_.replication(replication);
    if (!rep) {
        LOG_ERROR("sync accounts: unknown replication '", replication, "'");
        return Result<SyncReport>::failure("unknown replication '" + replication + "'");
    }
    LOG_INFO("replication '", replication, "': account sync requested", dryRun ? " (dry run)" : "",
             prune ? " (prune)" : "");
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
        LOG_DEBUG("replication '", rep->name, "': account ", account.accessKey, " access decision: ", d.toString());
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
    if (report) {
        stat.accountsSynced += report.value().created + report.value().updated;
        LOG_INFO("replication '", replication, "': account sync", dryRun ? " (dry run)" : "", " created=",
                 report.value().created, " updated=", report.value().updated, " deleted=", report.value().deleted,
                 " matched=", report.value().matched);
    } else {
        LOG_ERROR("replication '", replication, "': account sync failed: ", report.error());
    }
    return report;
}

} // namespace s3mm::repl
