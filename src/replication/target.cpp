#include "s3mm/replication/target.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <unistd.h>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/value.hpp"
#include "s3mm/s3/http.hpp"

namespace s3mm::repl {

// ---------------------------------------------------------------- helpers ---

static std::string renderTemplate(std::string tmpl, const ShipRecord& r) {
    auto replace = [&](const std::string& token, const std::string& value) {
        tmpl = str::replaceAll(tmpl, "{" + token + "}", value);
    };
    std::string keyCopy = r.key;
    auto slash = keyCopy.find_last_of('/');
    std::string filename = slash == std::string::npos ? keyCopy : keyCopy.substr(slash + 1);
    std::string ext;
    auto dot = filename.find_last_of('.');
    if (dot != std::string::npos && dot > 0) ext = filename.substr(dot + 1);
    std::string safeKey = r.key;
    for (auto& c : safeKey)
        if (c == '/' ) c = '_';

    replace("replication", r.replication);
    replace("outcome", r.outcome);
    replace("kind", r.kind);
    replace("bucket", r.bucket);
    replace("key", r.key);
    replace("safe_key", safeKey);
    replace("filename", filename);
    replace("ext", ext);
    replace("rule", r.rule);
    replace("reason", r.reason);
    replace("account", r.account);
    replace("cluster", r.sourceCluster);
    replace("destination", r.destinationCluster);
    tm::TimePoint ts = r.lastModified > tm::TimePoint{} ? r.lastModified : tm::now();
    replace("ts", std::to_string(tm::toSeconds(ts)));
    replace("date", tm::toIso8601(tm::now()).substr(0, 10));
    replace("size", std::to_string(r.size));
    replace("etag", r.etag);
    return tmpl;
}

std::string ShipRecord::toJson() const {
    Value v = Value::object();
    v.set("ts", Value::str(tm::toIso8601Ms(tm::now())));
    v.set("replication", Value::str(replication));
    v.set("outcome", Value::str(outcome));
    v.set("kind", Value::str(kind));
    v.set("rule", Value::str(rule));
    v.set("reason", Value::str(reason));
    v.set("source_cluster", Value::str(sourceCluster));
    v.set("destination_cluster", Value::str(destinationCluster));
    if (!bucket.empty()) v.set("bucket", Value::str(bucket));
    if (!key.empty()) v.set("key", Value::str(key));
    if (!account.empty()) v.set("account", Value::str(account));
    if (kind == "object" || kind == "delete") {
        v.set("size", Value::number((uint64_t)size));
        v.set("etag", Value::str(etag));
        v.set("last_modified", Value::str(tm::toIso8601(lastModified)));
        if (!contentType.empty()) v.set("content_type", Value::str(contentType));
    }
    if (!meta.empty()) {
        Value m = Value::object();
        for (const auto& [k, val] : meta) m.set(k, Value::str(val));
        v.set("meta", std::move(m));
    }
    return v.toJson(0);
}

// ------------------------------------------------------------ NullTarget ---

Result<void> NullTarget::ship(const ShipRecord& record, const std::string&) {
    LOG_DEBUG("drop target '", name_, "': ", record.replication, " ", record.kind, " ", record.bucket, "/",
              record.key.empty() ? record.account : record.key, " (", record.outcome, ")");
    return Result<void>::success();
}

// ----------------------------------------------------------- FileTarget ---

FileTarget::FileTarget(std::string name, std::string path, std::string pathTemplate)
    : name_(std::move(name)), path_(std::move(path)), pathTemplate_(std::move(pathTemplate)) {
    while (!path_.empty() && path_.back() == '/') path_.pop_back();
}

std::string FileTarget::renderPath(const ShipRecord& r) const {
    if (pathTemplate_.empty()) return path_;
    std::string base = path_;
    if (!base.empty() && base.back() != '/') base += '/';
    return base + renderTemplate(pathTemplate_, r);
}

Result<void> FileTarget::ship(const ShipRecord& r, const std::string& dataPath) {
    std::string target = renderPath(r);
    std::string json = r.toJson();
    // directory target: one file per record (path template) or an append-only log
    bool isDirectoryTarget = !pathTemplate_.empty() || fs::isDir(target) ||
                             (!target.empty() && target.back() == '/');

    std::error_code ec;
    LOG_DEBUG("file target '", name_, "': ", r.kind, " ", r.bucket, "/", r.key.empty() ? r.account : r.key, " -> ",
              target, isDirectoryTarget ? " (directory)" : " (file)", dataPath.empty() ? "" : " with payload");
    if (isDirectoryTarget) {
        if (!pathTemplate_.empty()) {
            // template fully defines the record path; append the JSON record
            if (!fs::mkdirp(fs::dirname(target)))
                LOG_WARN("file target '", name_, "': cannot create ", fs::dirname(target), ": ", std::strerror(errno));
            if (!fs::writeFileAtomic(target, json + "\n")) {
                LOG_ERROR("file target '", name_, "': cannot write ", target, ": ", std::strerror(errno));
                return Result<void>::failure("file target '" + name_ + "': cannot write " + target);
            }
        } else {
            if (!fs::mkdirp(target)) {
                LOG_ERROR("file target '", name_, "': cannot create directory ", target, ": ", std::strerror(errno));
                return Result<void>::failure("file target '" + name_ + "': cannot create directory " + target);
            }
            std::string logFile = fs::joinPath(target, "records.jsonl");
            if (!fs::appendFile(logFile, json + "\n")) {
                LOG_ERROR("file target '", name_, "': cannot append to ", logFile, ": ", std::strerror(errno));
                return Result<void>::failure("file target '" + name_ + "': cannot append to " + logFile);
            }
        }
        if (!dataPath.empty()) {
            std::string dest = target;
            if (!pathTemplate_.empty()) dest += ".data";
            else dest = fs::joinPath(target, (r.key.empty() ? r.account : str::replaceAll(r.key, "/", "_")) + ".data");
            std::error_code ec2;
            std::filesystem::copy_file(dataPath, dest, std::filesystem::copy_options::overwrite_existing, ec2);
            if (ec2) {
                LOG_ERROR("file target '", name_, "': cannot copy payload ", dataPath, " to ", dest, ": ", ec2.message());
                return Result<void>::failure("file target '" + name_ + "': cannot copy payload to " + dest);
            }
        }
        LOG_INFO("file target '", name_, "': stored ", r.kind, " ", r.bucket, "/", r.key, " -> ", target);
        return Result<void>::success();
    }

    // plain file: append JSON lines
    if (!fs::appendFile(target, json + "\n")) {
        LOG_ERROR("file target '", name_, "': cannot append to ", target, ": ", std::strerror(errno));
        return Result<void>::failure("file target '" + name_ + "': cannot append to " + target);
    }
    if (!dataPath.empty()) {
        std::string sidecar = target + ".data";
        std::error_code ec2;
        std::filesystem::copy_file(dataPath, sidecar, std::filesystem::copy_options::overwrite_existing, ec2);
        if (ec2) {
            LOG_ERROR("file target '", name_, "': cannot copy payload ", dataPath, " to ", sidecar, ": ",
                      ec2.message());
            return Result<void>::failure("file target '" + name_ + "': cannot copy payload to " + sidecar);
        }
    }
    LOG_INFO("file target '", name_, "': appended ", r.kind, " ", r.bucket, "/", r.key.empty() ? r.account : r.key,
             " (", r.outcome, ") to ", target);
    return Result<void>::success();
}

// ------------------------------------------------------------ HttpTarget ---

HttpTarget::HttpTarget(std::string name, std::string url, bool insecure)
    : name_(std::move(name)), url_(std::move(url)), insecure_(insecure) {}

Result<void> HttpTarget::ship(const ShipRecord& r, const std::string&) {
    http::Request req;
    req.method = "POST";
    req.url = url_;
    req.body = r.toJson();
    req.headers["Content-Type"] = "application/json";
    req.insecure = insecure_;
    req.timeoutSec = 30;
    LOG_DEBUG("http target '", name_, "': POST ", url_, " (", req.body.size(), " bytes", insecure_ ? ", insecure" : "",
              ") for ", r.kind, " ", r.bucket, "/", r.key.empty() ? r.account : r.key);
    log::Stopwatch sw;
    auto response = http::Client().send(req);
    if (response.transportError()) {
        LOG_ERROR("http target '", name_, "': POST ", url_, " failed after ", sw.ms(), " ms: ", response.curlError);
        return Result<void>::failure("http target '" + name_ + "': " + response.curlError);
    }
    if (!response.ok()) {
        LOG_ERROR("http target '", name_, "': POST ", url_, " -> HTTP ", response.status, " in ", sw.ms(),
                  " ms: ", log::clip(response.body));
        return Result<void>::failure("http target '" + name_ + "': HTTP " + std::to_string(response.status));
    }
    LOG_INFO("http target '", name_, "': delivered ", r.kind, " ", r.bucket, "/", r.key.empty() ? r.account : r.key,
             " -> HTTP ", response.status, " in ", sw.ms(), " ms");
    return Result<void>::success();
}

// -------------------------------------------------------------- S3Target ---

S3Target::S3Target(std::string name, std::string uri, std::string pathTemplate)
    : name_(std::move(name)), pathTemplate_(std::move(pathTemplate)) {
    // s3://cluster/bucket[/prefix]
    std::string rest = uri.substr(std::strlen("s3://"));
    auto slash = rest.find('/');
    if (slash == std::string::npos) {
        cluster_ = rest;
        bucket_.clear();
    } else {
        cluster_ = rest.substr(0, slash);
        std::string tail = rest.substr(slash + 1);
        auto slash2 = tail.find('/');
        if (slash2 == std::string::npos) {
            bucket_ = tail;
        } else {
            bucket_ = tail.substr(0, slash2);
            prefix_ = tail.substr(slash2 + 1);
            while (!prefix_.empty() && prefix_.front() == '/') prefix_.erase(prefix_.begin());
            while (!prefix_.empty() && prefix_.back() == '/') prefix_.pop_back();
        }
    }
    LOG_DEBUG("s3 target '", name_, "': cluster=", cluster_, " bucket=", bucket_.empty() ? "<same as source>" : bucket_,
              " prefix=", prefix_.empty() ? "-" : prefix_, " template=", pathTemplate_.empty() ? "-" : pathTemplate_);
}

void S3Target::bind(std::shared_ptr<s3::Client> destination, s3::Client* source, std::string stagingDir) {
    destination_ = std::move(destination);
    source_ = source;
    stagingDir_ = std::move(stagingDir);
    LOG_DEBUG("s3 target '", name_, "': bound to destination client", destination_ ? "" : " <none>",
              source_ ? " and source client" : " (no source client)", ", staging dir ",
              stagingDir_.empty() ? "/tmp (default)" : stagingDir_);
}

std::string S3Target::renderKey(const ShipRecord& r) const {
    std::string key = r.key;
    if (!pathTemplate_.empty()) key = renderTemplate(pathTemplate_, r);
    if (!prefix_.empty()) return prefix_ + "/" + key;
    return key;
}

Result<void> S3Target::ship(const ShipRecord& r, const std::string& dataPath) {
    if (!destination_) {
        LOG_ERROR("s3 target '", name_, "' is not bound to a client");
        return Result<void>::failure("s3 target '" + name_ + "' is not bound to a client");
    }
    // `bucket_` empty means the implicit 1:1 route: same bucket as the source object.
    const std::string destBucket = bucket_.empty() ? r.bucket : bucket_;
    if (destBucket.empty()) {
        // metadata-only record without a bucket (e.g. account decisions): log only
        LOG_INFO("s3 target '", name_, "': ", r.outcome, " ", r.kind, " ", r.account,
                 r.bucket.empty() ? "" : " " + r.bucket, r.key.empty() ? "" : "/" + r.key, " (", r.reason, ")");
        return Result<void>::success();
    }

    log::Stopwatch sw;
    auto exists = destination_->headBucket(destBucket);
    if (!exists) {
        LOG_ERROR("s3 target '", name_, "': HEAD bucket ", destBucket, " on ", cluster_, ": ", exists.error());
        return Result<void>(exists.error());
    }
    if (!exists.value()) {
        LOG_DEBUG("s3 target '", name_, "': destination bucket ", destBucket, " missing on ", cluster_, ", creating");
        auto created = destination_->createBucket(destBucket);
        if (!created) {
            LOG_ERROR("s3 target '", name_, "': create bucket ", destBucket, " on ", cluster_, ": ", created.error());
            return Result<void>(created.error());
        }
        LOG_INFO("s3 target '", name_, "': created bucket ", destBucket, " on ", cluster_);
    }

    std::string destKey = renderKey(r);

    if (r.kind == "delete") {
        auto head = destination_->headObject(destBucket, destKey);
        if (head && !head.value().exists) { // already gone
            LOG_DEBUG("s3 target '", name_, "': ", destBucket, "/", destKey, " already absent, delete skipped");
            return Result<void>::success();
        }
        // Do not pass the source versionId: version IDs are cluster-local. An
        // unversioned DELETE mirrors a source delete marker on a versioned
        // destination (or removes the object on an unversioned one).
        auto del = destination_->deleteObject(destBucket, destKey);
        if (!del) {
            LOG_ERROR("s3 target '", name_, "': delete ", destBucket, "/", destKey, " on ", cluster_, ": ", del.error());
            return Result<void>(del.error());
        }
        LOG_INFO("s3 target '", name_, "': deleted ", destBucket, "/", destKey);
        return Result<void>::success();
    }

    if (!source_) {
        LOG_ERROR("s3 target '", name_, "': no source client for object copy of ", r.bucket, "/", r.key);
        return Result<void>::failure("s3 target '" + name_ + "': no source client for object copy");
    }

    // Fetch source metadata/tags once. They are not part of the object body and
    // were previously dropped during replication.
    auto sourceHead = source_->headObject(r.bucket, r.key);
    if (!sourceHead) {
        LOG_ERROR("s3 target '", name_, "': HEAD source ", r.bucket, "/", r.key, ": ", sourceHead.error());
        return Result<void>(sourceHead.error());
    }
    if (!sourceHead.value().exists) {
        LOG_WARN("s3 target '", name_, "': source object ", r.bucket, "/", r.key, " disappeared before copy");
        return Result<void>::failure("source object disappeared: " + r.bucket + "/" + r.key);
    }
    s3::ObjectMeta sourceMeta = sourceHead.value();
    if (sourceMeta.contentType.empty()) sourceMeta.contentType = r.contentType;
    auto tagging = source_->getObjectTagging(r.bucket, r.key);
    if (tagging) sourceMeta.tags = tagging.value().tags;
    else LOG_DEBUG("s3 target '", name_, "': source tags of ", r.bucket, "/", r.key, " unavailable: ", tagging.error());
    LOG_DEBUG("s3 target '", name_, "': copying ", r.bucket, "/", r.key, " (", sourceMeta.size, " bytes, ",
              sourceMeta.userMeta.size(), " meta, ", sourceMeta.tags.size(), " tags) -> ", cluster_, ":", destBucket,
              "/", destKey);

    if (!dataPath.empty()) {
        auto meta = destination_->headObject(destBucket, destKey);
        if (meta && meta.value().exists && meta.value().size == r.size && !r.etag.empty() &&
            meta.value().etag == r.etag) { // identical copy already present
            LOG_DEBUG("s3 target '", name_, "': ", destBucket, "/", destKey, " identical on destination, skipped");
            return Result<void>::success();
        }
        auto put = destination_->putObjectFromFile(destBucket, destKey, dataPath, sourceMeta);
        if (!put) {
            LOG_ERROR("s3 target '", name_, "': upload ", dataPath, " -> ", destBucket, "/", destKey, ": ", put.error());
            return Result<void>(put.error());
        }
        LOG_INFO("s3 target '", name_, "': uploaded ", destBucket, "/", destKey, " from ", dataPath, " in ", sw.ms(),
                 " ms");
        return Result<void>::success();
    }

    const uint64_t maxInMemory = 8ull * 1024 * 1024;
    if (sourceMeta.size <= maxInMemory) {
        auto body = source_->getObjectRange(r.bucket, r.key, 0, sourceMeta.size);
        if (!body) {
            LOG_ERROR("s3 target '", name_, "': GET source ", r.bucket, "/", r.key, ": ", body.error());
            return Result<void>(body.error());
        }
        auto put = destination_->putObject(destBucket, destKey, body.value(), sourceMeta);
        if (!put) {
            LOG_ERROR("s3 target '", name_, "': PUT ", cluster_, ":", destBucket, "/", destKey, ": ", put.error());
            return Result<void>(put.error());
        }
        LOG_INFO("s3 target '", name_, "': replicated ", r.bucket, "/", r.key, " -> ", cluster_, ":", destBucket, "/",
                 destKey, " (", body.value().size(), " bytes) in ", sw.ms(), " ms");
        return Result<void>::success();
    }

    // large object: stage to a temporary file, then upload (possibly multipart)
    std::string staging = fs::joinPath(stagingDir_.empty() ? std::string("/tmp") : stagingDir_,
                                       "s3mm-stage-" + std::to_string(tm::nowMs()) + "-" +
                                           std::to_string((uint64_t)(uintptr_t)this));
    uint64_t offset = 0;
    LOG_DEBUG("s3 target '", name_, "': staging large object ", r.bucket, "/", r.key, " (", sourceMeta.size,
              " bytes) in ", staging);
    std::FILE* f = std::fopen(staging.c_str(), "wb");
    if (!f) {
        LOG_ERROR("s3 target '", name_, "': cannot create staging file ", staging, ": ", std::strerror(errno));
        return Result<void>::failure("cannot create staging file " + staging);
    }
    const uint64_t chunk = 16ull * 1024 * 1024;
    while (offset < sourceMeta.size) {
        uint64_t len = std::min(chunk, sourceMeta.size - offset);
        auto part = source_->getObjectRange(r.bucket, r.key, offset, len);
        if (!part) {
            LOG_ERROR("s3 target '", name_, "': GET range ", offset, "+", len, " of ", r.bucket, "/", r.key, ": ",
                      part.error());
            std::fclose(f);
            ::unlink(staging.c_str());
            return Result<void>(part.error());
        }
        if (std::fwrite(part.value().data(), 1, part.value().size(), f) != part.value().size())
            LOG_ERROR("s3 target '", name_, "': short write to staging file ", staging, ": ", std::strerror(errno));
        offset += part.value().size();
        LOG_DEBUG("s3 target '", name_, "': staged ", offset, "/", sourceMeta.size, " bytes of ", r.bucket, "/", r.key);
        if (part.value().size() < len) {
            LOG_WARN("s3 target '", name_, "': short range read of ", r.bucket, "/", r.key, " at ", offset, " (got ",
                     part.value().size(), " of ", len, " bytes)");
            break;
        }
    }
    std::fclose(f);

    Result<void> upload = Result<void>::failure("not attempted");
    if (sourceMeta.size <= 64ull * 1024 * 1024) {
        upload = destination_->putObjectFromFile(destBucket, destKey, staging, sourceMeta);
    } else {
        auto mp = destination_->uploadMultipartFromFile(destBucket, destKey, staging, 16ull * 1024 * 1024,
                                                       sourceMeta);
        upload = mp ? Result<void>::success() : Result<void>::failure(mp.error());
    }
    if (::unlink(staging.c_str()) != 0)
        LOG_WARN("s3 target '", name_, "': cannot remove staging file ", staging, ": ", std::strerror(errno));
    if (upload)
        LOG_INFO("s3 target '", name_, "': replicated ", r.bucket, "/", r.key, " -> ", cluster_, ":", destBucket, "/",
                 destKey, " (", offset, " bytes, ", sourceMeta.size > 64ull * 1024 * 1024 ? "multipart" : "single PUT",
                 ") in ", sw.ms(), " ms");
    else
        LOG_ERROR("s3 target '", name_, "': upload of ", r.bucket, "/", r.key, " -> ", cluster_, ":", destBucket, "/",
                  destKey, " failed: ", upload.error());
    return upload;
}

// --------------------------------------------------------- TargetFactory ---

TargetFactory::TargetFactory(const registry::Registry& registry, module::Loader* loader)
    : registry_(registry), loader_(loader) {}

TargetGroupPtr TargetFactory::find(const std::string& name) const {
    auto it = cache_.find(name);
    if (it != cache_.end()) return it->second;
    return nullptr;
}

Result<TargetGroupPtr> TargetFactory::create(const std::string& name) {
    auto cached = find(name);
    if (cached) return Result<TargetGroupPtr>(cached);
    LOG_DEBUG("creating target '", name, "'");

    const registry::Target* def = registry_.target(name);
    TargetGroupPtr group;
    if (!def) {
        // implicit targets
        if (name == "null" || name == "drop" || name == "db") {
            group = std::make_shared<NullTarget>(name);
        } else if (name == "quarantine") {
            std::string path = fs::joinPath(registry_.settings().cacheDir, "quarantine/records.jsonl");
            group = std::make_shared<FileTarget>(name, path, std::string());
        } else {
            LOG_DEBUG("target '", name, "' is not defined and not implicit");
            return Result<TargetGroupPtr>::failure("unknown target '" + name + "'");
        }
    } else if (def->kind == "null" || def->kind == "db") {
        group = std::make_shared<NullTarget>(name);
    } else if (def->kind == "file") {
        std::string path = def->uri;
        if (str::startsWith(path, "file:")) path = path.substr(std::strlen("file:"));
        if (path.empty()) path = fs::joinPath(registry_.settings().cacheDir, name);
        group = std::make_shared<FileTarget>(name, path, def->pathTemplate);
    } else if (def->kind == "http" || def->kind == "https") {
        group = std::make_shared<HttpTarget>(name, def->uri, false);
    } else if (def->kind == "s3") {
        group = std::make_shared<S3Target>(name, def->uri, def->pathTemplate);
    } else {
        LOG_ERROR("target '", name, "': unsupported type '", def->kind, "'");
        return Result<TargetGroupPtr>::failure("target '" + name + "': unsupported type '" + def->kind + "'");
    }
    cache_[name] = group;
    LOG_INFO("target '", name, "' created: kind ", group->kind(), def ? " (configured)" : " (implicit)");
    return Result<TargetGroupPtr>(group);
}

TargetGroupPtr TargetFactory::successRoute(const registry::Replication& replication) const {
    const registry::Cluster* dst = registry_.cluster(replication.destination);
    if (!dst) {
        LOG_ERROR("replication '", replication.name, "': success route: unknown destination cluster '",
                  replication.destination, "'");
        return nullptr;
    }
    std::string name = replication.name + "-rqueue";
    auto it = cache_.find(name);
    if (it != cache_.end()) return it->second;
    auto s3group = std::make_shared<S3Target>(name, "s3://" + dst->name + "/", std::string());
    // destination cluster binding is done by the engine (it owns clients)
    cache_[name] = s3group;
    LOG_DEBUG("replication '", replication.name, "': implicit success route '", name, "' -> s3://", dst->name, "/");
    return s3group;
}

Result<TargetFactory::Routes> TargetFactory::routesFor(const registry::Replication& replication) const {
    const policy::Bundle bundle = registry_.bundleOrBuiltin(replication.policy);
    Routes routes;

    std::string successName = bundle.routes.success.empty() ? replication.name + "-rqueue" : bundle.routes.success;
    std::string deniedName = bundle.routes.denied.empty() ? "null" : bundle.routes.denied;
    std::string warningName = bundle.routes.warning.empty() ? "quarantine" : bundle.routes.warning;
    LOG_DEBUG("replication '", replication.name, "': resolving routes from policy '", bundle.name, "': success=",
              successName, " denied=", deniedName, " warning=", warningName);

    auto resolve = [&](const std::string& n) -> Result<TargetGroupPtr> {
        auto it = cache_.find(n);
        if (it != cache_.end()) return Result<TargetGroupPtr>(it->second);
        return const_cast<TargetFactory*>(this)->create(n);
    };

    // success route may be the implicit replication queue (s3 copy)
    const registry::Target* explicitTarget = registry_.target(successName);
    if (!explicitTarget && successName == replication.name + "-rqueue") {
        routes.success = successRoute(replication);
    } else {
        auto res = resolve(successName);
        if (!res) {
            LOG_ERROR("replication '", replication.name, "': success route '", successName, "': ", res.error());
            return Result<Routes>::failure(res.error());
        }
        routes.success = res.value();
    }
    if (!routes.success) {
        LOG_ERROR("replication '", replication.name, "': cannot resolve success route '", successName, "'");
        return Result<Routes>::failure("cannot resolve success route '" + successName + "'");
    }

    auto denied = resolve(deniedName);
    if (!denied) {
        LOG_ERROR("replication '", replication.name, "': denied route '", deniedName, "': ", denied.error());
        return Result<Routes>::failure(denied.error());
    }
    routes.denied = denied.value();

    auto warning = resolve(warningName);
    if (!warning) {
        LOG_ERROR("replication '", replication.name, "': warning route '", warningName, "': ", warning.error());
        return Result<Routes>::failure(warning.error());
    }
    routes.warning = warning.value();
    return Result<Routes>(std::move(routes));
}

} // namespace s3mm::repl
