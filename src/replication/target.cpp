#include "s3mm/replication/target.hpp"

#include <algorithm>
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
    if (isDirectoryTarget) {
        if (!pathTemplate_.empty()) {
            // template fully defines the record path; append the JSON record
            fs::mkdirp(fs::dirname(target));
            if (!fs::writeFileAtomic(target, json + "\n"))
                return Result<void>::failure("file target '" + name_ + "': cannot write " + target);
        } else {
            if (!fs::mkdirp(target))
                return Result<void>::failure("file target '" + name_ + "': cannot create directory " + target);
            std::string logFile = fs::joinPath(target, "records.jsonl");
            if (!fs::appendFile(logFile, json + "\n"))
                return Result<void>::failure("file target '" + name_ + "': cannot append to " + logFile);
        }
        if (!dataPath.empty()) {
            std::string dest = target;
            if (!pathTemplate_.empty()) dest += ".data";
            else dest = fs::joinPath(target, (r.key.empty() ? r.account : str::replaceAll(r.key, "/", "_")) + ".data");
            std::error_code ec2;
            std::filesystem::copy_file(dataPath, dest, std::filesystem::copy_options::overwrite_existing, ec2);
            if (ec2) return Result<void>::failure("file target '" + name_ + "': cannot copy payload to " + dest);
        }
        LOG_INFO("file target '", name_, "': stored ", r.kind, " ", r.bucket, "/", r.key, " -> ", target);
        return Result<void>::success();
    }

    // plain file: append JSON lines
    if (!fs::appendFile(target, json + "\n"))
        return Result<void>::failure("file target '" + name_ + "': cannot append to " + target);
    if (!dataPath.empty()) {
        std::string sidecar = target + ".data";
        std::error_code ec2;
        std::filesystem::copy_file(dataPath, sidecar, std::filesystem::copy_options::overwrite_existing, ec2);
        if (ec2) return Result<void>::failure("file target '" + name_ + "': cannot copy payload to " + sidecar);
    }
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
    auto response = http::Client().send(req);
    if (response.transportError())
        return Result<void>::failure("http target '" + name_ + "': " + response.curlError);
    if (!response.ok())
        return Result<void>::failure("http target '" + name_ + "': HTTP " + std::to_string(response.status));
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
}

void S3Target::bind(std::shared_ptr<s3::Client> destination, s3::Client* source) {
    destination_ = std::move(destination);
    source_ = source;
}

std::string S3Target::renderKey(const ShipRecord& r) const {
    std::string key = r.key;
    if (!pathTemplate_.empty()) key = renderTemplate(pathTemplate_, r);
    if (!prefix_.empty()) return prefix_ + "/" + key;
    return key;
}

Result<void> S3Target::ship(const ShipRecord& r, const std::string& dataPath) {
    if (!destination_) return Result<void>::failure("s3 target '" + name_ + "' is not bound to a client");
    // `bucket_` empty means the implicit 1:1 route: same bucket as the source object.
    const std::string destBucket = bucket_.empty() ? r.bucket : bucket_;
    if (destBucket.empty()) {
        // metadata-only record without a bucket (e.g. account decisions): log only
        LOG_INFO("s3 target '", name_, "': ", r.outcome, " ", r.kind, " ", r.account,
                 r.bucket.empty() ? "" : " " + r.bucket, r.key.empty() ? "" : "/" + r.key, " (", r.reason, ")");
        return Result<void>::success();
    }

    auto exists = destination_->headBucket(destBucket);
    if (!exists) return Result<void>(exists.error());
    if (!exists.value()) {
        auto created = destination_->createBucket(destBucket);
        if (!created) return Result<void>(created.error());
    }

    std::string destKey = renderKey(r);

    if (r.kind == "delete") {
        auto head = destination_->headObject(destBucket, destKey);
        if (head && !head.value().exists) return Result<void>::success(); // already gone
        auto del = destination_->deleteObject(destBucket, destKey);
        if (!del) return Result<void>(del.error());
        LOG_INFO("s3 target '", name_, "': deleted ", destBucket, "/", destKey);
        return Result<void>::success();
    }

    if (!dataPath.empty()) {
        auto meta = destination_->headObject(destBucket, destKey);
        if (meta && meta.value().size > r.size) {
            // skip when the destination copy is already newer/larger (delta friendly)
            return Result<void>::success();
        }
        auto put = destination_->putObjectFromFile(destBucket, destKey, dataPath, r.contentType);
        if (!put) return Result<void>(put.error());
        return Result<void>::success();
    }

    if (!source_) return Result<void>::failure("s3 target '" + name_ + "': no source client for streaming copy");
    auto meta = source_->headObject(r.bucket, r.key);
    if (!meta) return Result<void>(meta.error());
    if (!meta.value().exists) return Result<void>::failure("source object disappeared: " + r.bucket + "/" + r.key);

    const uint64_t maxInMemory = 8ull * 1024 * 1024;
    if (meta.value().size <= maxInMemory) {
        auto body = source_->getObjectRange(r.bucket, r.key, 0, meta.value().size);
        if (!body) return Result<void>(body.error());
        auto put = destination_->putObject(destBucket, destKey, body.value(), meta.value().contentType);
        if (!put) return Result<void>(put.error());
        return Result<void>::success();
    }

    // large object: stage to a temporary file, then upload (possibly multipart)
    std::string staging = "/tmp/s3mm-stage-" + std::to_string(tm::nowMs()) + "-" +
                          std::to_string((uint64_t)(uintptr_t)this);
    uint64_t offset = 0;
    std::FILE* f = std::fopen(staging.c_str(), "wb");
    if (!f) return Result<void>::failure("cannot create staging file " + staging);
    const uint64_t chunk = 16ull * 1024 * 1024;
    while (offset < meta.value().size) {
        uint64_t len = std::min(chunk, meta.value().size - offset);
        auto part = source_->getObjectRange(r.bucket, r.key, offset, len);
        if (!part) {
            std::fclose(f);
            ::unlink(staging.c_str());
            return Result<void>(part.error());
        }
        std::fwrite(part.value().data(), 1, part.value().size(), f);
        offset += part.value().size();
        if (part.value().size() < len) break;
    }
    std::fclose(f);

    Result<void> upload = Result<void>::failure("not attempted");
    if (meta.value().size <= 64ull * 1024 * 1024) {
        upload = destination_->putObjectFromFile(destBucket, destKey, staging, meta.value().contentType);
    } else {
        auto mp = destination_->uploadMultipartFromFile(destBucket, destKey, staging, 16ull * 1024 * 1024,
                                                       meta.value().contentType);
        upload = mp ? Result<void>::success() : Result<void>::failure(mp.error());
    }
    ::unlink(staging.c_str());
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
        return Result<TargetGroupPtr>::failure("target '" + name + "': unsupported type '" + def->kind + "'");
    }
    cache_[name] = group;
    return Result<TargetGroupPtr>(group);
}

TargetGroupPtr TargetFactory::successRoute(const registry::Replication& replication) const {
    const registry::Cluster* dst = registry_.cluster(replication.destination);
    if (!dst) return nullptr;
    std::string name = replication.name + "-rqueue";
    auto it = cache_.find(name);
    if (it != cache_.end()) return it->second;
    auto s3group = std::make_shared<S3Target>(name, "s3://" + dst->name + "/", std::string());
    // destination cluster binding is done by the engine (it owns clients)
    cache_[name] = s3group;
    return s3group;
}

Result<TargetFactory::Routes> TargetFactory::routesFor(const registry::Replication& replication) const {
    const policy::Bundle bundle = registry_.bundleOrBuiltin(replication.policy);
    Routes routes;

    std::string successName = bundle.routes.success.empty() ? replication.name + "-rqueue" : bundle.routes.success;
    std::string deniedName = bundle.routes.denied.empty() ? "null" : bundle.routes.denied;
    std::string warningName = bundle.routes.warning.empty() ? "quarantine" : bundle.routes.warning;

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
        if (!res) return Result<Routes>::failure(res.error());
        routes.success = res.value();
    }
    if (!routes.success) return Result<Routes>::failure("cannot resolve success route '" + successName + "'");

    auto denied = resolve(deniedName);
    if (!denied) return Result<Routes>::failure(denied.error());
    routes.denied = denied.value();

    auto warning = resolve(warningName);
    if (!warning) return Result<Routes>::failure(warning.error());
    routes.warning = warning.value();
    return Result<Routes>(std::move(routes));
}

} // namespace s3mm::repl
