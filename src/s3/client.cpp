#include "s3mm/s3/client.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <thread>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/s3/xml.hpp"

namespace s3mm::s3 {

static std::string isoOrEmpty(tm::TimePoint t) { return t.time_since_epoch().count() == 0 ? std::string() : tm::toIso8601(t); }

Client::Client(ClientOptions options, sigv4::Credentials credentials)
    : options_(std::move(options)), creds_(std::move(credentials)) {
    endpoints_ = options_.endpoints;
    if (endpoints_.empty()) throw Error("s3 client: no endpoints configured");
    for (auto& e : endpoints_)
        while (!e.empty() && e.back() == '/') e.pop_back();
    if (options_.rateLimitPerSec > 0) minIntervalMs_ = 1000.0 / options_.rateLimitPerSec;
}

void Client::throttle() {
    if (minIntervalMs_ <= 0) return;
    std::lock_guard<std::mutex> lock(throttleMutex_);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double, std::milli>(now - lastRequest_).count();
    if (elapsed < minIntervalMs_) {
        auto sleepFor = std::chrono::milliseconds((long)(minIntervalMs_ - elapsed));
        std::this_thread::sleep_for(sleepFor);
    }
    lastRequest_ = std::chrono::steady_clock::now();
}

std::string Client::bucketPath(const std::string& bucket) const { return "/" + bucket; }

std::string Client::objectPath(const std::string& bucket, const std::string& key) const {
    return "/" + bucket + "/" + key;
}

Client::Attempt Client::prepare(const std::string& method, const std::string& resourcePath,
                                const std::map<std::string, std::string>& query, const std::string& body,
                                const std::string& bodyFile, bool unsignedPayload, const std::string& range,
                                const std::vector<std::pair<std::string, std::string>>& extraHeaders) {
    Attempt attempt;
    size_t idx = endpointIndex_++ % endpoints_.size();
    http::Request req;
    req.method = method;
    req.url = endpoints_[idx] + (resourcePath.empty() ? "/" : resourcePath);
    req.query = query;
    req.body = body;
    req.bodyFile = bodyFile;
    req.unsignedPayload = unsignedPayload;
    req.range = range;
    req.insecure = options_.insecure;
    req.timeoutSec = options_.timeoutSec;
    req.connectTimeoutSec = options_.connectTimeoutSec;
    req.maxResponseBytes = 64 * 1024 * 1024;
    for (const auto& [k, v] : extraHeaders) req.headers[k] = v;
    attempt.request = std::move(req);
    return attempt;
}

Client::Attempt Client::execute(Attempt attempt) {
    int attempts = std::max(1, options_.maxRetries);
    for (int i = 0; i < attempts; ++i) {
        throttle();
        http::Request signedReq = attempt.request;
        sigv4::sign(signedReq, creds_, options_.service);
        attempt.response = http::Client().send(signedReq);
        const auto& r = attempt.response;
        if (r.transportError()) {
            endpointIndex_++; // rotate endpoint on transport failure
            LOG_WARN("s3 transport error on ", signedReq.url, ": ", r.curlError);
            std::this_thread::sleep_for(std::chrono::milliseconds(200 * (i + 1)));
            continue;
        }
        bool retryable = r.status == 429 || r.status >= 500;
        if (retryable && i + 1 < attempts) {
            int64_t backoff = 200L * (1 << i);
            auto retryAfter = r.header("retry-after");
            if (!retryAfter.empty()) {
                if (auto v = str::parseInt64(retryAfter)) backoff = std::max(backoff, *v * 1000);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
            continue;
        }
        return attempt;
    }
    return attempt;
}

http::Response Client::raw(const http::Request& request) {
    http::Request signedReq = request;
    signedReq.insecure = signedReq.insecure || options_.insecure;
    sigv4::sign(signedReq, creds_, options_.service);
    return http::Client().send(signedReq);
}

static std::string xmlError(const http::Response& r) {
    auto parsed = xml::parse(r.body);
    if (parsed) {
        std::string code = parsed.value().childText("Code");
        std::string msg = parsed.value().childText("Message");
        if (!code.empty() || !msg.empty()) return "HTTP " + std::to_string(r.status) + " " + code + ": " + msg;
    }
    std::string body = r.body.size() > 300 ? r.body.substr(0, 300) + "..." : r.body;
    return "HTTP " + std::to_string(r.status) + (body.empty() ? "" : " " + body);
}

// ------------------------------------------------------------------ buckets --

Result<std::vector<BucketInfo>> Client::listBuckets() {
    auto att = execute(prepare("GET", "/", {}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (!r.ok()) return Result<std::vector<BucketInfo>>::failure("ListBuckets: " + xmlError(r));
    auto doc = xml::parse(r.body);
    if (!doc) return Result<std::vector<BucketInfo>>::failure("ListBuckets: cannot parse XML: " + doc.error());
    std::vector<BucketInfo> out;
    if (const xml::Element* buckets = doc.value().child("Buckets")) {
        for (const auto* b : buckets->childrenNamed("Bucket")) {
            BucketInfo info;
            info.name = b->childText("Name");
            if (auto t = tm::fromIso8601(b->childText("CreationDate"))) info.created = *t;
            if (!info.name.empty()) out.push_back(std::move(info));
        }
    }
    return Result<std::vector<BucketInfo>>(std::move(out));
}

Result<bool> Client::headBucket(const std::string& bucket) {
    auto att = execute(prepare("HEAD", bucketPath(bucket), {}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (r.status == 404) return Result<bool>(false);
    if (!r.ok()) return Result<bool>::failure("HeadBucket: " + xmlError(r));
    return Result<bool>(true);
}

Result<void> Client::createBucket(const std::string& bucket, const std::string& location) {
    std::string body;
    if (!location.empty() && location != "us-east-1")
        body = "<CreateBucketConfiguration><LocationConstraint>" + xml::escape(location) +
               "</LocationConstraint></CreateBucketConfiguration>";
    auto att = execute(prepare("PUT", bucketPath(bucket), {}, body, {}, false, {}, {}));
    const auto& r = att.response;
    if (!r.ok() && r.status != 409) return Result<void>::failure("CreateBucket: " + xmlError(r));
    return Result<void>::success();
}

Result<void> Client::deleteBucket(const std::string& bucket) {
    auto att = execute(prepare("DELETE", bucketPath(bucket), {}, {}, {}, false, {}, {}));
    if (!att.response.ok()) return Result<void>::failure("DeleteBucket: " + xmlError(att.response));
    return Result<void>::success();
}

Result<std::string> Client::getBucketLocation(const std::string& bucket) {
    auto att = execute(prepare("GET", bucketPath(bucket), {{"location", ""}}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (r.status == 404) return Result<std::string>::failure("GetBucketLocation: no such bucket");
    if (!r.ok()) return Result<std::string>("us-east-1"); // tolerate implementations without ?location
    auto doc = xml::parse(r.body);
    if (!doc || !doc.value().child("LocationConstraint")) return Result<std::string>("us-east-1");
    std::string loc = doc.value().childText("LocationConstraint");
    return Result<std::string>(loc.empty() ? "us-east-1" : loc);
}

Result<std::string> Client::getBucketPolicy(const std::string& bucket) {
    auto att = execute(prepare("GET", bucketPath(bucket), {{"policy", ""}}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (r.status == 404) return Result<std::string>(std::string());
    if (!r.ok()) return Result<std::string>::failure("GetBucketPolicy: " + xmlError(r));
    return Result<std::string>(r.body);
}

Result<void> Client::putBucketPolicy(const std::string& bucket, const std::string& jsonPolicy) {
    auto att = execute(prepare("PUT", bucketPath(bucket), {{"policy", ""}}, jsonPolicy, {}, false,
                               {}, {{"Content-Type", "application/json"}}));
    if (!att.response.ok()) return Result<void>::failure("PutBucketPolicy: " + xmlError(att.response));
    return Result<void>::success();
}

Result<void> Client::deleteBucketPolicy(const std::string& bucket) {
    auto att = execute(prepare("DELETE", bucketPath(bucket), {{"policy", ""}}, {}, {}, false, {}, {}));
    if (!att.response.ok() && att.response.status != 404) return Result<void>::failure("DeleteBucketPolicy: " + xmlError(att.response));
    return Result<void>::success();
}

Result<bool> Client::isBucketPublic(const std::string& bucket) {
    auto att = execute(prepare("GET", bucketPath(bucket), {{"policyStatus", ""}}, {}, {}, false, {}, {}));
    if (att.response.ok()) {
        auto doc = xml::parse(att.response.body);
        if (doc) {
            const xml::Element* st = doc.value().child("PolicyStatus");
            if (st) return Result<bool>(st->childText("IsPublic") == "true");
        }
    }
    auto acl = getBucketAcl(bucket);
    if (!acl) return Result<bool>::failure(acl.error());
    for (const auto& g : acl.value().grants)
        if (g.granteeType == "Group" && (g.grantee.find("AllUsers") != std::string::npos ||
                                         g.grantee.find("AuthenticatedUsers") != std::string::npos))
            return Result<bool>(true);
    return Result<bool>(false);
}

Result<BucketAcl> Client::getBucketAcl(const std::string& bucket) {
    auto att = execute(prepare("GET", bucketPath(bucket), {{"acl", ""}}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (!r.ok()) return Result<BucketAcl>::failure("GetBucketAcl: " + xmlError(r));
    auto doc = xml::parse(r.body);
    if (!doc) return Result<BucketAcl>::failure("GetBucketAcl: cannot parse XML");
    BucketAcl acl;
    if (const xml::Element* owner = doc.value().child("Owner")) {
        acl.owner = owner->childText("ID");
        acl.ownerDisplayName = owner->childText("DisplayName");
    }
    if (const xml::Element* grants = doc.value().child("AccessControlList")) {
        for (const auto* g : grants->childrenNamed("Grant")) {
            AclGrant grant;
            grant.permission = g->childText("Permission");
            if (const xml::Element* grantee = g->child("Grantee")) {
                for (const auto& [k, v] : grantee->attrs)
                    if (k == "type" || k == "xsi:type" || str::endsWith(k, "}type")) grant.granteeType = v;
                grant.grantee = grantee->childText("ID");
                if (grant.grantee.empty()) grant.grantee = grantee->childText("URI");
                if (grant.grantee.empty()) grant.grantee = grantee->childText("EmailAddress");
            }
            acl.grants.push_back(std::move(grant));
        }
    }
    return Result<BucketAcl>(std::move(acl));
}

Result<void> Client::putBucketAcl(const std::string& bucket, const BucketAcl& acl) {
    std::string owner = acl.owner.empty() ? bucket : acl.owner;
    std::string xmlBody = "<AccessControlPolicy><Owner>" + xml::tag("ID", owner) + xml::tag("DisplayName", acl.ownerDisplayName) +
                          "</Owner><AccessControlList>";
    for (const auto& g : acl.grants) {
        std::string type = g.granteeType.empty() ? (g.grantee.find("://") != std::string::npos ? "Group" : "CanonicalUser")
                                                 : g.granteeType;
        std::string grantee = "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"" + type + "\">";
        if (type == "Group") grantee += xml::tag("URI", g.grantee);
        else if (type == "AmazonCustomerByEmail") grantee += xml::tag("EmailAddress", g.grantee);
        else grantee += xml::tag("ID", g.grantee);
        grantee += "</Grantee>";
        xmlBody += "<Grant>" + grantee + xml::tag("Permission", g.permission) + "</Grant>";
    }
    xmlBody += "</AccessControlList></AccessControlPolicy>";
    auto att = execute(prepare("PUT", bucketPath(bucket), {{"acl", ""}}, xmlBody, {}, false,
                               {}, {{"Content-Type", "text/xml"}}));
    if (!att.response.ok()) return Result<void>::failure("PutBucketAcl: " + xmlError(att.response));
    return Result<void>::success();
}

Result<std::string> Client::getBucketVersioning(const std::string& bucket) {
    auto att = execute(prepare("GET", bucketPath(bucket), {{"versioning", ""}}, {}, {}, false, {}, {}));
    if (!att.response.ok()) return Result<std::string>(std::string());
    auto doc = xml::parse(att.response.body);
    if (!doc) return Result<std::string>(std::string());
    return Result<std::string>(doc.value().childText("Status"));
}

Result<void> Client::putBucketVersioning(const std::string& bucket, const std::string& status) {
    std::string body =
        "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" + xml::tag("Status", status) +
        "</VersioningConfiguration>";
    auto att = execute(prepare("PUT", bucketPath(bucket), {{"versioning", ""}}, body, {}, false,
                               {}, {{"Content-Type", "text/xml"}}));
    if (!att.response.ok()) return Result<void>::failure("PutBucketVersioning: " + xmlError(att.response));
    return Result<void>::success();
}

Result<BucketTagging> Client::getBucketTagging(const std::string& bucket) {
    auto att = execute(prepare("GET", bucketPath(bucket), {{"tagging", ""}}, {}, {}, false, {}, {}));
    if (att.response.status == 404) return Result<BucketTagging>(BucketTagging{});
    if (!att.response.ok()) return Result<BucketTagging>(BucketTagging{});
    auto doc = xml::parse(att.response.body);
    BucketTagging tagging;
    if (doc) {
        if (const xml::Element* set = doc.value().child("TagSet")) {
            for (const auto* t : set->childrenNamed("Tag")) tagging.tags[t->childText("Key")] = t->childText("Value");
        }
    }
    return Result<BucketTagging>(std::move(tagging));
}

Result<void> Client::putBucketTagging(const std::string& bucket, const BucketTagging& tagging) {
    std::string body = "<Tagging><TagSet>";
    for (const auto& [k, v] : tagging.tags)
        body += "<Tag>" + xml::tag("Key", k) + xml::tag("Value", v) + "</Tag>";
    body += "</TagSet></Tagging>";
    auto att = execute(prepare("PUT", bucketPath(bucket), {{"tagging", ""}}, body, {}, false,
                               {}, {{"Content-Type", "text/xml"}}));
    if (!att.response.ok()) return Result<void>::failure("PutBucketTagging: " + xmlError(att.response));
    return Result<void>::success();
}

// ------------------------------------------------------------------ objects --

Result<ObjectListPage> Client::listObjects(const std::string& bucket, const std::string& prefix,
                                           const std::string& delimiter, const std::string& token, int maxKeys) {
    std::map<std::string, std::string> query{{"list-type", "2"}, {"max-keys", std::to_string(maxKeys)}};
    if (!prefix.empty()) query["prefix"] = prefix;
    if (!delimiter.empty()) query["delimiter"] = delimiter;
    if (!token.empty()) query["continuation-token"] = token;
    auto att = execute(prepare("GET", bucketPath(bucket), query, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (!r.ok()) return Result<ObjectListPage>::failure("ListObjects: " + xmlError(r));
    auto doc = xml::parse(r.body);
    if (!doc) return Result<ObjectListPage>::failure("ListObjects: cannot parse XML");
    ObjectListPage page;
    page.truncated = doc.value().childText("IsTruncated") == "true";
    page.nextToken = doc.value().childText("NextContinuationToken");
    for (const auto* c : doc.value().childrenNamed("Contents")) {
        ObjectInfo info;
        info.key = c->childText("Key");
        info.size = c->childText("Size").empty() ? 0 : (uint64_t)std::strtoull(c->childText("Size").c_str(), nullptr, 10);
        if (auto t = tm::fromIso8601(c->childText("LastModified"))) info.lastModified = *t;
        info.etag = c->childText("ETag");
        info.storageClass = c->childText("StorageClass");
        info.versionId = c->childText("VersionId");
        page.objects.push_back(std::move(info));
    }
    for (const auto* c : doc.value().childrenNamed("CommonPrefixes")) page.commonPrefixes.push_back(c->childText("Prefix"));
    return Result<ObjectListPage>(std::move(page));
}

Result<std::vector<ObjectInfo>> Client::listAllObjects(const std::string& bucket, const std::string& prefix) {
    std::vector<ObjectInfo> out;
    std::string token;
    do {
        auto page = listObjects(bucket, prefix, {}, token, 1000);
        if (!page) return Result<std::vector<ObjectInfo>>::failure(page.error());
        for (auto& o : page.value().objects) out.push_back(std::move(o));
        token = page.value().truncated ? page.value().nextToken : std::string();
    } while (!token.empty());
    return Result<std::vector<ObjectInfo>>(std::move(out));
}

Result<ObjectMeta> Client::headObject(const std::string& bucket, const std::string& key) {
    auto att = execute(prepare("HEAD", objectPath(bucket, key), {}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    ObjectMeta meta;
    if (r.status == 404) return Result<ObjectMeta>(meta);
    if (!r.ok()) return Result<ObjectMeta>::failure("HeadObject: " + xmlError(r));
    meta.exists = true;
    meta.size = r.header("content-length").empty() ? 0 : std::strtoull(r.header("content-length").c_str(), nullptr, 10);
    meta.etag = r.header("etag");
    meta.contentType = r.header("content-type");
    meta.storageClass = r.header("x-amz-storage-class");
    meta.versionId = r.header("x-amz-version-id");
    if (!r.header("x-amz-mp-parts-count").empty()) meta.parts = std::atoi(r.header("x-amz-mp-parts-count").c_str());
    if (auto t = tm::fromIso8601(r.header("last-modified"))) meta.lastModified = *t;
    for (const auto& [k, v] : r.headers)
        if (str::startsWith(k, "x-amz-meta-")) meta.userMeta[k.substr(std::strlen("x-amz-meta-"))] = v;
    return Result<ObjectMeta>(meta);
}

Result<std::string> Client::getObjectRange(const std::string& bucket, const std::string& key, uint64_t offset,
                                            uint64_t length) {
    std::string range = "bytes=" + std::to_string(offset) + "-" + std::to_string(offset + length - 1);
    auto att = execute(prepare("GET", objectPath(bucket, key), {}, {}, {}, false, range, {}));
    const auto& r = att.response;
    if (!r.ok() && r.status != 206) return Result<std::string>::failure("GetObject: " + xmlError(r));
    return Result<std::string>(r.body);
}

Result<void> Client::putObject(const std::string& bucket, const std::string& key, const std::string& body,
                               const std::string& contentType,
                               const std::map<std::string, std::string>& userMeta) {
    std::vector<std::pair<std::string, std::string>> headers;
    if (!contentType.empty()) headers.emplace_back("Content-Type", contentType);
    for (const auto& [k, v] : userMeta) headers.emplace_back("x-amz-meta-" + k, v);
    auto att = execute(prepare("PUT", objectPath(bucket, key), {}, body, {}, false, {}, headers));
    if (!att.response.ok()) return Result<void>::failure("PutObject: " + xmlError(att.response));
    return Result<void>::success();
}

Result<void> Client::putObjectFromFile(const std::string& bucket, const std::string& key, const std::string& path,
                                       const std::string& contentType,
                                       const std::map<std::string, std::string>& userMeta) {
    std::vector<std::pair<std::string, std::string>> headers;
    if (!contentType.empty()) headers.emplace_back("Content-Type", contentType);
    for (const auto& [k, v] : userMeta) headers.emplace_back("x-amz-meta-" + k, v);
    auto att = execute(prepare("PUT", objectPath(bucket, key), {}, "", path, true, {}, headers));
    if (!att.response.ok()) return Result<void>::failure("PutObject: " + xmlError(att.response));
    return Result<void>::success();
}

Result<std::string> Client::uploadMultipartFromFile(const std::string& bucket, const std::string& key,
                                                    const std::string& path, uint64_t partSize,
                                                    const std::string& contentType,
                                                    const std::map<std::string, std::string>& userMeta) {
    if (partSize < 5 * 1024 * 1024) partSize = 5 * 1024 * 1024;
    std::vector<std::pair<std::string, std::string>> headers;
    if (!contentType.empty()) headers.emplace_back("Content-Type", contentType);
    for (const auto& [k, v] : userMeta) headers.emplace_back("x-amz-meta-" + k, v);

    auto create = execute(prepare("POST", objectPath(bucket, key), {{"uploads", ""}}, {}, {}, false, {}, headers));
    if (!create.response.ok()) return Result<std::string>::failure("CreateMultipartUpload: " + xmlError(create.response));
    auto doc = xml::parse(create.response.body);
    if (!doc) return Result<std::string>::failure("CreateMultipartUpload: cannot parse XML");
    std::string uploadId = doc.value().childText("UploadId");
    if (uploadId.empty()) return Result<std::string>::failure("CreateMultipartUpload: empty UploadId");

    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        execute(prepare("DELETE", objectPath(bucket, key), {{"uploadId", uploadId}}, {}, {}, false, {}, {}));
        return Result<std::string>::failure("cannot open " + path);
    }
    std::vector<std::pair<int, std::string>> parts;
    std::string buffer((size_t)partSize, '\0');
    int partNumber = 1;
    std::string etag;
    while (true) {
        size_t n = std::fread(buffer.data(), 1, buffer.size(), f);
        if (n == 0) break;
        auto put = execute(prepare("PUT", objectPath(bucket, key),
                                   {{"partNumber", std::to_string(partNumber)}, {"uploadId", uploadId}},
                                   buffer.substr(0, n), {}, false, {}, {}));
        if (!put.response.ok()) {
            std::fclose(f);
            execute(prepare("DELETE", objectPath(bucket, key), {{"uploadId", uploadId}}, {}, {}, false, {}, {}));
            return Result<std::string>::failure("UploadPart " + std::to_string(partNumber) + ": " + xmlError(put.response));
        }
        etag = put.response.header("etag");
        parts.emplace_back(partNumber, etag);
        ++partNumber;
        if (n < buffer.size()) break;
    }
    std::fclose(f);

    std::string completeBody = "<CompleteMultipartUpload>";
    for (const auto& [num, e] : parts)
        completeBody += "<Part>" + xml::tag("PartNumber", std::to_string(num)) + xml::tag("ETag", e) + "</Part>";
    completeBody += "</CompleteMultipartUpload>";
    auto complete = execute(prepare("POST", objectPath(bucket, key), {{"uploadId", uploadId}}, completeBody, {}, false,
                                    {}, {{"Content-Type", "text/xml"}}));
    if (!complete.response.ok()) {
        execute(prepare("DELETE", objectPath(bucket, key), {{"uploadId", uploadId}}, {}, {}, false, {}, {}));
        return Result<std::string>::failure("CompleteMultipartUpload: " + xmlError(complete.response));
    }
    return Result<std::string>(etag);
}

Result<void> Client::deleteObject(const std::string& bucket, const std::string& key) {
    auto att = execute(prepare("DELETE", objectPath(bucket, key), {}, {}, {}, false, {}, {}));
    if (!att.response.ok()) return Result<void>::failure("DeleteObject: " + xmlError(att.response));
    return Result<void>::success();
}

Result<std::string> Client::copyObject(const std::string& fromBucket, const std::string& fromKey,
                                       const std::string& toBucket, const std::string& toKey) {
    auto att = execute(prepare("PUT", objectPath(toBucket, toKey), {}, {}, {}, false, {},
                               {{"x-amz-copy-source", "/" + fromBucket + "/" + fromKey}}));
    if (!att.response.ok()) return Result<std::string>::failure("CopyObject: " + xmlError(att.response));
    auto doc = xml::parse(att.response.body);
    return Result<std::string>(doc ? doc.value().childText("ETag") : std::string());
}

} // namespace s3mm::s3
