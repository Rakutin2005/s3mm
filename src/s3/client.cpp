#include "s3mm/s3/client.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <thread>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/s3/xml.hpp"

namespace s3mm::s3 {

/// `k1=v1&k2=v2` for the x-amz-tagging header (values are URL encoded).
static std::string taggingHeader(const std::map<std::string, std::string>& tags) {
    std::string out;
    for (const auto& [k, v] : tags) {
        if (!out.empty()) out += '&';
        out += http::urlEncode(k, true) + "=" + http::urlEncode(v, true);
    }
    return out;
}

static void appendObjectHeaders(std::vector<std::pair<std::string, std::string>>& headers,
                                const ObjectMeta& meta) {
    if (!meta.contentType.empty()) headers.emplace_back("Content-Type", meta.contentType);
    if (!meta.contentEncoding.empty()) headers.emplace_back("Content-Encoding", meta.contentEncoding);
    if (!meta.contentLanguage.empty()) headers.emplace_back("Content-Language", meta.contentLanguage);
    if (!meta.contentDisposition.empty()) headers.emplace_back("Content-Disposition", meta.contentDisposition);
    if (!meta.cacheControl.empty()) headers.emplace_back("Cache-Control", meta.cacheControl);
    if (!meta.expires.empty()) headers.emplace_back("Expires", meta.expires);
    if (!meta.storageClass.empty() && meta.storageClass != "STANDARD")
        headers.emplace_back("x-amz-storage-class", meta.storageClass);
    for (const auto& [k, v] : meta.userMeta) headers.emplace_back("x-amz-meta-" + k, v);
    if (!meta.tags.empty()) headers.emplace_back("x-amz-tagging", taggingHeader(meta.tags));
}

Client::Client(ClientOptions options, sigv4::Credentials credentials)
    : options_(std::move(options)), creds_(std::move(credentials)) {
    endpoints_ = options_.endpoints;
    if (endpoints_.empty()) {
        LOG_ERROR("s3 client: no endpoints configured");
        throw Error("s3 client: no endpoints configured");
    }
    for (auto& e : endpoints_)
        while (!e.empty() && e.back() == '/') e.pop_back();
    if (options_.rateLimitPerSec > 0) minIntervalMs_ = 1000.0 / options_.rateLimitPerSec;
    std::string list;
    for (const auto& e : endpoints_) list += (list.empty() ? "" : ",") + e;
    LOG_DEBUG("s3 client: endpoints=", list, " service=", options_.service, " access_key=", creds_.accessKey,
              " timeout=", options_.timeoutSec, "s connect_timeout=", options_.connectTimeoutSec,
              "s retries=", options_.maxRetries, " rate_limit=", options_.rateLimitPerSec, "/s",
              options_.insecure ? " tls_verify=off" : "");
}

void Client::throttle() {
    if (minIntervalMs_ <= 0) return;
    std::lock_guard<std::mutex> lock(throttleMutex_);
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double, std::milli>(now - lastRequest_).count();
    if (elapsed < minIntervalMs_) {
        auto sleepFor = std::chrono::milliseconds((long)(minIntervalMs_ - elapsed));
        LOG_DEBUG("s3: rate limit ", options_.rateLimitPerSec, "/s, sleeping ", sleepFor.count(), " ms");
        std::this_thread::sleep_for(sleepFor);
    }
    lastRequest_ = std::chrono::steady_clock::now();
}

std::string Client::bucketPath(const std::string& bucket) const {
    return "/" + http::urlEncode(bucket, true);
}

std::string Client::objectPath(const std::string& bucket, const std::string& key) const {
    // Keys may contain spaces, non-ASCII bytes and other characters that curl
    // would otherwise reject or send unencoded. Keep '/' as the separator.
    return "/" + http::urlEncode(bucket, true) + "/" + http::urlEncode(key, false);
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
    // Range requests fetch object data: the response may legitimately be as
    // large as the requested slice, so lift the default control-plane cap to
    // cover it (still bounded by the requested length).
    if (!range.empty()) {
        // parse "bytes=OFF-OFFLEN" style ranges to derive the expected size
        auto dash = range.find('-');
        if (dash != std::string::npos && dash + 1 < range.size()) {
            auto fromEnd = str::parseInt64(std::string_view(range).substr(dash + 1));
            auto fromStart = str::parseInt64(std::string_view(range).substr(6, dash - 6)); // after "bytes="
            if (fromEnd && fromStart && *fromEnd >= *fromStart) {
                int64_t len = *fromEnd - *fromStart + 1;
                if (len > req.maxResponseBytes)
                    req.maxResponseBytes = len + 64 * 1024; // margin for chunked lies
            } else if (fromEnd && *fromEnd > req.maxResponseBytes) {
                req.maxResponseBytes = *fromEnd + 64 * 1024;
            }
        }
    }
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
        LOG_DEBUG("s3: ", signedReq.method, " ", signedReq.url, " attempt ", i + 1, "/", attempts);
        attempt.response = http::Client().send(signedReq);
        const auto& r = attempt.response;
        if (r.transportError()) {
            endpointIndex_++; // rotate endpoint on transport failure
            LOG_WARN("s3 transport error on ", signedReq.url, ": ", r.curlError, " (attempt ", i + 1, "/", attempts,
                     endpoints_.size() > 1 ? ", failing over to " + endpoints_[endpointIndex_ % endpoints_.size()] : std::string(), ")");
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
            LOG_WARN("s3: ", signedReq.method, " ", signedReq.url, " -> HTTP ", r.status,
                     r.status == 429 ? " (throttled)" : "", ", retrying in ", backoff, " ms (attempt ", i + 1, "/", attempts, ")");
            std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
            continue;
        }
        if (retryable) LOG_WARN("s3: ", signedReq.method, " ", signedReq.url, " -> HTTP ", r.status, ", retries exhausted (", attempts, ")");
        return attempt;
    }
    if (attempt.response.transportError())
        LOG_ERROR("s3: ", attempt.request.method, " ", attempt.request.url, " failed on all ", attempts,
                  " attempt(s): ", attempt.response.curlError);
    return attempt;
}

http::Response Client::raw(const http::Request& request) {
    http::Request signedReq = request;
    signedReq.insecure = signedReq.insecure || options_.insecure;
    sigv4::sign(signedReq, creds_, options_.service);
    LOG_DEBUG("s3: raw ", signedReq.method, " ", signedReq.url);
    auto r = http::Client().send(signedReq);
    if (!r.ok()) LOG_WARN("s3: raw ", signedReq.method, " ", signedReq.url, " -> ", r.errorText());
    return r;
}

static std::string xmlError(const http::Response& r) {
    auto parsed = xml::parse(r.body);
    if (!parsed && !r.body.empty()) LOG_DEBUG("s3: error body is not XML: ", parsed.error());
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
    LOG_DEBUG("s3: ListBuckets ", primaryEndpoint());
    auto att = execute(prepare("GET", "/", {}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (!r.ok()) {
        std::string err = "ListBuckets: " + xmlError(r);
        LOG_ERROR("s3: ", err, " [", primaryEndpoint(), "]");
        return Result<std::vector<BucketInfo>>::failure(err);
    }
    auto doc = xml::parse(r.body);
    if (!doc) {
        std::string err = "ListBuckets: cannot parse XML: " + doc.error();
        LOG_ERROR("s3: ", err, " [", primaryEndpoint(), "]");
        return Result<std::vector<BucketInfo>>::failure(err);
    }
    std::vector<BucketInfo> out;
    if (const xml::Element* buckets = doc.value().child("Buckets")) {
        for (const auto* b : buckets->childrenNamed("Bucket")) {
            BucketInfo info;
            info.name = b->childText("Name");
            if (auto t = tm::fromIso8601(b->childText("CreationDate"))) info.created = *t;
            if (!info.name.empty()) out.push_back(std::move(info));
        }
    }
    LOG_DEBUG("s3: ListBuckets -> ", out.size(), " bucket(s)");
    return Result<std::vector<BucketInfo>>(std::move(out));
}

Result<bool> Client::headBucket(const std::string& bucket) {
    LOG_DEBUG("s3: HeadBucket s3://", bucket);
    auto att = execute(prepare("HEAD", bucketPath(bucket), {}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (r.status == 404) {
        LOG_DEBUG("s3: HeadBucket s3://", bucket, " -> not found");
        return Result<bool>(false);
    }
    if (!r.ok()) {
        std::string err = "HeadBucket: " + xmlError(r);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<bool>::failure(err);
    }
    return Result<bool>(true);
}

Result<void> Client::createBucket(const std::string& bucket, const std::string& location) {
    LOG_DEBUG("s3: CreateBucket s3://", bucket);
    std::string body;
    if (!location.empty() && location != "us-east-1")
        body = "<CreateBucketConfiguration><LocationConstraint>" + xml::escape(location) +
               "</LocationConstraint></CreateBucketConfiguration>";
    auto att = execute(prepare("PUT", bucketPath(bucket), {}, body, {}, false, {}, {}));
    const auto& r = att.response;
    if (!r.ok() && r.status != 409) {
        std::string err = "CreateBucket: " + xmlError(r);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<void>::failure(err);
    }
    if (r.status == 409) LOG_DEBUG("s3: CreateBucket s3://", bucket, " -> 409 (already exists)");
    else LOG_INFO("s3: bucket s3://", bucket, " created", location.empty() ? "" : " in " + location);
    return Result<void>::success();
}

Result<void> Client::deleteBucket(const std::string& bucket) {
    LOG_DEBUG("s3: DeleteBucket s3://", bucket);
    auto att = execute(prepare("DELETE", bucketPath(bucket), {}, {}, {}, false, {}, {}));
    if (!att.response.ok()) {
        std::string err = "DeleteBucket: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<void>::failure(err);
    }
    LOG_INFO("s3: bucket s3://", bucket, " deleted");
    return Result<void>::success();
}

Result<std::string> Client::getBucketLocation(const std::string& bucket) {
    LOG_DEBUG("s3: GetBucketLocation s3://", bucket);
    auto att = execute(prepare("GET", bucketPath(bucket), {{"location", ""}}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (r.status == 404) {
        std::string err = "GetBucketLocation: no such bucket";
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<std::string>::failure(err);
    }
    if (!r.ok()) { // tolerate implementations without ?location
        LOG_DEBUG("s3: GetBucketLocation s3://", bucket, " -> ", r.errorText(), ", assuming us-east-1");
        return Result<std::string>("us-east-1");
    }
    auto doc = xml::parse(r.body);
    if (!doc || !doc.value().child("LocationConstraint")) {
        LOG_DEBUG("s3: GetBucketLocation s3://", bucket, ": no LocationConstraint, assuming us-east-1");
        return Result<std::string>("us-east-1");
    }
    std::string loc = doc.value().childText("LocationConstraint");
    LOG_DEBUG("s3: GetBucketLocation s3://", bucket, " -> ", loc.empty() ? "us-east-1" : loc);
    return Result<std::string>(loc.empty() ? "us-east-1" : loc);
}

Result<std::string> Client::getBucketPolicy(const std::string& bucket) {
    LOG_DEBUG("s3: GetBucketPolicy s3://", bucket);
    auto att = execute(prepare("GET", bucketPath(bucket), {{"policy", ""}}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (r.status == 404) {
        LOG_DEBUG("s3: GetBucketPolicy s3://", bucket, " -> no policy");
        return Result<std::string>(std::string());
    }
    if (!r.ok()) {
        std::string err = "GetBucketPolicy: " + xmlError(r);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<std::string>::failure(err);
    }
    LOG_DEBUG("s3: GetBucketPolicy s3://", bucket, " -> ", r.body.size(), " bytes");
    return Result<std::string>(r.body);
}

Result<void> Client::putBucketPolicy(const std::string& bucket, const std::string& jsonPolicy) {
    LOG_DEBUG("s3: PutBucketPolicy s3://", bucket);
    auto att = execute(prepare("PUT", bucketPath(bucket), {{"policy", ""}}, jsonPolicy, {}, false,
                               {}, {{"Content-Type", "application/json"}}));
    if (!att.response.ok()) {
        std::string err = "PutBucketPolicy: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<void>::failure(err);
    }
    LOG_INFO("s3: bucket policy set on s3://", bucket, " (", jsonPolicy.size(), " bytes)");
    return Result<void>::success();
}

Result<void> Client::deleteBucketPolicy(const std::string& bucket) {
    LOG_DEBUG("s3: DeleteBucketPolicy s3://", bucket);
    auto att = execute(prepare("DELETE", bucketPath(bucket), {{"policy", ""}}, {}, {}, false, {}, {}));
    if (!att.response.ok() && att.response.status != 404) {
        std::string err = "DeleteBucketPolicy: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<void>::failure(err);
    }
    return Result<void>::success();
}

Result<bool> Client::isBucketPublic(const std::string& bucket) {
    LOG_DEBUG("s3: IsBucketPublic s3://", bucket);
    auto att = execute(prepare("GET", bucketPath(bucket), {{"policyStatus", ""}}, {}, {}, false, {}, {}));
    if (att.response.ok()) {
        auto doc = xml::parse(att.response.body);
        if (doc) {
            const xml::Element* st = doc.value().child("PolicyStatus");
            if (st) {
                LOG_DEBUG("s3: IsBucketPublic s3://", bucket, " (policyStatus) -> ", st->childText("IsPublic"));
                return Result<bool>(st->childText("IsPublic") == "true");
            }
        }
    }
    LOG_DEBUG("s3: IsBucketPublic s3://", bucket, ": policyStatus unavailable (", att.response.errorText(), "), falling back to ACL");
    auto acl = getBucketAcl(bucket);
    if (!acl) return Result<bool>::failure(acl.error());
    for (const auto& g : acl.value().grants)
        if (g.granteeType == "Group" && (g.grantee.find("AllUsers") != std::string::npos ||
                                         g.grantee.find("AuthenticatedUsers") != std::string::npos))
            return Result<bool>(true);
    return Result<bool>(false);
}

Result<BucketAcl> Client::getBucketAcl(const std::string& bucket) {
    LOG_DEBUG("s3: GetBucketAcl s3://", bucket);
    auto att = execute(prepare("GET", bucketPath(bucket), {{"acl", ""}}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (!r.ok()) {
        std::string err = "GetBucketAcl: " + xmlError(r);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<BucketAcl>::failure(err);
    }
    auto doc = xml::parse(r.body);
    if (!doc) {
        std::string err = "GetBucketAcl: cannot parse XML";
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<BucketAcl>::failure(err);
    }
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
    LOG_DEBUG("s3: GetBucketAcl s3://", bucket, " -> owner=", acl.owner, " grants=", acl.grants.size());
    return Result<BucketAcl>(std::move(acl));
}

Result<void> Client::putBucketAcl(const std::string& bucket, const BucketAcl& acl) {
    LOG_DEBUG("s3: PutBucketAcl s3://", bucket);
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
    LOG_DEBUG("s3: PutBucketAcl s3://", bucket, " owner=", owner, " grants=", acl.grants.size());
    auto att = execute(prepare("PUT", bucketPath(bucket), {{"acl", ""}}, xmlBody, {}, false,
                               {}, {{"Content-Type", "text/xml"}}));
    if (!att.response.ok()) {
        std::string err = "PutBucketAcl: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<void>::failure(err);
    }
    return Result<void>::success();
}

Result<std::string> Client::getBucketVersioning(const std::string& bucket) {
    LOG_DEBUG("s3: GetBucketVersioning s3://", bucket);
    auto att = execute(prepare("GET", bucketPath(bucket), {{"versioning", ""}}, {}, {}, false, {}, {}));
    if (!att.response.ok()) {
        LOG_DEBUG("s3: GetBucketVersioning s3://", bucket, " -> ", att.response.errorText(), ", treating as unversioned");
        return Result<std::string>(std::string());
    }
    auto doc = xml::parse(att.response.body);
    if (!doc) {
        LOG_WARN("s3: GetBucketVersioning s3://", bucket, ": cannot parse XML: ", doc.error());
        return Result<std::string>(std::string());
    }
    LOG_DEBUG("s3: GetBucketVersioning s3://", bucket, " -> '", doc.value().childText("Status"), "'");
    return Result<std::string>(doc.value().childText("Status"));
}

Result<void> Client::putBucketVersioning(const std::string& bucket, const std::string& status) {
    LOG_DEBUG("s3: PutBucketVersioning s3://", bucket, " status=", status);
    std::string body =
        "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" + xml::tag("Status", status) +
        "</VersioningConfiguration>";
    auto att = execute(prepare("PUT", bucketPath(bucket), {{"versioning", ""}}, body, {}, false,
                               {}, {{"Content-Type", "text/xml"}}));
    if (!att.response.ok()) {
        std::string err = "PutBucketVersioning: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<void>::failure(err);
    }
    return Result<void>::success();
}

Result<BucketTagging> Client::getBucketTagging(const std::string& bucket) {
    LOG_DEBUG("s3: GetBucketTagging s3://", bucket);
    auto att = execute(prepare("GET", bucketPath(bucket), {{"tagging", ""}}, {}, {}, false, {}, {}));
    if (att.response.status == 404) return Result<BucketTagging>(BucketTagging{});
    if (!att.response.ok()) {
        LOG_WARN("s3: GetBucketTagging s3://", bucket, " -> ", att.response.errorText(), ", treating as untagged");
        return Result<BucketTagging>(BucketTagging{});
    }
    auto doc = xml::parse(att.response.body);
    BucketTagging tagging;
    if (doc) {
        if (const xml::Element* set = doc.value().child("TagSet")) {
            for (const auto* t : set->childrenNamed("Tag")) tagging.tags[t->childText("Key")] = t->childText("Value");
        }
    } else {
        LOG_WARN("s3: GetBucketTagging s3://", bucket, ": cannot parse XML: ", doc.error());
    }
    LOG_DEBUG("s3: GetBucketTagging s3://", bucket, " -> ", tagging.tags.size(), " tag(s)");
    return Result<BucketTagging>(std::move(tagging));
}

Result<void> Client::putBucketTagging(const std::string& bucket, const BucketTagging& tagging) {
    LOG_DEBUG("s3: PutBucketTagging s3://", bucket, " tags=", tagging.tags.size());
    std::string body = "<Tagging><TagSet>";
    for (const auto& [k, v] : tagging.tags)
        body += "<Tag>" + xml::tag("Key", k) + xml::tag("Value", v) + "</Tag>";
    body += "</TagSet></Tagging>";
    auto att = execute(prepare("PUT", bucketPath(bucket), {{"tagging", ""}}, body, {}, false,
                               {}, {{"Content-Type", "text/xml"}}));
    if (!att.response.ok()) {
        std::string err = "PutBucketTagging: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<void>::failure(err);
    }
    return Result<void>::success();
}

// ------------------------------------------------------------------ objects --

Result<ObjectListPage> Client::listObjects(const std::string& bucket, const std::string& prefix,
                                           const std::string& delimiter, const std::string& token, int maxKeys) {
    LOG_DEBUG("s3: ListObjects s3://", bucket, " prefix='", prefix, "' delimiter='", delimiter, "' max_keys=", maxKeys,
              token.empty() ? "" : " (continuation)");
    std::map<std::string, std::string> query{{"list-type", "2"}, {"max-keys", std::to_string(maxKeys)}};
    if (!prefix.empty()) query["prefix"] = prefix;
    if (!delimiter.empty()) query["delimiter"] = delimiter;
    if (!token.empty()) query["continuation-token"] = token;
    auto att = execute(prepare("GET", bucketPath(bucket), query, {}, {}, false, {}, {}));
    const auto& r = att.response;
    if (!r.ok()) {
        std::string err = "ListObjects: " + xmlError(r);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<ObjectListPage>::failure(err);
    }
    auto doc = xml::parse(r.body);
    if (!doc) {
        std::string err = "ListObjects: cannot parse XML";
        LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
        return Result<ObjectListPage>::failure(err);
    }
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
    LOG_DEBUG("s3: ListObjects s3://", bucket, " -> ", page.objects.size(), " object(s), ", page.commonPrefixes.size(),
              " prefix(es)", page.truncated ? ", truncated" : "");
    return Result<ObjectListPage>(std::move(page));
}

Result<void> Client::forEachObject(const std::string& bucket, const std::string& prefix,
                                   const std::function<Result<void>(const ObjectInfo&)>& callback) {
    LOG_DEBUG("s3: ForEachObject s3://", bucket, " prefix='", prefix, "'");
    std::string token;
    size_t pages = 0, objects = 0;
    do {
        auto page = listObjects(bucket, prefix, {}, token, 1000);
        if (!page) return Result<void>::failure(page.error());
        ++pages;
        for (const auto& o : page.value().objects) {
            ++objects;
            auto res = callback(o);
            if (!res) {
                LOG_DEBUG("s3: ForEachObject s3://", bucket, " stopped by callback at ", o.key, ": ", res.error());
                return res;
            }
        }
        token = page.value().truncated ? page.value().nextToken : std::string();
    } while (!token.empty());
    LOG_DEBUG("s3: ForEachObject s3://", bucket, " prefix='", prefix, "' done: ", objects, " object(s) in ", pages, " page(s)");
    return Result<void>::success();
}

Result<std::vector<ObjectInfo>> Client::listAllObjects(const std::string& bucket, const std::string& prefix) {
    LOG_DEBUG("s3: ListAllObjects s3://", bucket, " prefix='", prefix, "'");
    std::vector<ObjectInfo> out;
    auto res = forEachObject(bucket, prefix, [&out](const ObjectInfo& o) {
        out.push_back(o);
        return Result<void>::success();
    });
    if (!res) return Result<std::vector<ObjectInfo>>::failure(res.error());
    return Result<std::vector<ObjectInfo>>(std::move(out));
}

Result<void> Client::forEachObjectVersion(
    const std::string& bucket, const std::function<Result<void>(const ObjectVersion&)>& callback) {
    LOG_DEBUG("s3: ForEachObjectVersion s3://", bucket);
    std::string keyMarker;
    std::string versionMarker;
    for (;;) {
        std::map<std::string, std::string> query{{"versions", ""}, {"max-keys", "1000"}};
        if (!keyMarker.empty()) query["key-marker"] = keyMarker;
        if (!versionMarker.empty()) query["version-id-marker"] = versionMarker;
        auto att = execute(prepare("GET", bucketPath(bucket), query, {}, {}, false, {}, {}));
        const auto& r = att.response;
        if (!r.ok()) {
            std::string err = "ListObjectVersions: " + xmlError(r);
            LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
            return Result<void>::failure(err);
        }
        auto doc = xml::parse(r.body);
        if (!doc) {
            std::string err = "ListObjectVersions: cannot parse XML";
            LOG_ERROR("s3: ", err, " [s3://", bucket, "]");
            return Result<void>::failure(err);
        }
        for (const auto& name : {"Version", "DeleteMarker"}) {
            for (const auto* c : doc.value().childrenNamed(name)) {
                ObjectVersion v;
                v.key = c->childText("Key");
                v.versionId = c->childText("VersionId");
                v.deleteMarker = std::string(name) == "DeleteMarker";
                auto res = callback(v);
                if (!res) return res;
            }
        }
        LOG_DEBUG("s3: ListObjectVersions s3://", bucket, " page: ", doc.value().childrenNamed("Version").size(), " version(s), ",
                  doc.value().childrenNamed("DeleteMarker").size(), " delete marker(s)");
        if (doc.value().childText("IsTruncated") != "true") break;
        keyMarker = doc.value().childText("NextKeyMarker");
        versionMarker = doc.value().childText("NextVersionIdMarker");
        if (keyMarker.empty()) break;
    }
    return Result<void>::success();
}

Result<ObjectMeta> Client::headObject(const std::string& bucket, const std::string& key) {
    LOG_DEBUG("s3: HeadObject s3://", bucket, "/", key);
    auto att = execute(prepare("HEAD", objectPath(bucket, key), {}, {}, {}, false, {}, {}));
    const auto& r = att.response;
    ObjectMeta meta;
    if (r.status == 404) {
        LOG_DEBUG("s3: HeadObject s3://", bucket, "/", key, " -> not found");
        return Result<ObjectMeta>(meta);
    }
    if (!r.ok()) {
        std::string err = "HeadObject: " + xmlError(r);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<ObjectMeta>::failure(err);
    }
    meta.exists = true;
    meta.size = r.header("content-length").empty() ? 0 : std::strtoull(r.header("content-length").c_str(), nullptr, 10);
    meta.etag = r.header("etag");
    meta.contentType = r.header("content-type");
    meta.contentEncoding = r.header("content-encoding");
    meta.contentLanguage = r.header("content-language");
    meta.contentDisposition = r.header("content-disposition");
    meta.cacheControl = r.header("cache-control");
    meta.expires = r.header("expires");
    meta.storageClass = r.header("x-amz-storage-class");
    meta.versionId = r.header("x-amz-version-id");
    if (!r.header("x-amz-mp-parts-count").empty()) meta.parts = std::atoi(r.header("x-amz-mp-parts-count").c_str());
    const std::string lastModified = r.header("last-modified");
    if (auto t = tm::fromHttpDate(lastModified)) meta.lastModified = *t;
    else if (auto t2 = tm::fromIso8601(lastModified)) meta.lastModified = *t2;
    else if (!lastModified.empty()) LOG_WARN("s3: HeadObject s3://", bucket, "/", key, ": unparseable Last-Modified '", lastModified, "'");
    for (const auto& [k, v] : r.headers)
        if (str::startsWith(k, "x-amz-meta-")) meta.userMeta[k.substr(std::strlen("x-amz-meta-"))] = v;
    LOG_DEBUG("s3: HeadObject s3://", bucket, "/", key, " -> size=", meta.size, " etag=", meta.etag,
              meta.versionId.empty() ? "" : " version=" + meta.versionId);
    return Result<ObjectMeta>(meta);
}

Result<std::string> Client::getObjectRange(const std::string& bucket, const std::string& key, uint64_t offset,
                                            uint64_t length) {
    LOG_DEBUG("s3: GetObjectRange s3://", bucket, "/", key, " offset=", offset, " length=", length);
    if (length == 0) {
        LOG_DEBUG("s3: GetObjectRange s3://", bucket, "/", key, ": zero length, nothing to fetch");
        return Result<std::string>(std::string());
    }
    std::string range = "bytes=" + std::to_string(offset) + "-" + std::to_string(offset + length - 1);
    auto att = execute(prepare("GET", objectPath(bucket, key), {}, {}, {}, false, range, {}));
    const auto& r = att.response;
    if (!r.ok() && r.status != 206) {
        std::string err = "GetObject: " + xmlError(r);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<std::string>::failure(err);
    }
    LOG_DEBUG("s3: GetObjectRange s3://", bucket, "/", key, " -> ", r.body.size(), " bytes (HTTP ", r.status, ")");
    return Result<std::string>(r.body);
}

Result<BucketTagging> Client::getObjectTagging(const std::string& bucket, const std::string& key) {
    LOG_DEBUG("s3: GetObjectTagging s3://", bucket, "/", key);
    auto att = execute(prepare("GET", objectPath(bucket, key), {{"tagging", ""}}, {}, {}, false, {}, {}));
    if (att.response.status == 404) return Result<BucketTagging>(BucketTagging{});
    if (!att.response.ok()) {
        std::string err = "GetObjectTagging: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<BucketTagging>::failure(err);
    }
    BucketTagging tagging;
    auto doc = xml::parse(att.response.body);
    if (doc) {
        if (const xml::Element* set = doc.value().child("TagSet")) {
            for (const auto* t : set->childrenNamed("Tag"))
                tagging.tags[t->childText("Key")] = t->childText("Value");
        }
    } else {
        LOG_WARN("s3: GetObjectTagging s3://", bucket, "/", key, ": cannot parse XML: ", doc.error());
    }
    LOG_DEBUG("s3: GetObjectTagging s3://", bucket, "/", key, " -> ", tagging.tags.size(), " tag(s)");
    return Result<BucketTagging>(std::move(tagging));
}

Result<void> Client::putObjectTagging(const std::string& bucket, const std::string& key,
                                      const BucketTagging& tagging) {
    LOG_DEBUG("s3: PutObjectTagging s3://", bucket, "/", key, " tags=", tagging.tags.size());
    std::string body = "<Tagging><TagSet>";
    for (const auto& [k, v] : tagging.tags)
        body += "<Tag>" + xml::tag("Key", k) + xml::tag("Value", v) + "</Tag>";
    body += "</TagSet></Tagging>";
    auto att = execute(prepare("PUT", objectPath(bucket, key), {{"tagging", ""}}, body, {}, false,
                               {}, {{"Content-Type", "text/xml"}}));
    if (!att.response.ok()) {
        std::string err = "PutObjectTagging: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<void>::failure(err);
    }
    return Result<void>::success();
}

Result<void> Client::deleteObjectTagging(const std::string& bucket, const std::string& key) {
    LOG_DEBUG("s3: DeleteObjectTagging s3://", bucket, "/", key);
    auto att = execute(prepare("DELETE", objectPath(bucket, key), {{"tagging", ""}}, {}, {}, false, {}, {}));
    if (!att.response.ok() && att.response.status != 404) {
        std::string err = "DeleteObjectTagging: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<void>::failure(err);
    }
    return Result<void>::success();
}

Result<void> Client::putObject(const std::string& bucket, const std::string& key, const std::string& body,
                               const ObjectMeta& meta) {
    LOG_DEBUG("s3: PutObject s3://", bucket, "/", key, " size=", body.size(), " content_type=", meta.contentType);
    std::vector<std::pair<std::string, std::string>> headers;
    appendObjectHeaders(headers, meta);
    auto att = execute(prepare("PUT", objectPath(bucket, key), {}, body, {}, false, {}, headers));
    if (!att.response.ok()) {
        std::string err = "PutObject: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<void>::failure(err);
    }
    LOG_DEBUG("s3: PutObject s3://", bucket, "/", key, " -> ok, ", body.size(), " bytes, etag=", att.response.header("etag"));
    return Result<void>::success();
}

Result<void> Client::putObjectFromFile(const std::string& bucket, const std::string& key, const std::string& path,
                                       const ObjectMeta& meta) {
    LOG_DEBUG("s3: PutObjectFromFile s3://", bucket, "/", key, " from ", path);
    std::vector<std::pair<std::string, std::string>> headers;
    appendObjectHeaders(headers, meta);
    auto att = execute(prepare("PUT", objectPath(bucket, key), {}, "", path, true, {}, headers));
    if (!att.response.ok()) {
        std::string err = "PutObject: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, " from ", path, "]");
        return Result<void>::failure(err);
    }
    LOG_DEBUG("s3: PutObjectFromFile s3://", bucket, "/", key, " -> ok in ", (long long)(att.response.totalSeconds * 1000),
              " ms, etag=", att.response.header("etag"));
    return Result<void>::success();
}

Result<std::string> Client::uploadMultipartFromFile(const std::string& bucket, const std::string& key,
                                                    const std::string& path, uint64_t partSize,
                                                    const ObjectMeta& meta) {
    LOG_DEBUG("s3: UploadMultipartFromFile s3://", bucket, "/", key, " from ", path, " part_size=", partSize);
    if (partSize < 5 * 1024 * 1024) {
        LOG_DEBUG("s3: multipart part size ", partSize, " below S3 minimum, using 5 MiB");
        partSize = 5 * 1024 * 1024;
    }
    log::Stopwatch sw;
    std::vector<std::pair<std::string, std::string>> headers;
    appendObjectHeaders(headers, meta);

    auto create = execute(prepare("POST", objectPath(bucket, key), {{"uploads", ""}}, {}, {}, false, {}, headers));
    if (!create.response.ok()) {
        std::string err = "CreateMultipartUpload: " + xmlError(create.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<std::string>::failure(err);
    }
    auto doc = xml::parse(create.response.body);
    if (!doc) {
        std::string err = "CreateMultipartUpload: cannot parse XML";
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<std::string>::failure(err);
    }
    std::string uploadId = doc.value().childText("UploadId");
    if (uploadId.empty()) {
        std::string err = "CreateMultipartUpload: empty UploadId";
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<std::string>::failure(err);
    }

    LOG_DEBUG("s3: multipart upload created for s3://", bucket, "/", key, " upload_id=", uploadId);

    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        LOG_ERROR("s3: multipart: cannot open ", path, ": ", std::strerror(errno), "; aborting upload ", uploadId);
        execute(prepare("DELETE", objectPath(bucket, key), {{"uploadId", uploadId}}, {}, {}, false, {}, {}));
        std::string err = "cannot open " + path;
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<std::string>::failure(err);
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
            LOG_WARN("s3: multipart: aborting upload ", uploadId, " for s3://", bucket, "/", key, " after part ", partNumber, " failure");
            execute(prepare("DELETE", objectPath(bucket, key), {{"uploadId", uploadId}}, {}, {}, false, {}, {}));
            std::string err = "UploadPart " + std::to_string(partNumber) + ": " + xmlError(put.response);
            LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
            return Result<std::string>::failure(err);
        }
        etag = put.response.header("etag");
        LOG_DEBUG("s3: UploadPart ", partNumber, " s3://", bucket, "/", key, " -> ", n, " bytes, etag=", etag);
        parts.emplace_back(partNumber, etag);
        ++partNumber;
        if (n < buffer.size()) break;
    }
    if (std::ferror(f)) LOG_WARN("s3: multipart: read error on ", path, ": ", std::strerror(errno));
    std::fclose(f);

    LOG_DEBUG("s3: CompleteMultipartUpload s3://", bucket, "/", key, " upload_id=", uploadId, " parts=", parts.size());
    std::string completeBody = "<CompleteMultipartUpload>";
    for (const auto& [num, e] : parts)
        completeBody += "<Part>" + xml::tag("PartNumber", std::to_string(num)) + xml::tag("ETag", e) + "</Part>";
    completeBody += "</CompleteMultipartUpload>";
    auto complete = execute(prepare("POST", objectPath(bucket, key), {{"uploadId", uploadId}}, completeBody, {}, false,
                                    {}, {{"Content-Type", "text/xml"}}));
    if (!complete.response.ok()) {
        LOG_WARN("s3: multipart: aborting upload ", uploadId, " for s3://", bucket, "/", key, " after complete failure");
        execute(prepare("DELETE", objectPath(bucket, key), {{"uploadId", uploadId}}, {}, {}, false, {}, {}));
        std::string err = "CompleteMultipartUpload: " + xmlError(complete.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<std::string>::failure(err);
    }
    LOG_INFO("s3: multipart upload s3://", bucket, "/", key, " completed: ", parts.size(), " part(s) in ", sw.ms(), " ms");
    return Result<std::string>(etag);
}

Result<void> Client::deleteObject(const std::string& bucket, const std::string& key,
                                  const std::string& versionId) {
    LOG_DEBUG("s3: DeleteObject s3://", bucket, "/", key, versionId.empty() ? "" : " version=" + versionId);
    std::map<std::string, std::string> query;
    if (!versionId.empty()) query["versionId"] = versionId;
    auto att = execute(prepare("DELETE", objectPath(bucket, key), query, {}, {}, false, {}, {}));
    if (!att.response.ok()) {
        std::string err = "DeleteObject: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", bucket, "/", key, "]");
        return Result<void>::failure(err);
    }
    LOG_DEBUG("s3: DeleteObject s3://", bucket, "/", key, " -> HTTP ", att.response.status);
    return Result<void>::success();
}

Result<std::string> Client::copyObject(const std::string& fromBucket, const std::string& fromKey,
                                       const std::string& toBucket, const std::string& toKey) {
    LOG_DEBUG("s3: CopyObject s3://", fromBucket, "/", fromKey, " -> s3://", toBucket, "/", toKey);
    const std::string source = "/" + http::urlEncode(fromBucket, true) + "/" + http::urlEncode(fromKey, false);
    auto att = execute(prepare("PUT", objectPath(toBucket, toKey), {}, {}, {}, false, {},
                               {{"x-amz-copy-source", source}}));
    if (!att.response.ok()) {
        std::string err = "CopyObject: " + xmlError(att.response);
        LOG_ERROR("s3: ", err, " [s3://", fromBucket, "/", fromKey, " -> s3://", toBucket, "/", toKey, "]");
        return Result<std::string>::failure(err);
    }
    auto doc = xml::parse(att.response.body);
    if (!doc) LOG_WARN("s3: CopyObject s3://", toBucket, "/", toKey, ": cannot parse response XML: ", doc.error());
    LOG_DEBUG("s3: CopyObject -> s3://", toBucket, "/", toKey, " ok, etag=", doc ? doc.value().childText("ETag") : std::string());
    return Result<std::string>(doc ? doc.value().childText("ETag") : std::string());
}

} // namespace s3mm::s3
