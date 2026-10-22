#pragma once
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/common/time.hpp"
#include "s3mm/s3/http.hpp"
#include "s3mm/s3/sigv4.hpp"

namespace s3mm::s3 {

struct ObjectInfo {
    std::string key;
    uint64_t size = 0;
    tm::TimePoint lastModified;
    std::string etag;
    std::string storageClass;
    std::string versionId;
    bool latest = true;
};

struct ObjectListPage {
    std::vector<ObjectInfo> objects;
    std::vector<std::string> commonPrefixes;
    std::string nextToken;
    bool truncated = false;
};

struct BucketInfo {
    std::string name;
    tm::TimePoint created;
};

/// One entry of ListObjectVersions (a real version or a delete marker).
struct ObjectVersion {
    std::string key;
    std::string versionId; // may be "null" or empty for unversioned buckets
    bool deleteMarker = false;
};

struct AclGrant {
    std::string permission;   // READ|WRITE|READ_ACP|WRITE_ACP|FULL_CONTROL|...
    std::string granteeType;  // CanonicalUser|Group|AmazonCustomerByEmail
    std::string grantee;      // id or URI
};

struct BucketAcl {
    std::string owner;
    std::string ownerDisplayName;
    std::vector<AclGrant> grants;
};

struct BucketTagging {
    std::map<std::string, std::string> tags;
};

struct ObjectMeta {
    bool exists = false;
    uint64_t size = 0;
    std::string etag;
    tm::TimePoint lastModified;
    std::string contentType;
    std::string contentEncoding;
    std::string contentLanguage;
    std::string contentDisposition;
    std::string cacheControl;
    std::string expires;
    std::string storageClass;
    std::string versionId;
    int parts = 0; // 0 = single part
    std::map<std::string, std::string> userMeta;
    std::map<std::string, std::string> tags;
};

struct ClientOptions {
    std::vector<std::string> endpoints; // scheme://host:port, round-robin on failure
    bool pathStyle = true;
    bool insecure = false;
    int timeoutSec = 120;
    int connectTimeoutSec = 10;
    double rateLimitPerSec = 0; // 0 = unlimited
    std::string service = "s3"; // override for admin endpoints
    int maxRetries = 2;
};

class Client {
public:
    Client(ClientOptions options, sigv4::Credentials credentials);

    const sigv4::Credentials& credentials() const { return creds_; }
    const ClientOptions& options() const { return options_; }
    const std::string& primaryEndpoint() const { return endpoints_.front(); }

    // bucket operations --------------------------------------------------------
    Result<std::vector<BucketInfo>> listBuckets();
    Result<bool> headBucket(const std::string& bucket);
    Result<void> createBucket(const std::string& bucket, const std::string& location = {});
    Result<void> deleteBucket(const std::string& bucket);
    Result<std::string> getBucketLocation(const std::string& bucket);
    Result<std::string> getBucketPolicy(const std::string& bucket); // empty string when absent (404)
    Result<void> putBucketPolicy(const std::string& bucket, const std::string& jsonPolicy);
    Result<void> deleteBucketPolicy(const std::string& bucket);
    Result<bool> isBucketPublic(const std::string& bucket);
    Result<BucketAcl> getBucketAcl(const std::string& bucket);
    Result<void> putBucketAcl(const std::string& bucket, const BucketAcl& acl);
    Result<std::string> getBucketVersioning(const std::string& bucket); // "enabled"|"suspended"|""
    Result<void> putBucketVersioning(const std::string& bucket, const std::string& status);
    Result<BucketTagging> getBucketTagging(const std::string& bucket);
    Result<void> putBucketTagging(const std::string& bucket, const BucketTagging& tagging);

    // object operations --------------------------------------------------------
    Result<ObjectListPage> listObjects(const std::string& bucket, const std::string& prefix = {},
                                       const std::string& delimiter = {}, const std::string& token = {},
                                       int maxKeys = 1000);
    Result<std::vector<ObjectInfo>> listAllObjects(const std::string& bucket, const std::string& prefix = {});
    /// Stream the object list page by page instead of accumulating every entry.
    Result<void> forEachObject(const std::string& bucket, const std::string& prefix,
                               const std::function<Result<void>(const ObjectInfo&)>& callback);
    /// Stream every version/delete marker of a bucket, including non-current ones.
    Result<void> forEachObjectVersion(
        const std::string& bucket,
        const std::function<Result<void>(const ObjectVersion&)>& callback);
    Result<ObjectMeta> headObject(const std::string& bucket, const std::string& key);
    Result<std::string> getObjectRange(const std::string& bucket, const std::string& key, uint64_t offset,
                                       uint64_t length);
    Result<BucketTagging> getObjectTagging(const std::string& bucket, const std::string& key);
    Result<void> putObjectTagging(const std::string& bucket, const std::string& key,
                                  const BucketTagging& tagging);
    Result<void> deleteObjectTagging(const std::string& bucket, const std::string& key);
    /// Write an object together with the HTTP metadata, user metadata and tags
    /// carried by `meta`. `meta.size/etag/...` are ignored here.
    Result<void> putObject(const std::string& bucket, const std::string& key, const std::string& body,
                           const ObjectMeta& meta = {});
    /// Streaming PUT (uses UNSIGNED-PAYLOAD) — for objects up to partSize.
    Result<void> putObjectFromFile(const std::string& bucket, const std::string& key, const std::string& path,
                                   const ObjectMeta& meta = {});
    /// Multipart upload from a local file; returns ETag of the completed upload.
    Result<std::string> uploadMultipartFromFile(const std::string& bucket, const std::string& key,
                                                const std::string& path, uint64_t partSize,
                                                const ObjectMeta& meta = {});
    Result<void> deleteObject(const std::string& bucket, const std::string& key,
                              const std::string& versionId = {});
    Result<std::string> copyObject(const std::string& fromBucket, const std::string& fromKey,
                                   const std::string& toBucket, const std::string& toKey);

    /// Escape hatch for vendor modules (admin APIs share the transport).
    http::Response raw(const http::Request& request);

private:
    struct Attempt {
        http::Response response;
        http::Request request;
    };
    Attempt prepare(const std::string& method, const std::string& resourcePath,
                    const std::map<std::string, std::string>& query, const std::string& body,
                    const std::string& bodyFile, bool unsignedPayload, const std::string& range,
                    const std::vector<std::pair<std::string, std::string>>& extraHeaders);
    Attempt execute(Attempt attempt);
    std::string objectPath(const std::string& bucket, const std::string& key) const;
    std::string bucketPath(const std::string& bucket) const;
    void throttle();

    ClientOptions options_;
    sigv4::Credentials creds_;
    std::vector<std::string> endpoints_;
    std::atomic<size_t> endpointIndex_{0};
    std::mutex throttleMutex_;
    double minIntervalMs_ = 0;
    std::chrono::steady_clock::time_point lastRequest_{};
};

/// Build a Client from a config block (`cluster <name> { ... }`) + credentials.
class Registry; // fwd

} // namespace s3mm::s3
