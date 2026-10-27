#pragma once
#include <map>
#include <memory>
#include <string>

#include "s3mm/common/result.hpp"
#include "s3mm/common/time.hpp"
#include "s3mm/module/loader.hpp"
#include "s3mm/registry/registry.hpp"
#include "s3mm/s3/client.hpp"

namespace s3mm::repl {

/// Everything a target group needs to route one classified item.
struct ShipRecord {
    std::string replication;
    std::string outcome;   // success | denied | warning
    std::string kind;      // object | bucket | account | delete
    std::string rule;      // matched rule (name or number)
    std::string reason;    // human readable reason / log message
    std::string sourceCluster;
    std::string destinationCluster;
    std::string bucket;
    std::string key;
    std::string account;
    uint64_t size = 0;
    std::string etag;
    std::string versionId;
    tm::TimePoint lastModified;
    std::string contentType;
    std::map<std::string, std::string> meta;

    std::string toJson() const;
};

/// A named destination for classified items ("корзина" -> куда уходит).
class ITargetGroup {
public:
    virtual ~ITargetGroup() = default;
    virtual const std::string& name() const = 0;
    virtual const std::string& kind() const = 0;
    /// Deliver the record. `dataPath` is a local file with the payload when one
    /// was materialised (object shipments); empty for metadata-only records.
    virtual Result<void> ship(const ShipRecord& record, const std::string& dataPath) = 0;
};

using TargetGroupPtr = std::shared_ptr<ITargetGroup>;

/// Internal drop target: records nothing outside of logs/stats.
class NullTarget final : public ITargetGroup {
public:
    explicit NullTarget(std::string name = "null") : name_(std::move(name)) {}
    const std::string& name() const override { return name_; }
    const std::string& kind() const override { return kind_; }
    Result<void> ship(const ShipRecord& record, const std::string& dataPath) override;

private:
    std::string name_;
    std::string kind_ = "null";
};

/// Appends JSON records to a file (append-only audit / manual processing).
class FileTarget final : public ITargetGroup {
public:
    FileTarget(std::string name, std::string path, std::string pathTemplate);
    const std::string& name() const override { return name_; }
    const std::string& kind() const override { return kind_; }
    Result<void> ship(const ShipRecord& record, const std::string& dataPath) override;

private:
    std::string name_;
    std::string kind_ = "file";
    std::string path_;
    std::string pathTemplate_;
    std::string renderPath(const ShipRecord& record) const;
};

/// POSTs the record as JSON to an HTTP(S) endpoint (webhook).
class HttpTarget final : public ITargetGroup {
public:
    HttpTarget(std::string name, std::string url, bool insecure);
    const std::string& name() const override { return name_; }
    const std::string& kind() const override { return kind_; }
    Result<void> ship(const ShipRecord& record, const std::string& dataPath) override;

private:
    std::string name_;
    std::string kind_ = "http";
    std::string url_;
    bool insecure_ = false;
};

/// Copies the object itself to s3://<cluster>/<bucket>/<prefix>/...
/// Used for custom replication target batches (see `redirect <batch>`).
class S3Target final : public ITargetGroup {
public:
    S3Target(std::string name, std::string uri, std::string pathTemplate);
    const std::string& name() const override { return name_; }
    const std::string& kind() const override { return kind_; }

    const std::string& targetCluster() const { return cluster_; }
    const std::string& targetBucket() const { return bucket_; }
    const std::string& targetPrefix() const { return prefix_; }
    const std::string& pathTemplate() const { return pathTemplate_; }

    /// S3 targets need live clients; the engine injects them before shipping.
    /// Large objects are staged in `stagingDir` (falls back to /tmp when empty).
    void bind(std::shared_ptr<s3::Client> destination, s3::Client* source, std::string stagingDir = {});

    Result<void> ship(const ShipRecord& record, const std::string& dataPath) override;

private:
    std::string name_;
    std::string kind_ = "s3";
    std::string cluster_, bucket_, prefix_;
    std::string pathTemplate_;
    std::shared_ptr<s3::Client> destination_;
    s3::Client* source_ = nullptr;
    std::string stagingDir_;
    std::string renderKey(const ShipRecord& record) const;
};

/// Builds target groups from registry definitions and implicit routes.
class TargetFactory {
public:
    TargetFactory(const registry::Registry& registry, module::Loader* loader);

    /// Explicitly configured target by name, or nullptr.
    TargetGroupPtr find(const std::string& name) const;
    /// Create (and cache) a target by name; reports unknown names.
    Result<TargetGroupPtr> create(const std::string& name);
    /// Implicit success route: copy to the replication destination cluster.
    TargetGroupPtr successRoute(const registry::Replication& replication) const;
    /// The three outcome routes of a bundle, resolved to live target groups.
    struct Routes {
        TargetGroupPtr success, denied, warning;
    };
    Result<Routes> routesFor(const registry::Replication& replication) const;

private:
    const registry::Registry& registry_;
    module::Loader* loader_;
    mutable std::map<std::string, TargetGroupPtr> cache_;
};

} // namespace s3mm::repl
