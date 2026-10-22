#pragma once
#include <map>
#include <string>
#include <vector>

#include "s3mm/common/time.hpp"
#include "s3mm/policy/engine.hpp"
#include "s3mm/s3/client.hpp"

namespace s3mm::repl {

/// One classified item on its way to a target group.
struct Candidate {
    enum class Kind { Bucket, Object, Account, Delete };

    Kind kind = Kind::Object;
    std::string replication;
    std::string bucket;
    std::string key;      // object key (Kind::Object / Delete)
    std::string account;  // access key id (Kind::Account)
    uint64_t size = 0;
    std::string etag;
    tm::TimePoint lastModified;
    std::string contentType;
    std::map<std::string, std::string> meta;

    // classification result
    std::string outcome;  // success | denied | warning
    std::string target;   // resolved target group name
    std::string rule;     // matched rule name/number, "default" when applicable
    std::string reason;
    std::string versionId; // source version (empty for unversioned buckets)
    std::string metadataHash; // canonical hash of HTTP/user metadata
    std::string tagsHash;     // canonical hash of object tags
    int attempts = 0;         // delivery attempts (bounded by settings.retries)

    static Candidate fromDecision(const policy::Decision& decision, const s3::ObjectInfo& info,
                                  const std::string& replication, const std::string& bucket);
};

/// A basket: all items of one outcome for one task.
struct Basket {
    std::string outcome;    // denied | success | warning
    std::string targetName; // resolved target group
    std::vector<Candidate> items;

    size_t count() const { return items.size(); }
    uint64_t bytes() const;
};

/// A task = (replication x bucket x scan cycle): the "общий ящик" of the
/// pipeline. Items arrive classified by policies and are shipped by outcome.
class Task {
public:
    Task() = default;
    Task(std::string replication, std::string source, std::string destination, std::string bucket, int64_t cycle);

    const std::string& id() const { return id_; }
    const std::string& replication() const { return replication_; }
    const std::string& source() const { return source_; }
    const std::string& destination() const { return destination_; }
    const std::string& bucket() const { return bucket_; }
    int64_t cycle() const { return cycle_; }
    tm::TimePoint started() const { return started_; }

    void add(Candidate candidate);
    Basket& basket(const std::string& outcome);
    const std::map<std::string, Basket>& baskets() const { return baskets_; }

    size_t total() const;
    uint64_t bytes() const;
    /// Items grouped by target name (a target may receive several outcomes).
    std::map<std::string, std::vector<Candidate>> byTarget() const;

private:
    std::string id_;
    std::string replication_, source_, destination_, bucket_;
    int64_t cycle_ = 0;
    tm::TimePoint started_;
    std::map<std::string, Basket> baskets_;
};

} // namespace s3mm::repl
