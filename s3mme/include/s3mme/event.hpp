#pragma once
#include <cstdint>
#include <string>

#include "s3mm/common/value.hpp"

namespace s3mme {

/// One routing/replication decision as observed by the core engine and
/// translated into an event by s3mme. Mirrors s3mm::repl::RouteInfo, but is
/// deliberately a standalone structure so the event client never links against
/// the replication engine — it only talks to the daemon control socket.
struct Event {
    std::string id;          // unique event id (node-id + sequence)
    int64_t atSec = 0;       // unix seconds of the decision
    std::string node;        // local node id (from s3mme.conf)
    std::string replication; // replication name
    std::string kind;        // bucket | object | delete | account
    std::string sourceCluster;
    std::string sourceBucket;
    std::string destCluster;
    std::string destBucket;
    std::string bucket;      // effective bucket of the record
    std::string key;         // object key / access key for accounts
    std::string outcome;     // success | denied | warning
    std::string target;      // policy action target (redirect/quarantine basket)
    std::string rule;        // matched rule name/order
    std::string reason;      // policy decision text
    uint64_t size = 0;       // object size in bytes when known

    Value toJson() const;
};

} // namespace s3mme
