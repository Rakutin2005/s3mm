#pragma once
// Wire protocol of the s3mmc cluster channel.
//
// Transport: newline-delimited JSON frames. Between s3mmd and its local
// s3mmc the frames travel over a UNIX socket; between two s3mmc instances —
// over a single mTLS TCP connection per peer pair. The channel is logically
// bidirectional but physically initiated by exactly one side (the dialer);
// all replies, data pulls and forwarded requests travel back over the same
// established session or over the listener-side session of the other node.
//
// Frame kinds (`type` field):
//   hello        — session handshake: node id + inventory snapshot
//   inventory    — periodic / on-change snapshot push (poll model "push")
//   inventory_req— poll request for a snapshot (poll model "pull")
//   task         — routed replication task (object | delete)
//   task_result  — verdict ok|denied|failed, returned hop-by-hop to origin
//   object_req   — "send me this range" (data reversal over inbound channel)
//   object_data  — response to object_req / task payload spool reference
//   config_get   — manager asks a peer for its current s3mmc config text
//   config_set   — manager pushes a new config text to a managed peer
//   cred_request — pull S3 credentials from a peer (managers always; other
//                  peers only when the target sets expose_credentials on)
//   cred_response — sealed credential blocks, re-sealed for the requester
//   ping/pong    — liveness
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::peer {

constexpr int kProtocolVersion = 1;
constexpr size_t kMaxFrameBytes = 64ull * 1024 * 1024 + 8ull * 1024 * 1024; // payload cap + headroom

// ------------------------------------------------------------------ framing --

/// Serialise a frame as one line of JSON (newline appended).
std::string encodeFrame(const Value& frame);
/// Parse one frame line. Returns null value + error text on failure.
Result<Value> decodeFrame(const std::string& line);

// ------------------------------------------------------------------- types ---

/// One entry of a node's S3 inventory ("cluster" == local or remote id;
/// a remote id is simultaneously a peer name and a destination cluster name).
struct InventoryCluster {
    std::string id;            // canonical cluster name
    std::string alias;
    std::string vendor;
    std::string zone;
    std::vector<std::string> endpoints;
};

struct RemoteReplication {
    std::string name;
    std::string source;
    std::string destination;   // may be a remote id served through the cluster
    bool paused = false;
};

/// Full state snapshot of one node, exchanged on connect and periodically.
struct Inventory {
    std::string nodeId;        // this node's stable identifier
    int64_t revision = 0;      // bumped on every local change
    int64_t generatedAtSec = 0;
    std::vector<InventoryCluster> clusters;
    std::vector<RemoteReplication> replications;
    /// cluster ids reachable directly (locally managed) from the reporting node
    std::vector<std::string> localClusters;

    Value toJson() const;
    static Result<Inventory> fromJson(const Value& v);
};

/// One routed replication task. `origin` is the node that created the task,
/// `trail` lists the nodes it travelled through (loop protection).
struct TaskSpec {
    std::string id;            // globally unique task id
    std::string origin;        // node id of the creator
    std::vector<std::string> trail;
    std::string replication;   // replication name as known to the origin
    std::string kind;          // object | delete
    std::string bucket;
    std::string key;
    uint64_t size = 0;
    std::string etag;
    std::string versionId;
    std::string contentType;
    std::string lastModified;  // ISO-8601
    std::string reason;        // policy note carried along the route
    std::map<std::string, std::string> meta;

    Value toJson() const;
    static Result<TaskSpec> fromJson(const Value& v);
};

/// Verdict returned by the node responsible for a task's destination.
struct TaskResult {
    std::string taskId;
    std::string node;          // node that produced the verdict
    std::string status;        // ok | denied | failed
    std::string reason;
    uint64_t bytesShipped = 0;

    Value toJson() const;
    static Result<TaskResult> fromJson(const Value& v);
};

} // namespace s3mm::peer
