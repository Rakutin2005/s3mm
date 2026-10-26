#pragma once
// s3mmc — cluster client for s3mmd.
//
// One s3mmc instance fronts one s3mmd node. It owns:
//   * a UNIX listener socket per remote destination id (remote[id]): the core
//     connects to /var/run/s3mmc/<node>/remote-<id>.sock as if it were an S3
//     endpoint; everything arriving there is destined for cluster `id`;
//   * a control UNIX socket (s3mmc.sock) for status/inspection;
//   * mTLS peer channels to other s3mmc instances — the only network-visible
//     interface. All peers are equal; the sole asymmetry is which side dials
//     whom (`connect` vs `listen` on each peer block). A channel is logically
//     bidirectional: replies, inventory pulls and data transfers travel back
//     over whichever session exists between the two nodes.
//
// Routing model (network routing, not RPC): every node answers only for
// itself. If the task's destination cluster is directly reachable here, the
// node serves it (fetches the payload from its local core when needed and
// PUTs it into the real S3 endpoint). Otherwise it consults its merged route
// table (built from peer inventories: a peer advertising cluster X can serve
// X) and forwards the task to that hop with trail-based loop protection. A
// deny anywhere along the path travels back hop-by-hop and surfaces at the
// origin as "remote denied: <reason>".
#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"
#include "s3mm/transport.hpp"
#include "s3mm/wire.hpp"

namespace s3mm::s3mmc {

/// One configured peer of this node. `id` doubles as the remote S3 cluster
/// identifier namespace owned by that node's zone: local -> remote[id].
struct PeerConfig {
    std::string id;
    std::string address;        // host:port
    bool dial = true;           // true: we connect to it; false: it connects to us
    int connectTimeoutSec = 10;
};

/// TLS material shared by all peer sessions of this node.
struct TlsConfig {
    std::string certFile;
    std::string keyFile;
    std::string caFile;         // empty => verification off (tests only)
};

/// Live state of one peer link.
struct PeerLinkInfo {
    std::string id;
    std::string address;
    std::string direction;      // "out" (we dialed) | "in" (peer dialed)
    bool connected = false;
    int64_t sinceSec = 0;
    int64_t lastSeenSec = 0;
    int64_t reconnects = 0;
    int64_t lastErrorSec = 0;
    std::string lastError;
    int64_t inventoryRevision = 0;
    int64_t inventoryAtSec = 0;
};

/// Result of serving one object request received on a remote[id] socket.
struct ServeOutcome {
    bool ok = false;
    std::string error;          // "remote denied: ..." | transport error
    uint64_t bytesShipped = 0;
};

/// The cluster client. Owns listeners, peer sessions, the merged inventory
/// view and the route table. Thread-safe: every public method may be called
/// from any thread.
class ClusterClient {
public:
    struct Options {
        std::string nodeId;                 // stable identity (cert CN by default)
        std::string runDir = "/var/run/s3mmc";
        std::string spoolDir;               // default: runDir/spool
        std::string coreSocket;             // s3mmd control socket (default /run/s3mm.sock)
        std::string listenAddress = "0.0.0.0";
        int listenPort = 9443;              // peer mTLS port; 0 => no listener
        std::string pollModel = "both";     // push | pull | both (both == no-op alias)
        int64_t pollIntervalSec = 60;       // inventory exchange cadence
        int64_t pollTimeoutSec = 15;
        int64_t coreTimeoutSec = 300;       // GET-wait budget towards local core
        uint64_t spoolThresholdBytes = 1ull << 20;
        /// Managers of this node ("*" | list of peer ids/CNs | empty = none).
        /// A manager receives the FULL unfiltered inventory, may patch our
        /// config and pull credentials over the cluster channel. Identity is
        /// the CN of the peer's mTLS certificate.
        std::vector<std::string> managedNodes;
        /// on: bind a remote[id] UNIX socket only when some local replication
        /// rule actually references that foreign cluster (lazy creation on
        /// demand); off: bind sockets for every cluster known from the merged
        /// inventory.
        bool requiredOnly = true;

        // ---- per-peer visibility ACL ------------------------------------------
        // Non-managers see only what the matching ACL entry grants them;
        // managers ignore ACLs entirely and always receive everything.
        struct PeerAcl {
            std::string pattern;   // peer id / CN, glob ("*", "zone-*")
            int priority = 0;      // explicit numeric `order`, then specificity
            // Inventory element names this peer may see. Glob patterns with
            // leading '!' as exclusions (same semantics as policy filters):
            // "*" = all; {"clusters","!endpoints"} = clusters minus endpoints.
            // Recognised names: clusters, endpoints, zones, aliases, vendor,
            // replications, local_clusters, credentials.
            std::vector<std::string> elements;
        };
        struct ExposeRule {
            std::string spec;          // raw value: "*" | "none" | "a,!b,c"
            std::string appliesTo;     // "unmanaged" | "all" | "<peer-id>" | glob
            int order = 0;             // explicit precedence (lower wins)
            int line = 0;              // config line — stable tie-breaker
        };
        /// Expose directives in file order (used when no ACL entries exist).
        std::vector<ExposeRule> exposeRules;
        /// Compiled per-peer ACL, derived from exposeRules by configure().
        /// Empty => legacy behaviour: opts_.exposeInventory filter for all
        /// non-managers (back-compat with single global `expose`).
        std::vector<PeerAcl> peerAcls;
    };

    explicit ClusterClient(Options opts, TlsConfig tls);
    ~ClusterClient();

    // ---- configuration -----------------------------------------------------
    Result<void> setPeers(std::vector<PeerConfig> peers);
    Result<void> addPeer(PeerConfig p);
    Result<void> removePeer(const std::string& idOrAddress);
    std::vector<PeerConfig> peers() const;

    Options options() const;
    TlsConfig tlsConfig() const;
    /// Reconfigure before start(). Changing nodeId/runDir after start is an
    /// error; poll model / intervals / TLS material may be updated live.
    Result<void> configure(const Options& opts, const TlsConfig& tls);

    // ---- cluster management (managed-nodes model) ---------------------------
    /// True when `peerId` (CN of its mTLS certificate == peer id) is allowed
    /// to manage this node: patch our config, pull credentials. "*" in the
    /// managed list matches every connected peer; a peer is always its own
    /// manager. There are no roles — this is a per-node delegation matrix.
    bool isManagerOf(const std::string& peerId) const;
    /// Path of the live configuration file once known (set by main()/tests).
    void setConfigPath(const std::string& path);
    std::string configPath() const;
    /// Directory holding sealed credential PEM files (default /etc/s3mm/secrets)
    /// and the master-key file used to re-seal them for a manager.
    void setSecretsDir(const std::string& dir, const std::string& masterKeyFile = {});

    // ---- inventory visibility & socket provisioning -----------------------
    /// Normalise an expose value ("*" | "none" | names with optional "!"
    /// exclusions). Exposed for config parsing and CLI validation.
    static Result<std::vector<std::string>> parseExposeList(const std::string& spec);
    /// Compile opts_.exposeRules into the ordered per-peer ACL table
    /// (opts_.peerAcls). Rules without `to` default to "unmanaged"; a bare
    /// `expose <list>;` (no block form) is kept as the legacy global filter.
    static Result<void> compilePeerAcls(Options& opts);
    /// The ACL entry governing `peerId`, or nullptr when no ACL table exists.
    /// Managers never consult ACLs — see filteredInventoryFor().
    const Options::PeerAcl* aclForLocked(const std::string& peerId) const;
    /// Our local snapshot as it would be disclosed to `peerId`: managers get
    /// everything; non-managers get the view filtered by their ACL entry.
    peer::Inventory filteredInventoryFor(const std::string& peerId) const;
    /// Effective visibility summary for one peer (manager flag, matched ACL,
    /// element list, disclosure counts). Served on the control socket.
    Value describeVisibility(const std::string& peerId) const;
    /// Bind (if not bound yet) the remote[id] UNIX listener. Called on demand
    /// when requiredOnly=true and a task/socket request needs that cluster.
    Result<void> ensureRemoteSocket(const std::string& clusterId);
    /// Foreign clusters referenced by our own replication rules (destination
    /// or source that we do not own locally) — the "required" socket set.
    std::vector<std::string> requiredClustersLocked() const;
    /// Current s3mmc.conf text read from disk (empty + false on failure).
    bool currentConfigText(std::string* text, std::string* error) const;
    /// Validate `text` and persist it over the live config file, then apply
    /// it to this running instance (hot reload of peers/TLS/scalars).
    /// Refused unless invoked via a channel authenticated as our manager
    /// (`viaManager` carries the requester's peer id; empty = local CLI).
    Result<void> applyConfigTextFrom(const std::string& text, const std::string& filename,
                                     const std::string& viaManager);

    // ---- manager-side operations (run on THIS node acting as a manager) -----
    /// Pull the live s3mmc.conf text of a managed peer over the cluster channel.
    Result<std::string> pullPeerConfig(const std::string& peerId);
    /// Push a new config text to a managed peer (it validates, persists and
    /// hot-reloads it; refuses us unless we are in its `managed` list).
    Result<void> pushPeerConfig(const std::string& peerId, const std::string& text,
                                const std::string& filename);
    /// Pull sealed credentials from a peer and re-import them into our own core
    /// registry via the control socket (the core owns sealing under our key).
    Result<Value> pullPeerCredentials(const std::string& peerId, const std::string& clusterFilter);

    /// Local inventory reported by s3mmd over the control connection (or set
    /// directly in tests). Bumps our revision and pushes when poll model says so.
    void setLocalInventory(const peer::Inventory& inv);
    peer::Inventory localInventory() const;

    // ---- lifecycle -----------------------------------------------------------
    /// Bind the peer mTLS listener + the per-remote-id UNIX sockets + the
    /// control socket, then spawn accept/dial/poll threads.
    Result<void> start();
    void stop();
    bool running() const { return running_.load(); }

    // ---- core-facing service --------------------------------------------------
    /// Serve one HTTP-over-UNIX request arriving on remote[clusterId]'s socket.
    /// Reads the request line + headers (and PUT body) from `fd`, routes/serves
    /// the task and writes the response back. Returns the response head to
    /// write (empty when the handler already streamed everything).
    std::string handleCoreRequestOnSocket(int fd, const std::string& clusterId);

    /// Blocking: route a replication task towards `clusterId` — serve it via
    /// the local core when the cluster is reachable here, otherwise forward to
    /// the next hop and wait for the verdict travelling back along the path.
    ServeOutcome routeTaskToCluster(const std::string& clusterId, const peer::TaskSpec& spec,
                                    const std::string& spoolPath);

    // ---- frame handling (peer threads call in) --------------------------------
    /// Process one inbound frame on the session with `peerId`. Returns frames
    /// to write back on the same channel (usually 0..1).
    std::vector<Value> handlePeerFrame(const std::string& peerId, const Value& frame,
                                       std::shared_ptr<Channel> ch);

    // ---- outbound requests ------------------------------------------------------
    /// Ask a connected peer to deliver `object` into our local core. Blocking
    /// (runs on the caller thread; the reply arrives on the peer session).
    ServeOutcome fetchViaPeer(const std::string& peerId, const std::string& bucket,
                              const std::string& key, uint64_t sizeHint);

    // ---- views -------------------------------------------------------------------
    peer::Inventory mergedInventory() const;
    std::string routeTo(const std::string& clusterId) const; // "" => unreachable
    bool ownsCluster(const std::string& id) const;
    std::vector<std::pair<std::string, std::string>> routes() const;
    std::vector<PeerLinkInfo> links() const;
    Value statusValue() const;
    size_t pendingCount() const;

private:
    struct PeerRuntime {
        PeerConfig cfg;
        bool connected = false;
        std::string direction;
        std::shared_ptr<Channel> channel;   // current session (may be null)
        std::string peerCN;                 // authenticated CN of the mTLS session
        int64_t sinceSec = 0;
        int64_t lastSeenSec = 0;
        int64_t reconnects = 0;
        int64_t lastErrorSec = 0;
        std::string lastError;
        peer::Inventory inventory;
        bool hasInventory = false;
        std::mutex sendMutex;               // serialises writes on channel
    };

    struct InflightServe {                  // GET waiters keyed by bucket/key
        std::mutex mu;
        std::condition_variable cv;
        bool done = false;
        ServeOutcome outcome;
    };

    /// Pending manager request awaiting a reply frame (config_get, cred_request).
    struct PendingReq {
        std::mutex mu;
        std::condition_variable cv;
        bool done = false;
        Value reply;                        // response frame payload ("result" member)
    };

    // -- internals
    void acceptLoop();                       // peer mTLS listener
    void dialLoop();                         // maintain outbound sessions
    void pollLoop();                         // inventory exchange cadence
    void unixAcceptLoop(int fd, std::string clusterId); // remote[id] sockets
    void controlLoop();                                 // s3mmc.sock (status CLI)
    void sessionLoop(std::shared_ptr<Channel> ch, std::string peerIdHint, bool dialed);
    bool ensureSession(const std::string& peerId);      // blocking dial + hello
    void dropSession(const std::string& peerId, const std::string& reason);
    void dropSessionByChannel(const std::shared_ptr<Channel>& ch, const std::string& reason);

    std::string sendOnPeer(const std::string& peerId, const Value& frame);
    Value buildHelloFrame(const std::string& forPeer = {});
    Value buildInventoryFrame(const std::string& forPeer = {});
    void applyInventoryFrom(const std::string& peerId, const peer::Inventory& inv);
    void mergeViewsLocked();
    void rebuildRoutesLocked();

    // frame handlers
    Value onHello(const std::string& peerId, const Value& frame, std::shared_ptr<Channel> ch);
    void onInventory(const std::string& peerId, const Value& frame);
    Value onTask(const std::string& peerId, const Value& frame);
    void onTaskResult(const std::string& peerId, const Value& frame);
    Value onObjectReq(const std::string& peerId, const Value& frame);
    void onObjectData(const std::string& peerId, const Value& frame, std::shared_ptr<Channel> ch);
    Value onConfigGet(const std::string& peerId, const Value& frame);
    Value onConfigSet(const std::string& peerId, const Value& frame);
    Value onCredRequest(const std::string& peerId, const Value& frame);
    void onManagerReply(const std::string& peerId, const Value& frame);
    static Value makeManagerReply(const std::string& type, const Value& frame,
                                  bool ok, const std::string& status,
                                  const std::string& reason, const Value* result);

    // manager-side outbound requests (blocking; reply arrives on the session)
    Result<std::string> requestConfigFromPeer(const std::string& peerId);
    Result<Value> requestCredsFromPeer(const std::string& peerId, const std::string& clusterFilter);

    bool ownsClusterLocked(const std::string& id) const;

    // core helpers
    bool coreCall(const Value& request, int extraFd, Value* reply);
    bool coreGetToFile(const std::string& bucket, const std::string& key, const std::string& path,
                       std::string* error);
    bool corePutFromFile(const std::string& bucket, const std::string& key, const std::string& path,
                         const Value& meta, uint64_t size, std::string* error);
    bool coreDelete(const std::string& bucket, const std::string& key, std::string* error);

    Options opts_;
    TlsConfig tls_;
    std::string spoolDir_;
    std::string controlPath_;
    std::string coreSocketPath_;      // s3mmd control socket used by coreCall
    std::string configPath_;          // live s3mmc.conf (for manager-side patches)
    std::string secretsDir_ = "/etc/s3mm/secrets";  // sealed credential material
    std::string masterKeyFile_;       // file holding the sealing passphrase

    mutable std::recursive_mutex mutex_;
    std::map<std::string, PeerRuntime> peers_;          // by id
    std::map<std::string, std::string> byAddress_;      // "host:port" -> id
    peer::Inventory localInv_;
    int64_t localRev_ = 1;
    peer::Inventory merged_;
    std::map<std::string, std::string> routes_;         // cluster id -> next hop peer id
    std::set<std::string> processedTasks_;              // loop/duplicate guard (task ids)
    std::map<std::string, std::string> taskNextHop_;    // taskId -> peer we forwarded to
    std::map<std::string, std::string> taskSender_;     // taskId -> peer that sent it to us
    std::map<std::string, std::shared_ptr<InflightServe>> inflight_; // "bkt\nkey" -> waiter

    // verdict rendez-vous: routeTaskToCluster waits here for onTaskResult
    std::mutex waitMutex_;
    std::condition_variable waitCv_;
    std::map<std::string, peer::TaskResult> verdicts_;   // taskId -> result

    /// Pending manager requests awaiting a reply frame (id -> waiter).
    std::mutex reqMutex_;
    std::condition_variable reqCv_;
    std::map<std::string, std::shared_ptr<PendingReq>> pendingReqs_;

    // sockets
    int peerListenFd_ = -1;
    int controlFd_ = -1;
    std::map<std::string, int> remoteFds_;              // cluster id -> unix listener fd
    std::vector<int> threadSockets_;                    // self-pipes to wake loops

    std::vector<std::thread> threads_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> taskSeq_{0};
};

} // namespace s3mm::s3mmc
