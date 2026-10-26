// s3mmc — cluster client for s3mmd. Implementation of the ClusterClient:
// per-remote-id UNIX listeners (core-facing pseudo-S3 endpoints), mTLS peer
// sessions (the only network interface), inventory exchange on a configured
// polling model, and hop-by-hop task routing with verdicts returned along
// the path they came in.
#include "s3mm/clusterclient.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <thread>

#include "s3mm/common/crypto.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/time.hpp"

#include "configfile.hpp"

namespace s3mm::s3mmc {

namespace {

int64_t nowSec() { return (int64_t)tm::toSeconds(tm::now()); }

std::string newTaskId(const std::string& nodeId, uint64_t& seq) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "%s-%llx-%llu", nodeId.c_str(), (unsigned long long)nowSec(),
                  (unsigned long long)seq.fetch_add(1));
    return buf;
}

std::string urlDecode(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int h = hex(s[i + 1]), l = hex(s[i + 2]);
            if (h >= 0 && l >= 0) {
                out.push_back((char)((h << 4) | l));
                i += 2;
                continue;
            }
        }
        out.push_back(s[i]);
    }
    return out;
}

bool readLineFd(int fd, std::string& line, int timeoutMs) {
    char c;
    line.clear();
    for (;;) {
        pollfd p{fd, POLLIN, 0};
        int pr = ::poll(&p, 1, timeoutMs);
        if (pr <= 0) return false;
        ssize_t n = ::recv(fd, &c, 1, 0);
        if (n <= 0) return false;
        if (c == '\n') return true;
        if (c != '\r') line.push_back(c);
        if (line.size() > 16384) return false;
    }
}

bool writeAllFd(int fd, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

bool fileExists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

/// Stream exactly `len` bytes from socket into file path. Returns bytes written.
uint64_t streamBodyToFile(int fd, const std::string& path, uint64_t len, int timeoutMs) {
    int out = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) return (uint64_t)-1;
    uint64_t got = 0;
    char buf[65536];
    while (got < len) {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, timeoutMs) <= 0) break;
        size_t want = (size_t)std::min<uint64_t>(sizeof(buf), len - got);
        ssize_t n = ::recv(fd, buf, want, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        size_t off = 0;
        while (off < (size_t)n) {
            ssize_t w = ::write(out, buf + off, (size_t)n - off);
            if (w <= 0) { ::close(out); return got; }
            off += (size_t)w;
        }
        got += (size_t)n;
    }
    ::close(out);
    return got;
}

int bindTcpListener(const std::string& address, int port, std::string* error) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { *error = "socket failed"; return -1; }
    int opt = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (::inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
        *error = "invalid listen address '" + address + "'";
        ::close(fd);
        return -1;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        *error = std::string("bind ") + address + ":" + std::to_string(port) + " failed: " + strerror(errno);
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 32) < 0) {
        *error = "listen failed";
        ::close(fd);
        return -1;
    }
    return fd;
}

int connectTcp(const std::string& host, int port, int timeoutSec) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) return -1;
    int fd = -1;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) { ::close(fd); fd = -1; continue; }
        if (rc < 0) {
            pollfd p{fd, POLLOUT, 0};
            if (::poll(&p, 1, timeoutSec * 1000) <= 0) { ::close(fd); fd = -1; continue; }
            int err = 0;
            socklen_t elen = sizeof(err);
            ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (err != 0) { ::close(fd); fd = -1; continue; }
        }
        ::fcntl(fd, F_SETFL, flags); // back to blocking
        break;
    }
    freeaddrinfo(res);
    return fd;
}

int bindUnixListener(const std::string& path) {
    fs::mkdirp(fs::dirname(path));
    ::unlink(path.c_str());
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_un un{};
    un.sun_family = AF_UNIX;
    std::strncpy(un.sun_path, path.c_str(), sizeof(un.sun_path) - 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) { ::close(fd); return -1; }
    if (::listen(fd, 64) < 0) { ::close(fd); ::unlink(path.c_str()); return -1; }
    return fd;
}

} // namespace

// ---------------------------------------------------------------- construction --

ClusterClient::ClusterClient(Options opts, TlsConfig tls) : opts_(std::move(opts)), tls_(std::move(tls)) {
    if (opts_.nodeId.empty()) opts_.nodeId = "node-" + std::to_string(::getpid());
    if (opts_.spoolDir.empty()) opts_.spoolDir = opts_.runDir + "/spool";
    spoolDir_ = opts_.spoolDir;
    controlPath_ = opts_.runDir + "/" + opts_.nodeId + "/s3mmc.sock";
    coreSocketPath_ = opts_.coreSocket.empty() ? std::string("/run/s3mm/s3mm.sock") : opts_.coreSocket;
}

ClusterClient::~ClusterClient() { stop(); }

// ------------------------------------------------------------------ configure --

Result<void> ClusterClient::setPeers(std::vector<PeerConfig> peers) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    peers_.clear();
    byAddress_.clear();
    for (auto& p : peers) {
        if (p.id.empty()) return Result<void>::failure("peer requires an id");
        if (p.address.empty()) return Result<void>::failure("peer '" + p.id + "' requires an address");
        PeerRuntime rt;
        rt.cfg = p;
        peers_[p.id] = rt;
        byAddress_[p.address] = p.id;
    }
    rebuildRoutesLocked();
    return Result<void>::success();
}

Result<void> ClusterClient::addPeer(PeerConfig p) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (p.id.empty() || p.address.empty()) return Result<void>::failure("peer add: id and address required");
    PeerRuntime rt;
    rt.cfg = std::move(p);
    peers_[rt.cfg.id] = std::move(rt);
    byAddress_[peers_[rt.cfg.id].cfg.address] = peers_[rt.cfg.id].cfg.id;
    rebuildRoutesLocked();
    return Result<void>::success();
}

Result<void> ClusterClient::removePeer(const std::string& idOrAddress) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    auto it = peers_.find(idOrAddress);
    if (it == peers_.end()) {
        auto ad = byAddress_.find(idOrAddress);
        if (ad != byAddress_.end()) it = peers_.find(ad->second);
    }
    if (it == peers_.end()) return Result<void>::failure("unknown peer '" + idOrAddress + "'");
    byAddress_.erase(it->second.cfg.address);
    peers_.erase(it);
    rebuildRoutesLocked();
    return Result<void>::success();
}

std::vector<PeerConfig> ClusterClient::peers() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    std::vector<PeerConfig> out;
    for (const auto& [id, rt] : peers_) out.push_back(rt.cfg);
    return out;
}

ClusterClient::Options ClusterClient::options() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return opts_;
}

TlsConfig ClusterClient::tlsConfig() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return tls_;
}

Result<void> ClusterClient::configure(const Options& opts, const TlsConfig& tls) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (running_.load() && (opts.nodeId != opts_.nodeId || opts.runDir != opts_.runDir))
        return Result<void>::failure("node/run_dir cannot change while s3mmc is running");
    opts_ = opts;
    if (opts_.nodeId.empty()) opts_.nodeId = "node-" + std::to_string(::getpid());
    if (opts_.spoolDir.empty()) opts_.spoolDir = opts_.runDir + "/spool";
    spoolDir_ = opts_.spoolDir;
    controlPath_ = opts_.runDir + "/" + opts_.nodeId + "/s3mmc.sock";
    coreSocketPath_ = opts_.coreSocket.empty() ? std::string("/run/s3mm/s3mm.sock") : opts_.coreSocket;
    tls_ = tls;
    if (!tls_.certFile.empty() && !fs::exists(tls_.certFile))
        return Result<void>::failure("tls cert file not found: " + tls_.certFile);
    if (!tls_.keyFile.empty() && !fs::exists(tls_.keyFile))
        return Result<void>::failure("tls key file not found: " + tls_.keyFile);
    if (!tls_.caFile.empty() && !fs::exists(tls_.caFile))
        return Result<void>::failure("tls ca file not found: " + tls_.caFile);
    return Result<void>::success();
}

void ClusterClient::setLocalInventory(const peer::Inventory& inv) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    localInv_ = inv;
    localInv_.nodeId = opts_.nodeId;
    localInv_.revision = ++localRev_;
    localInv_.generatedAtSec = nowSec();
    mergeViewsLocked();
    // push our fresh snapshot to every listener-side session (they dialed us;
    // we may initiate transfers towards them) when the model allows pushes
    if (opts_.pollModel == "push" || opts_.pollModel == "both") {
        Value frame = buildInventoryFrame();
        for (auto& [id, rt] : peers_) {
            if (rt.connected && rt.direction == "in" && rt.channel) {
                std::lock_guard<std::mutex> slk(rt.sendMutex);
                rt.channel->send(frame);
            }
        }
    }
}

peer::Inventory ClusterClient::localInventory() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return localInv_;
}

// ------------------------------------------- managed-nodes model (local side) --

bool ClusterClient::isManagerOf(const std::string& peerId) const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (peerId.empty()) return false;
    if (peerId == opts_.nodeId) return true;  // a node is always its own manager
    for (const auto& m : opts_.managedNodes) {
        if (m == "*") return true;            // wildcard: every connected peer
        if (m == peerId) return true;         // CN == cluster id == peer id
    }
    return false;
}

void ClusterClient::setConfigPath(const std::string& path) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    configPath_ = path;
}

std::string ClusterClient::configPath() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return configPath_;
}

void ClusterClient::setSecretsDir(const std::string& dir, const std::string& masterKeyFile) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    secretsDir_ = dir;
    masterKeyFile_ = masterKeyFile;
}

bool ClusterClient::currentConfigText(std::string* text, std::string* error) const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (configPath_.empty()) {
        *error = "no configuration file is associated with this instance";
        return false;
    }
    auto content = fs::readFile(configPath_);
    if (!content) {
        *error = "cannot read '" + configPath_ + "'";
        return false;
    }
    *text = *content;
    return true;
}

Result<void> ClusterClient::applyConfigTextFrom(const std::string& text, const std::string& filename,
                                                const std::string& viaManager) {
    std::string targetPath;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        if (!viaManager.empty() && !isManagerOf(viaManager))
            return Result<void>::failure("remote denied: '" + viaManager +
                                         "' is not a manager of " + opts_.nodeId);
        targetPath = configPath_.empty() ? filename : configPath_;
    }
    if (targetPath.empty())
        return Result<void>::failure("no configuration file path known; refusing to apply");

    // Validate the candidate text against a throwaway client first so a bad
    // patch never overwrites the live file.
    {
        ClusterClient probe(options(), tlsConfig());
        auto vr = applyConfigText(probe, text, targetPath);
        if (!vr) return Result<void>::failure("config rejected: " + vr.error());
    }

    // Persist over the live file (atomic), then hot-reload ourselves.
    std::string dir = fs::dirname(targetPath);
    if (!dir.empty()) fs::mkdirp(dir);
    if (!fs::writeFileAtomic(targetPath, text, /*fsyncDir=*/true))
        return Result<void>::failure("cannot write '" + targetPath + "'");
    setConfigPath(targetPath);
    auto ar = applyConfigText(*this, text, targetPath);
    if (!ar) return Result<void>::failure("applied but reload failed: " + ar.error());
    LOG_INFO("s3mmc: configuration updated",
             viaManager.empty() ? "" : (" via manager '" + viaManager + "'"));
    return Result<void>::success();
}

// ---------------------------------------------- managed-nodes model (manager) --

Result<std::string> ClusterClient::pullPeerConfig(const std::string& peerId) {
    return requestConfigFromPeer(peerId);
}

Result<void> ClusterClient::pushPeerConfig(const std::string& peerId, const std::string& text,
                                           const std::string& filename) {
    if (!ensureSession(peerId))
        return Result<void>::failure("peer '" + peerId + "' not reachable");
    std::string id = "cfgset-" + std::to_string(++taskSeq_);
    auto waiter = std::make_shared<PendingReq>();
    {
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_[id] = waiter;
    }
    Value req = Value::object();
    req.set("type", Value::str("config_set"));
    req.set("id", Value::str(id));
    req.set("from", Value::str(opts_.nodeId));
    req.set("filename", Value::str(filename));
    req.set("result", Value::str(text));
    std::string serr = sendOnPeer(peerId, req);
    if (!serr.empty()) {
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_.erase(id);
        return Result<void>::failure(serr);
    }
    std::unique_lock<std::mutex> wl(waiter->mu);
    bool got = waiter->cv.wait_for(wl, std::chrono::seconds(opts_.pollTimeoutSec),
                                   [&] { return waiter->done; });
    if (!got) {
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_.erase(id);
        return Result<void>::failure("config_set timed out on '" + peerId + "'");
    }
    const Value& reply = waiter->reply;
    if (reply.getString("status") != "ok")
        return Result<void>::failure(reply.getString("reason", "config_set refused"));
    return Result<void>::success();
}

Result<Value> ClusterClient::pullPeerCredentials(const std::string& peerId,
                                                 const std::string& clusterFilter) {
    auto credsR = requestCredsFromPeer(peerId, clusterFilter);
    if (!credsR) return credsR;
    // Hand the sealed blocks to our own core for import under our master key.
    // The core owns sealing/unsealing; s3mmc only transports them.
    Value req = Value::object();
    req.set("cmd", Value::str("cluster-import-credentials"));
    req.set("source_peer", Value::str(peerId));
    req.set("credentials", *credsR.value().find("credentials"));
    Value reply;
    if (!coreCall(req, -1, &reply))
        return Result<Value>::failure("core rejected credential import");
    if (const Value* ok = reply.find("ok"); ok && ok->asBool(false))
        return Result<Value>::success(credsR.value());
    return Result<Value>::failure(reply.getString("error", "core credential import failed"));
}

// --------------------------------------------------------------------- start --

Result<void> ClusterClient::start() {
    if (running_.exchange(true)) return Result<void>::success();
    fs::mkdirp(spoolDir_);

    std::string error;
    if (opts_.listenPort > 0) {
        peerListenFd_ = bindTcpListener(opts_.listenAddress, opts_.listenPort, &error);
        if (peerListenFd_ < 0) {
            running_ = false;
            return Result<void>::failure("peer listener: " + error);
        }
        threads_.emplace_back([this] { acceptLoop(); });
    }

    // remote[id] UNIX listeners from the local inventory's remote clusters:
    // any destination cluster that is NOT owned locally gets its own socket.
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        for (const auto& [clusterId, hop] : routes_) {
            if (ownsClusterLocked(clusterId)) continue;
            std::string path = opts_.runDir + "/" + opts_.nodeId + "/remote-" + clusterId + ".sock";
            int fd = bindUnixListener(path);
            if (fd < 0) { LOG_WARN("s3mmc: cannot bind ", path); continue; }
            remoteFds_[clusterId] = fd;
            threads_.emplace_back([this, fd, clusterId] { unixAcceptLoop(fd, clusterId); });
        }
    }

    controlFd_ = bindUnixListener(controlPath_);
    if (controlFd_ >= 0)
        threads_.emplace_back([this] { controlLoop(); });
    threads_.emplace_back([this] { dialLoop(); });
    threads_.emplace_back([this] { pollLoop(); });
    LOG_INFO("s3mmc node '", opts_.nodeId, "' started (peer port ", opts_.listenPort, ", run dir ",
             opts_.runDir, ")");
    return Result<void>::success();
}

void ClusterClient::stop() {
    if (!running_.exchange(false)) return;
    if (peerListenFd_ >= 0) { ::close(peerListenFd_); peerListenFd_ = -1; }
    if (controlFd_ >= 0) { ::close(controlFd_); controlFd_ = -1; ::unlink(controlPath_.c_str()); }
    for (auto& [id, fd] : remoteFds_) {
        ::close(fd);
        ::unlink((opts_.runDir + "/" + opts_.nodeId + "/remote-" + id + ".sock").c_str());
    }
    remoteFds_.clear();
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        for (auto& [id, rt] : peers_) rt.channel.reset();
    }
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    threads_.clear();
}

// ------------------------------------------------------------- core sockets ---

namespace {

// Core protocol helpers (see class comment): one request line + headers,
// optional body of Content-Length bytes. We answer with a status line +
// X-S3MM-* headers.

struct ParsedRequest {
    std::string method;
    std::string target;   // "/bucket/key..."
    std::map<std::string, std::string> headers; // lower-cased names
    bool ok = false;
};

ParsedRequest parseHttpRequest(int fd, int timeoutMs) {
    ParsedRequest r;
    std::string line;
    if (!readLineFd(fd, line, timeoutMs)) return r;
    auto sp1 = line.find(' ');
    if (sp1 == std::string::npos) return r;
    auto sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return r;
    r.method = line.substr(0, sp1);
    r.target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    for (;;) {
        if (!readLineFd(fd, line, timeoutMs)) return r;
        if (line.empty()) break;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = str::toLower(str::trim(line.substr(0, colon)));
        std::string val = str::trim(line.substr(colon + 1));
        r.headers[name] = val;
    }
    r.ok = true;
    return r;
}

std::string httpReply(int code, const std::string& status, const std::string& error, uint64_t bytes) {
    std::ostringstream os;
    os << "HTTP/1.1 " << code << " " << status << "\r\n";
    os << "X-S3MM-Status: " << status << "\r\n";
    if (!error.empty()) os << "X-S3MM-Error: " << error << "\r\n";
    os << "Content-Length: 0\r\nConnection: close\r\n\r\n";
    (void)bytes;
    return os.str();
}

} // namespace

void ClusterClient::unixAcceptLoop(int fd, std::string clusterId) {
    while (running_.load()) {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, 500) <= 0) continue;
        int client = ::accept(fd, nullptr, nullptr);
        if (client < 0) continue;
        std::thread([this, client, clusterId] {
            std::string resp = handleCoreRequestOnSocket(client, clusterId);
            if (!resp.empty()) writeAllFd(client, resp);
            ::close(client);
        }).detach();
    }
}

std::string ClusterClient::handleCoreRequestOnSocket(int fd, const std::string& clusterId) {
    auto req = parseHttpRequest(fd, (int)opts_.coreTimeoutSec * 1000);
    if (!req.ok) return httpReply(400, "failed", "malformed request", 0);
    // split /bucket/key
    std::string path = urlDecode(req.target);
    if (!path.empty() && path[0] == '/') path.erase(0, 1);
    auto q = path.find('?');
    if (q != std::string::npos) path = path.substr(0, q);
    auto slash = path.find('/');
    std::string bucket = slash == std::string::npos ? path : path.substr(0, slash);
    std::string key = slash == std::string::npos ? "" : path.substr(slash + 1);
    if (bucket.empty() || key.empty()) return httpReply(400, "failed", "bad resource path", 0);

    uint64_t contentLength = 0;
    if (auto it = req.headers.find("content-length"); it != req.headers.end())
        contentLength = (uint64_t)std::strtoull(it->second.c_str(), nullptr, 10);

    if (req.method == "PUT") {
        // spool the body, then route the task
        std::string spool = spoolDir_ + "/put-" + std::to_string((uint64_t)::time(nullptr)) + "-" +
                            std::to_string(taskSeq_.fetch_add(1)) + ".bin";
        uint64_t got = streamBodyToFile(fd, spool, contentLength, (int)opts_.coreTimeoutSec * 1000);
        if (got != contentLength) {
            fs::removeFile(spool);
            return httpReply(400, "failed", "short body read", 0);
        }
        peer::TaskSpec spec;
        spec.id = newTaskId(opts_.nodeId, taskSeq_);
        spec.origin = opts_.nodeId;
        spec.kind = "object";
        spec.bucket = bucket;
        spec.key = key;
        spec.size = contentLength;
        if (auto it = req.headers.find("x-s3mm-replication"); it != req.headers.end())
            spec.replication = it->second;
        for (const auto& [name, val] : req.headers)
            if (str::startsWith(name, "x-amz-meta-")) spec.meta[name] = val;
        ServeOutcome out = routeTaskToCluster(clusterId, spec, spool);
        fs::removeFile(spool);
        if (out.ok) return httpReply(200, "ok", "", out.bytesShipped);
        if (out.error.rfind("remote denied", 0) == 0) return httpReply(403, "denied", out.error, 0);
        return httpReply(502, "failed", out.error, 0);
    }
    if (req.method == "DELETE") {
        peer::TaskSpec spec;
        spec.id = newTaskId(opts_.nodeId, taskSeq_);
        spec.origin = opts_.nodeId;
        spec.kind = "delete";
        spec.bucket = bucket;
        spec.key = key;
        ServeOutcome out = routeTaskToCluster(clusterId, spec, "");
        if (out.ok) return httpReply(204, "ok", "", 0);
        if (out.error.rfind("remote denied", 0) == 0) return httpReply(403, "denied", out.error, 0);
        return httpReply(502, "failed", out.error, 0);
    }
    if (req.method == "GET" || req.method == "HEAD") {
        // serve from local storage through the core
        std::string error;
        if (req.method == "HEAD") {
            return httpReply(200, "ok", "", 0); // existence check only
        }
        std::string spool = spoolDir_ + "/get-" + std::to_string((uint64_t)::time(nullptr)) + "-" +
                            std::to_string(taskSeq_.fetch_add(1)) + ".bin";
        if (!coreGetToFile(bucket, key, spool, &error)) {
            fs::removeFile(spool);
            return httpReply(404, "failed", error, 0);
        }
        auto sz = fs::fileSize(spool);
        std::ostringstream head;
        head << "HTTP/1.1 200 OK\r\nX-S3MM-Status: ok\r\nContent-Length: " << (sz ? *sz : 0) << "\r\n\r\n";
        writeAllFd(fd, head.str());
        auto body = fs::readFile(spool);
        if (body) writeAllFd(fd, *body);
        fs::removeFile(spool);
        return ""; // already streamed
    }
    return httpReply(405, "failed", "method not supported", 0);
}

// ------------------------------------------------------------ task routing ---

ServeOutcome ClusterClient::routeTaskToCluster(const std::string& clusterId, const peer::TaskSpec& specIn,
                                               const std::string& spoolPath) {
    ServeOutcome out;
    peer::TaskSpec spec = specIn;
    spec.trail.push_back(opts_.nodeId);

    if (ownsCluster(clusterId)) {
        // destination is directly reachable here: apply it via the local core
        std::string error;
        bool okv = false;
        if (spec.kind == "delete") {
            okv = coreDelete(spec.bucket, spec.key, &error);
        } else {
            Value meta = Value::object();
            meta.set("content_type", Value::str(spec.contentType));
            meta.set("last_modified", Value::str(spec.lastModified));
            Value m = Value::object();
            for (const auto& [k, v] : spec.meta) m.set(k, Value::str(v));
            meta.set("user_meta", m);
            okv = corePutFromFile(spec.bucket, spec.key, spoolPath, meta, spec.size, &error);
        }
        if (okv) {
            out.ok = true;
            out.bytesShipped = spec.size;
        } else {
            out.error = error.empty() ? "local apply failed" : error;
        }
        return out;
    }

    std::string hop;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = routes_.find(clusterId);
        if (it != routes_.end()) hop = it->second;
    }
    if (hop.empty()) {
        out.error = "remote denied: no route to " + clusterId;
        return out;
    }
    if (std::find(spec.trail.begin(), spec.trail.end(), hop) != spec.trail.end()) {
        out.error = "remote denied: routing loop via " + hop;
        return out;
    }

    // ensure the channel to the hop exists
    if (!ensureSession(hop)) {
        out.error = "remote denied: peer '" + hop + "' unreachable";
        return out;
    }

    // send the task frame; with payload when we have it inline/spooled
    Value frame = Value::object();
    frame.set("type", Value::str("task"));
    frame.set("id", Value::str(spec.id));
    frame.set("from", Value::str(opts_.nodeId));
    frame.set("dest_cluster", Value::str(clusterId));
    Value taskJson = spec.toJson();
    frame.set("task", taskJson);

    if (!spoolPath.empty()) {
        auto sz = fs::fileSize(spoolPath);
        if (sz && *sz <= opts_.spoolThresholdBytes) {
            auto body = fs::readFile(spoolPath);
            if (body) {
                Value data = Value::object();
                data.set("b64", Value::str(crypto::base64Encode(*body)));
                data.set("bytes", Value::number((int64_t)*sz));
                frame.set("data", data);
            }
        } else {
            // large object: ask the destination to pull it from us later
            frame.set("payload", Value::str("pull"));
        }
    }

    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        taskNextHop_[spec.id] = hop;
    }

    std::string serr = sendOnPeer(hop, frame);
    if (!serr.empty()) {
        out.error = "remote denied: forward to '" + hop + "' failed: " + serr;
        return out;
    }

    // await the verdict travelling back along the path
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(opts_.coreTimeoutSec);
    for (;;) {
        peer::TaskResult res;
        bool have = false;
        {
            std::unique_lock<std::mutex> lk(waitMutex_);
            if (!waitCv_.wait_until(lk, deadline,
                                    [&] { return verdicts_.count(spec.id) > 0 || !running_.load(); })) {
                // timeout: treat as failure but keep routing state clean
                std::lock_guard<std::recursive_mutex> lk2(mutex_);
                taskNextHop_.erase(spec.id);
                out.error = "remote denied: timeout awaiting verdict from '" + hop + "'";
                return out;
            }
            auto it = verdicts_.find(spec.id);
            if (it != verdicts_.end()) {
                res = it->second;
                verdicts_.erase(it);
                have = true;
            }
        }
        if (!have || !running_.load()) { out.error = "remote denied: session closed"; return out; }
        if (res.status == "ok") { out.ok = true; out.bytesShipped = res.bytesShipped; return out; }
        out.error = "remote denied: " + (res.reason.empty() ? res.status : res.reason);
        return out;
    }
}

// --------------------------------------------------------------- peer frames ---

Value ClusterClient::buildHelloFrame() {
    Value f = Value::object();
    f.set("type", Value::str("hello"));
    f.set("from", Value::str(opts_.nodeId));
    f.set("version", Value::number(kProtocolVersion));
    f.set("inventory", localInv_.toJson());
    return f;
}

Value ClusterClient::buildInventoryFrame() {
    Value f = Value::object();
    f.set("type", Value::str("inventory"));
    f.set("from", Value::str(opts_.nodeId));
    f.set("inventory", localInv_.toJson());
    return f;
}

std::string ClusterClient::sendOnPeer(const std::string& peerId, const Value& frame) {
    std::shared_ptr<Channel> ch;
    std::mutex* sm = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        if (it == peers_.end() || !it->second.connected || !it->second.channel)
            return "peer '" + peerId + "' not connected";
        ch = it->second.channel;
        sm = &it->second.sendMutex;
    }
    std::lock_guard<std::mutex> slk(*sm);
    auto r = ch->send(frame);
    return r ? std::string() : r.error();
}

std::vector<Value> ClusterClient::handlePeerFrame(const std::string& peerIdHint, const Value& frame,
                                                  std::shared_ptr<Channel> ch) {
    std::string type = frame.getString("type");
    std::string from = frame.getString("from");
    std::string peerId = peerIdHint.empty() ? from : peerIdHint;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        if (it != peers_.end()) it->second.lastSeenSec = nowSec();
    }
    if (type == "hello") return {onHello(peerId, frame, ch)};
    if (type == "inventory") { onInventory(peerId, frame); return {}; }
    if (type == "inventory_req") return {buildInventoryFrame()};
    if (type == "task") return {onTask(peerId, frame)};
    if (type == "task_result") { onTaskResult(peerId, frame); return {}; }
    if (type == "object_req") return {onObjectReq(peerId, frame)};
    if (type == "object_data") { onObjectData(peerId, frame, ch); return {}; }
    // managed-nodes model frames: config/credential management. Replies to
    // our own outbound requests are matched by "ref" and never guarded here.
    if (type == "config_get") return {onConfigGet(peerId, frame)};
    if (type == "config_set") return {onConfigSet(peerId, frame)};
    if (type == "cred_request") return {onCredRequest(peerId, frame)};
    if (type == "config_response" || type == "config_ack" || type == "cred_response") {
        onManagerReply(peerId, frame);
        return {};
    }
    if (type == "ping") {
        Value pong = Value::object();
        pong.set("type", Value::str("pong"));
        pong.set("from", Value::str(opts_.nodeId));
        pong.set("ref", Value::str(frame.getString("id")));
        return {pong};
    }
    return {};
}

Value ClusterClient::onHello(const std::string& peerId, const Value& frame, std::shared_ptr<Channel> ch) {
    std::string theirNode = frame.getString("from");
    bool dialectOk = frame.find("version") && frame.find("version")->asInt(0) == kProtocolVersion;
    if (!dialectOk) {
        Value err = Value::object();
        err.set("type", Value::str("error"));
        err.set("reason", Value::str("protocol version mismatch"));
        return err;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        if (it != peers_.end()) {
            it->second.connected = true;
            it->second.channel = ch;
            if (it->second.sinceSec == 0) it->second.sinceSec = nowSec();
            if (ch) it->second.direction = "in";
        }
    }
    if (frame.find("inventory")) {
        auto inv = peer::Inventory::fromJson(*frame.find("inventory"));
        if (inv) applyInventoryFrom(peerId, inv.value());
    }
    return buildHelloFrame();
}

void ClusterClient::onInventory(const std::string& peerId, const Value& frame) {
    if (!frame.find("inventory")) return;
    auto inv = peer::Inventory::fromJson(*frame.find("inventory"));
    if (inv) applyInventoryFrom(peerId, inv.value());
}

void ClusterClient::applyInventoryFrom(const std::string& peerId, const peer::Inventory& inv) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    auto it = peers_.find(peerId);
    if (it == peers_.end()) {
        // unknown peer reported itself — adopt it under its node id
        PeerConfig cfg;
        cfg.id = peerId;
        cfg.address = "discovered";
        cfg.dial = false;
        PeerRuntime rt;
        rt.cfg = cfg;
        peers_[peerId] = rt;
        it = peers_.find(peerId);
    }
    it->second.inventory = inv;
    it->second.hasInventory = true;
    it->second.lastSeenSec = nowSec();
    mergeViewsLocked();
}

Value ClusterClient::onTask(const std::string& peerId, const Value& frame) {
    Value resultJson = Value::object();
    peer::TaskResult res;
    res.node = opts_.nodeId;
    std::string destCluster = frame.getString("dest_cluster");
    auto specR = peer::TaskSpec::fromJson(frame.find("task") ? *frame.find("task") : frame);
    if (!specR) {
        res.status = "denied";
        res.reason = "malformed task: " + specR.error();
        if (frame.find("id")) res.taskId = frame.getString("id");
        Value f = Value::object();
        f.set("type", Value::str("task_result"));
        f.set("from", Value::str(opts_.nodeId));
        f.set("result", res.toJson());
        return f;
    }
    peer::TaskSpec spec = specR.value();
    res.taskId = spec.id;

    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        if (processedTasks_.count(spec.id)) {
            res.status = "ok"; // duplicate delivery — idempotent ack
            res.reason = "duplicate";
            Value f = Value::object();
            f.set("type", Value::str("task_result"));
            f.set("from", Value::str(opts_.nodeId));
            f.set("result", res.toJson());
            return f;
        }
        processedTasks_.insert(spec.id);
        taskSender_[spec.id] = peerId; // verdict must travel back this way
    }

    // loop guard: refuse to serve tasks that already visited us
    if (std::find(spec.trail.begin(), spec.trail.end(), opts_.nodeId) != spec.trail.end()) {
        res.status = "denied";
        res.reason = "routing loop at " + opts_.nodeId;
        Value f = Value::object();
        f.set("type", Value::str("task_result"));
        f.set("from", Value::str(opts_.nodeId));
        f.set("result", res.toJson());
        return f;
    }

    // materialise payload
    std::string spool = spoolDir_ + "/task-" + spec.id + ".bin";
    bool haveData = false;
    if (const Value* d = frame.find("data"); d && d->isObject()) {
        if (const Value* b64 = d->find("b64"); b64 && b64->isString()) {
            auto body = crypto::base64Decode(b64->asString());
            if (body) {
                FILE* fp = std::fopen(spool.c_str(), "wb");
                if (fp) {
                    std::fwrite(body->data(), 1, body->size(), fp);
                    std::fclose(fp);
                    haveData = true;
                }
            }
        }
    }
    if (spec.kind == "object" && !haveData) {
        // big payload: pull it from the previous hop over that channel
        Value req = Value::object();
        req.set("type", Value::str("object_req"));
        req.set("id", Value::str("pull-" + spec.id));
        req.set("from", Value::str(opts_.nodeId));
        req.set("bucket", Value::str(spec.bucket));
        req.set("key", Value::str(spec.key));
        req.set("task", Value::str(spec.id));
        std::string serr = sendOnPeer(peerId, req);
        if (!serr.empty()) {
            res.status = "failed";
            res.reason = "payload pull failed: " + serr;
        } else {
            // wait for object_data to land (bounded)
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(opts_.coreTimeoutSec);
            std::unique_lock<std::mutex> lk(waitMutex_);
            bool arrived = waitCv_.wait_until(lk, deadline, [&] { return fileExists(spool); });
            if (arrived) haveData = true;
            else {
                res.status = "failed";
                res.reason = "payload pull timed out";
            }
        }
    }

    if (res.status.empty()) {
        // Now act as the destination node: serve locally or forward onward.
        ServeOutcome out = routeTaskToCluster(destCluster, spec, spool);
        res.status = out.ok ? "ok" : (out.error.rfind("remote denied", 0) == 0 ? "denied" : "failed");
        res.reason = out.ok ? "" : out.error;
        res.bytesShipped = out.bytesShipped;
    }

    Value f = Value::object();
    f.set("type", Value::str("task_result"));
    f.set("from", Value::str(opts_.nodeId));
    f.set("result", res.toJson());
    fs::removeFile(spool);
    return f;
}

void ClusterClient::onTaskResult(const std::string& peerId, const Value& frame) {
    if (!frame.find("result")) return;
    auto resR = peer::TaskResult::fromJson(*frame.find("result"));
    if (!resR) return;
    peer::TaskResult res = resR.value();
    std::string nextHop;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = taskNextHop_.find(res.taskId);
        if (it != taskNextHop_.end()) {
            nextHop = it->second;
            taskNextHop_.erase(it);
        }
    }
    if (!nextHop.empty()) {
        // we forwarded this task earlier — relay the verdict back down the path
        Value f = Value::object();
        f.set("type", Value::str("task_result"));
        f.set("from", Value::str(opts_.nodeId));
        f.set("result", res.toJson());
        sendOnPeer(nextHop, f);
        return;
    }
    // origin-side: hand the verdict to the waiting routeTaskToCluster
    {
        std::lock_guard<std::mutex> lk(waitMutex_);
        verdicts_[res.taskId] = res;
    }
    waitCv_.notify_all();
}

Value ClusterClient::onObjectReq(const std::string& peerId, const Value& frame) {
    (void)peerId;
    std::string bucket = frame.getString("bucket");
    std::string key = frame.getString("key");
    std::string spool = spoolDir_ + "/pull-" + frame.getString("id") + ".bin";
    std::string error;
    Value f = Value::object();
    f.set("type", Value::str("object_data"));
    f.set("from", Value::str(opts_.nodeId));
    f.set("ref", Value::str(frame.getString("id")));
    if (coreGetToFile(bucket, key, spool, &error)) {
        auto sz = fs::fileSize(spool);
        auto body = fs::readFile(spool);
        Value data = Value::object();
        if (body && sz && *sz <= opts_.spoolThresholdBytes) {
            data.set("b64", Value::str(crypto::base64Encode(*body)));
            data.set("bytes", Value::number((int64_t)*sz));
        } else {
            f.set("status", Value::str("failed"));
            f.set("error", Value::str("object too large for inline transfer"));
            fs::removeFile(spool);
            return f;
        }
        f.set("data", data);
        f.set("status", Value::str("ok"));
        fs::removeFile(spool);
    } else {
        f.set("status", Value::str("failed"));
        f.set("error", Value::str(error));
    }
    return f;
}

void ClusterClient::onObjectData(const std::string& peerId, const Value& frame, std::shared_ptr<Channel> ch) {
    (void)peerId; (void)ch;
    std::string ref = frame.getString("ref");
    // ref = "pull-<taskId>"
    std::string taskId = ref.rfind("pull-", 0) == 0 ? ref.substr(5) : ref;
    std::string spool = spoolDir_ + "/task-" + taskId + ".bin";
    if (frame.getString("status") == "ok") {
        if (const Value* d = frame.find("data"); d && d->isObject()) {
            if (const Value* b64 = d->find("b64"); b64 && b64->isString()) {
                auto body = crypto::base64Decode(b64->asString());
                if (body) {
                    FILE* fp = std::fopen(spool.c_str(), "wb");
                    if (fp) {
                        std::fwrite(body->data(), 1, body->size(), fp);
                        std::fclose(fp);
                    }
                }
            }
        }
    }
    waitCv_.notify_all();
}

// ---------------------------------------------------- manager / config frames ---
//
// These implement the managed-nodes model: a peer whose authenticated mTLS CN
// appears in our `managed` list (or when the list is "*") may read/patch our
// live s3mmc.conf and pull S3 credentials over the cluster channel. Identity
// is the certificate CN — there are no roles, only this per-node delegation
// matrix. A non-manager request is answered with status "denied".

Value ClusterClient::makeManagerReply(const std::string& type, const Value& frame,
                                      bool ok, const std::string& status,
                                      const std::string& reason, const Value* result) {
    Value f = Value::object();
    f.set("type", Value::str(type));
    f.set("from", Value::str(opts_.nodeId));
    f.set("ref", Value::str(frame.getString("id")));
    f.set("ok", Value::boolean(ok));
    f.set("status", Value::str(status));
    if (!reason.empty()) f.set("reason", Value::str(reason));
    if (result) f.set("result", *result);
    return f;
}

Value ClusterClient::onConfigGet(const std::string& peerId, const Value& frame) {
    if (!isManagerOf(peerId))
        return makeManagerReply("config_response", frame, false, "denied",
                                "remote denied: not a manager of " + opts_.nodeId, nullptr);
    std::string text, err;
    if (!currentConfigText(&text, &err))
        return makeManagerReply("config_response", frame, false, "failed", err, nullptr);
    Value res = Value::object();
    res.set("filename", Value::str(configPath_));
    res.set("text", Value::str(text));
    return makeManagerReply("config_response", frame, true, "ok", "", &res);
}

Value ClusterClient::onConfigSet(const std::string& peerId, const Value& frame) {
    if (!isManagerOf(peerId))
        return makeManagerReply("config_ack", frame, false, "denied",
                                "remote denied: not a manager of " + opts_.nodeId, nullptr);
    const Value* res = frame.find("result");
    if (!res || !res->isString())
        return makeManagerReply("config_ack", frame, false, "denied", "malformed config_set", nullptr);
    auto r = applyConfigTextFrom(res->asString(), frame.getString("filename"), peerId);
    if (!r)
        return makeManagerReply("config_ack", frame, false, "failed", r.error(), nullptr);
    return makeManagerReply("config_ack", frame, true, "ok", "", nullptr);
}

Value ClusterClient::onCredRequest(const std::string& peerId, const Value& frame) {
    bool allowed = isManagerOf(peerId) || opts_.exposeCredentials;
    if (!allowed)
        return makeManagerReply("cred_response", frame, false, "denied",
                                "remote denied: credential export not permitted for '" +
                                    peerId + "'", nullptr);
    // Collect local sealed secret material. The core owns the authoritative
    // credential set; we hand over the raw sealed PEM blocks from secretsDir so
    // the manager can re-seal them under its own passphrase. Nothing plaintext
    // ever leaves this node.
    std::string filter = frame.getString("cluster");
    Value arr = Value::array();
    if (fs::exists(secretsDir_)) {
        for (const auto& name : fs::listDir(secretsDir_)) {
            if (!filter.empty() && name != filter) continue;
            auto content = fs::readFile(fs::joinPath(secretsDir_, name));
            if (!content) continue;
            Value item = Value::object();
            item.set("name", Value::str(name));
            item.set("sealed", Value::str(*content));
            arr.push(item);
        }
    }
    Value res = Value::object();
    res.set("credentials", arr);
    return makeManagerReply("cred_response", frame, true, "ok", "", &res);
}

void ClusterClient::onManagerReply(const std::string& peerId, const Value& frame) {
    (void)peerId;
    std::string id = frame.getString("ref");
    std::shared_ptr<PendingReq> waiter;
    {
        std::lock_guard<std::mutex> lk(reqMutex_);
        auto it = pendingReqs_.find(id);
        if (it == pendingReqs_.end()) return;
        waiter = it->second;
        pendingReqs_.erase(it);
    }
    {
        std::lock_guard<std::mutex> lk(waiter->mu);
        waiter->reply = frame;
        waiter->done = true;
    }
    waiter->cv.notify_all();
}

Result<std::string> ClusterClient::requestConfigFromPeer(const std::string& peerId) {
    if (!ensureSession(peerId))
        return Result<std::string>::failure("peer '" + peerId + "' not reachable");
    std::string id = "cfgget-" + std::to_string(++taskSeq_);
    auto waiter = std::make_shared<PendingReq>();
    {
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_[id] = waiter;
    }
    Value req = Value::object();
    req.set("type", Value::str("config_get"));
    req.set("id", Value::str(id));
    req.set("from", Value::str(opts_.nodeId));
    std::string serr = sendOnPeer(peerId, req);
    if (!serr.empty()) {
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_.erase(id);
        return Result<std::string>::failure(serr);
    }
    std::unique_lock<std::mutex> wl(waiter->mu);
    bool got = waiter->cv.wait_for(wl, std::chrono::seconds(opts_.pollTimeoutSec),
                                   [&] { return waiter->done; });
    if (!got) {
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_.erase(id);
        return Result<std::string>::failure("config_get timed out on '" + peerId + "'");
    }
    const Value& reply = waiter->reply;
    std::string status = reply.getString("status");
    if (status != "ok") {
        std::string reason = reply.getString("reason", "no reason given");
        return Result<std::string>::failure(reason.empty() ? "config_get failed" : reason);
    }
    const Value* res = reply.find("result");
    if (!res || !res->isString())
        return Result<std::string>::failure("config_get returned no text");
    return Result<std::string>::success(res->asString());
}

Result<Value> ClusterClient::requestCredsFromPeer(const std::string& peerId,
                                                  const std::string& clusterFilter) {
    if (!ensureSession(peerId))
        return Result<Value>::failure("peer '" + peerId + "' not reachable");
    std::string id = "creq-" + std::to_string(++taskSeq_);
    auto waiter = std::make_shared<PendingReq>();
    {
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_[id] = waiter;
    }
    Value req = Value::object();
    req.set("type", Value::str("cred_request"));
    req.set("id", Value::str(id));
    req.set("from", Value::str(opts_.nodeId));
    if (!clusterFilter.empty()) req.set("cluster", Value::str(clusterFilter));
    std::string serr = sendOnPeer(peerId, req);
    if (!serr.empty()) {
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_.erase(id);
        return Result<Value>::failure(serr);
    }
    std::unique_lock<std::mutex> wl(waiter->mu);
    bool got = waiter->cv.wait_for(wl, std::chrono::seconds(opts_.pollTimeoutSec),
                                   [&] { return waiter->done; });
    if (!got) {
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_.erase(id);
        return Result<Value>::failure("cred_request timed out on '" + peerId + "'");
    }
    const Value& reply = waiter->reply;
    if (reply.getString("status") != "ok") {
        std::string reason = reply.getString("reason", "credential request refused");
        return Result<Value>::failure(reason);
    }
    const Value* res = reply.find("result");
    if (!res) return Result<Value>::failure("cred_response without payload");
    return Result<Value>::success(*res);
}

// ------------------------------------------------------------------- loops ---

void ClusterClient::controlLoop() {
    while (running_.load()) {
        pollfd p{controlFd_, POLLIN, 0};
        if (::poll(&p, 1, 500) <= 0) continue;
        int client = ::accept(controlFd_, nullptr, nullptr);
        if (client < 0) continue;
        std::thread([this, client] {
            std::string line;
            if (!readLineFd(client, line, 5000)) { ::close(client); return; }
            std::string err;
            auto req = Value::parseJson(line, &err);
            Value reply = Value::object();
            if (!err.empty() || !req.isObject()) {
                reply.set("ok", Value::boolean(false));
                reply.set("error", Value::str("malformed control request"));
            } else if (req.getString("cmd") == "status") {
                reply = statusValue();
                reply.set("ok", Value::boolean(true));
            } else if (req.getString("cmd") == "routes") {
                reply = Value::object();
                reply.set("ok", Value::boolean(true));
                Value arr = Value::array();
                for (const auto& [c, hop] : routes()) {
                    Value rv = Value::object();
                    rv.set("cluster", Value::str(c));
                    rv.set("via", Value::str(hop));
                    arr.push(rv);
                }
                reply.set("routes", arr);
            } else {
                reply.set("ok", Value::boolean(false));
                reply.set("error", Value::str("unknown command: " + req.getString("cmd")));
            }
            writeAllFd(client, reply.toJson() + "\n");
            ::close(client);
        }).detach();
    }
}

void ClusterClient::acceptLoop() {
    while (running_.load()) {
        pollfd p{peerListenFd_, POLLIN, 0};
        if (::poll(&p, 1, 500) <= 0) continue;
        int client = ::accept(peerListenFd_, nullptr, nullptr);
        if (client < 0) continue;
        auto chR = makeTlsChannel(client, /*clientRole=*/false, tls_.certFile, tls_.keyFile, tls_.caFile);
        if (!chR) {
            LOG_WARN("s3mmc: inbound TLS handshake failed: ", chR.error());
            ::close(client);
            continue;
        }
        std::thread([this, ch = chR.value()] { sessionLoop(ch, "", false); }).detach();
    }
}

void ClusterClient::sessionLoop(std::shared_ptr<Channel> ch, std::string peerIdHint, bool dialed) {
    std::string peerId = peerIdHint;
    // outbound side sends hello first; inbound side answers hellos
    if (dialed) {
        Value hello = buildHelloFrame();
        auto sr = ch->send(hello);
        if (!sr) { dropSessionByChannel(ch, "hello send failed"); return; }
    }
    for (;;) {
        if (!running_.load()) break;
        auto fr = ch->recv();
        if (!fr) {
            dropSessionByChannel(ch, fr.error());
            break;
        }
        const Value& frame = fr.value();
        std::string type = frame.getString("type");
        std::string from = frame.getString("from");
        if (peerId.empty() && !from.empty()) {
            peerId = from;
            // adopt/confirm the runtime entry for this session
            std::lock_guard<std::recursive_mutex> lk(mutex_);
            auto it = peers_.find(peerId);
            if (it == peers_.end()) {
                PeerConfig cfg;
                cfg.id = peerId;
                cfg.address = "inbound";
                cfg.dial = false;
                PeerRuntime rt;
                rt.cfg = cfg;
                peers_[peerId] = rt;
                it = peers_.find(peerId);
            }
            it->second.connected = true;
            it->second.channel = ch;
            it->second.direction = dialed ? "out" : "in";
            it->second.sinceSec = nowSec();
        } else if (!peerId.empty()) {
            std::lock_guard<std::recursive_mutex> lk(mutex_);
            auto it = peers_.find(peerId);
            if (it != peers_.end()) { it->second.connected = true; it->second.channel = ch; }
        }
        auto replies = handlePeerFrame(peerId, frame, ch);
        for (const auto& r : replies) {
            std::lock_guard<std::recursive_mutex> lk(mutex_);
            auto it = peers_.find(peerId);
            std::mutex* sm = (it != peers_.end()) ? &it->second.sendMutex : nullptr;
            if (sm) {
                std::lock_guard<std::mutex> slk(*sm);
                ch->send(r);
            } else {
                ch->send(r);
            }
        }
        (void)type;
    }
}

void ClusterClient::dropSession(const std::string& peerId, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    auto it = peers_.find(peerId);
    if (it == peers_.end()) return;
    it->second.connected = false;
    it->second.channel.reset();
    it->second.lastError = reason;
    it->second.lastErrorSec = nowSec();
    it->second.reconnects++;
}

void ClusterClient::dropSessionByChannel(const std::shared_ptr<Channel>& ch, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    for (auto& [id, rt] : peers_) {
        if (rt.channel == ch) {
            rt.connected = false;
            rt.channel.reset();
            rt.lastError = reason;
            rt.lastErrorSec = nowSec();
            rt.reconnects++;
            return;
        }
    }
}

bool ClusterClient::ensureSession(const std::string& peerId) {
    std::shared_ptr<Channel> existing;
    PeerConfig cfg;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        if (it == peers_.end()) return false;
        if (it->second.connected && it->second.channel) return true;
        cfg = it->second.cfg;
    }
    // dial: host:port
    auto colon = cfg.address.rfind(':');
    if (colon == std::string::npos) return false;
    std::string host = cfg.address.substr(0, colon);
    int port = std::atoi(cfg.address.substr(colon + 1).c_str());
    int fd = connectTcp(host, port, cfg.connectTimeoutSec);
    if (fd < 0) { dropSession(peerId, "tcp connect failed"); return false; }
    auto chR = makeTlsChannel(fd, /*clientRole=*/true, tls_.certFile, tls_.keyFile, tls_.caFile);
    if (!chR) {
        ::close(fd);
        dropSession(peerId, chR.error());
        return false;
    }
    auto ch = chR.value();
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        if (it == peers_.end()) return false;
        it->second.connected = true;
        it->second.channel = ch;
        it->second.direction = "out";
        it->second.sinceSec = nowSec();
    }
    Value hello = buildHelloFrame();
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        std::lock_guard<std::mutex> slk(it->second.sendMutex);
        auto sr = ch->send(hello);
        if (!sr) { dropSession(peerId, "hello send failed"); return false; }
    }
    // spawn the reader loop for this session
    std::thread([this, ch, peerId] { sessionLoop(ch, peerId, true); }).detach();
    return true;
}

void ClusterClient::dialLoop() {
    while (running_.load()) {
        {
            std::lock_guard<std::recursive_mutex> lk(mutex_);
            for (auto& [id, rt] : peers_) {
                if (!rt.cfg.dial) continue; // we are the listener side
                if (rt.connected) continue;
                // release lock around blocking connect: copy id
                std::string peerId = id;
                mutex_.unlock();
                ensureSession(peerId);
                mutex_.lock();
            }
        }
        for (int i = 0; i < 50 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ClusterClient::pollLoop() {
    while (running_.load()) {
        int64_t slept = 0;
        while (slept < opts_.pollIntervalSec && running_.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            ++slept;
        }
        if (!running_.load()) break;
        // pull snapshots from all outbound sessions (we dialed them => they
        // never initiate towards us; requests go over our channel)
        if (opts_.pollModel == "pull" || opts_.pollModel == "both") {
            std::vector<std::pair<std::string, std::shared_ptr<Channel>>> targets;
            {
                std::lock_guard<std::recursive_mutex> lk(mutex_);
                for (auto& [id, rt] : peers_)
                    if (rt.connected && rt.channel && rt.direction == "out") targets.emplace_back(id, rt.channel);
            }
            Value req = Value::object();
            req.set("type", Value::str("inventory_req"));
            req.set("from", Value::str(opts_.nodeId));
            for (auto& [id, ch] : targets) {
                std::lock_guard<std::recursive_mutex> lk(mutex_);
                auto it = peers_.find(id);
                if (it == peers_.end()) continue;
                std::lock_guard<std::mutex> slk(it->second.sendMutex);
                ch->send(req);
            }
        }
    }
}

// ------------------------------------------------------------- inventories ---

void ClusterClient::mergeViewsLocked() {
    peer::Inventory merged;
    merged.nodeId = opts_.nodeId;
    merged.revision = localRev_;
    merged.generatedAtSec = nowSec();
    std::set<std::string> seenClusters;
    auto addClusters = [&](const peer::Inventory& inv) {
        for (const auto& c : inv.clusters)
            if (seenClusters.insert(c.id).second) merged.clusters.push_back(c);
    };
    addClusters(localInv_);
    for (const auto& [id, rt] : peers_)
        if (rt.hasInventory) addClusters(rt.inventory);
    std::set<std::string> seenReps;
    auto addReps = [&](const peer::Inventory& inv) {
        for (const auto& r : inv.replications)
            if (seenReps.insert(r.name + "@" + inv.nodeId).second) merged.replications.push_back(r);
    };
    addReps(localInv_);
    for (const auto& [id, rt] : peers_)
        if (rt.hasInventory) addReps(rt.inventory);
    merged_ = merged;
    rebuildRoutesLocked();
}

void ClusterClient::rebuildRoutesLocked() {
    routes_.clear();
    // A peer advertising cluster X (or having X among its local clusters) can
    // serve X: local -> remote[X]. Clusters owned locally are never routed.
    for (const auto& [id, rt] : peers_) {
        if (!rt.hasInventory) continue;
        for (const auto& c : rt.inventory.localClusters)
            if (!ownsClusterLocked(c)) routes_.emplace(c, id);
        for (const auto& c : rt.inventory.clusters)
            if (!ownsClusterLocked(c)) routes_.emplace(c.id, id);
    }
    // refresh remote[] UNIX listeners lazily on next start(); also create on demand
    for (const auto& [clusterId, hop] : routes_) {
        if (remoteFds_.count(clusterId)) continue;
        std::string path = opts_.runDir + "/" + opts_.nodeId + "/remote-" + clusterId + ".sock";
        int fd = bindUnixListener(path);
        if (fd >= 0) {
            remoteFds_[clusterId] = fd;
            if (running_.load())
                std::thread([this, fd, clusterId] { unixAcceptLoop(fd, clusterId); }).detach();
        }
    }
}

bool ClusterClient::ownsClusterLocked(const std::string& id) const {
    for (const auto& c : localInv_.localClusters)
        if (c == id) return true;
    return false;
}

bool ClusterClient::ownsCluster(const std::string& id) const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return ownsClusterLocked(id);
}

std::string ClusterClient::routeTo(const std::string& clusterId) const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    auto it = routes_.find(clusterId);
    return it == routes_.end() ? std::string() : it->second;
}

peer::Inventory ClusterClient::mergedInventory() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return merged_;
}

std::vector<std::pair<std::string, std::string>> ClusterClient::routes() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return {routes_.begin(), routes_.end()};
}

std::vector<PeerLinkInfo> ClusterClient::links() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    std::vector<PeerLinkInfo> out;
    for (const auto& [id, rt] : peers_) {
        PeerLinkInfo info;
        info.id = id;
        info.address = rt.cfg.address;
        info.direction = rt.direction;
        info.connected = rt.connected;
        info.sinceSec = rt.sinceSec;
        info.lastSeenSec = rt.lastSeenSec;
        info.reconnects = rt.reconnects;
        info.lastErrorSec = rt.lastErrorSec;
        info.lastError = rt.lastError;
        if (rt.hasInventory) {
            info.inventoryRevision = rt.inventory.revision;
            info.inventoryAtSec = rt.inventory.generatedAtSec;
        }
        out.push_back(info);
    }
    return out;
}

size_t ClusterClient::pendingCount() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    return taskNextHop_.size();
}

Value ClusterClient::statusValue() const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    Value v = Value::object();
    v.set("node", Value::str(opts_.nodeId));
    v.set("revision", Value::number(localRev_));
    v.set("poll_model", Value::str(opts_.pollModel));
    v.set("poll_interval_sec", Value::number(opts_.pollIntervalSec));
    Value links = Value::array();
    for (const auto& [id, rt] : peers_) {
        Value lv = Value::object();
        lv.set("id", Value::str(id));
        lv.set("address", Value::str(rt.cfg.address));
        lv.set("direction", Value::str(rt.direction));
        lv.set("connected", Value::boolean(rt.connected));
        lv.set("last_error", Value::str(rt.lastError));
        lv.set("inventory_revision", Value::number(rt.hasInventory ? rt.inventory.revision : 0));
        links.push(lv);
    }
    v.set("links", links);
    Value routesArr = Value::array();
    for (const auto& [c, hop] : routes_) {
        Value rv = Value::object();
        rv.set("cluster", Value::str(c));
        rv.set("via", Value::str(hop));
        routesArr.push(rv);
    }
    v.set("routes", routesArr);
    v.set("pending_tasks", Value::number((int64_t)taskNextHop_.size()));
    return v;
}

// ------------------------------------------------------------- core bridge ---

namespace {

int connectCoreCtl(const std::string& coreSocketPath) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_un un{};
    un.sun_family = AF_UNIX;
    std::strncpy(un.sun_path, coreSocketPath.c_str(), sizeof(un.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

} // namespace

// The core bridge talks to s3mmd's control protocol (JSON lines over the
// control UNIX socket) using two commands implemented daemon-side:
//   {"cmd":"cluster-get","bucket":..,"key":..,"to":<abs path>}
//   {"cmd":"cluster-put","bucket":..,"key":..,"from":<abs path>,"meta":{...},"size":N}
//   {"cmd":"cluster-del","bucket":..,"key":..}
// Replies: {"ok":true} / {"ok":false,"error":"..."}.

bool ClusterClient::coreCall(const Value& request, int extraFd, Value* reply) {
    std::string line = request.toJson() + "\n";
    int fd = connectCoreCtl(coreSocketPath_);
    if (fd < 0) return false;
    if (!writeAllFd(fd, line)) { ::close(fd); return false; }
    // optional blob: 8-byte BE length + raw bytes follow the request line
    if (extraFd >= 0) {
        auto sz = fs::fileSize(std::string(request.getString("from")));
        uint64_t len = sz ? *sz : 0;
        unsigned char hdr[8];
        uint64_t t = len;
        for (int i = 7; i >= 0; --i) { hdr[i] = (unsigned char)(t & 0xFF); t >>= 8; }
        if (!writeAllFd(fd, std::string((char*)hdr, 8))) { ::close(fd); return false; }
        char buf[65536];
        uint64_t sent = 0;
        while (sent < len) {
            ssize_t n = ::read(extraFd, buf, sizeof(buf));
            if (n <= 0) break;
            if (!writeAllFd(fd, std::string(buf, (size_t)n))) { ::close(fd); return false; }
            sent += (uint64_t)n;
        }
    }
    std::string resp;
    if (!readLineFd(fd, resp, (int)opts_.coreTimeoutSec * 1000)) { ::close(fd); return false; }
    ::close(fd);
    std::string err;
    auto v = Value::parseJson(resp, &err);
    if (!err.empty() || !v.isObject()) return false;
    if (reply) *reply = v;
    return v.asBool(false) || v.find("ok") != nullptr;
}

bool ClusterClient::coreGetToFile(const std::string& bucket, const std::string& key, const std::string& path,
                                  std::string* error) {
    Value req = Value::object();
    req.set("cmd", Value::str("cluster-get"));
    req.set("bucket", Value::str(bucket));
    req.set("key", Value::str(key));
    req.set("to", Value::str(path));
    Value reply;
    if (!coreCall(req, -1, &reply)) {
        if (error) *error = "core get failed";
        return false;
    }
    if (const Value* ok = reply.find("ok"); ok && ok->asBool(false)) return true;
    if (error) *error = reply.getString("error", "core get rejected");
    return false;
}

bool ClusterClient::corePutFromFile(const std::string& bucket, const std::string& key, const std::string& path,
                                    const Value& meta, uint64_t size, std::string* error) {
    Value req = Value::object();
    req.set("cmd", Value::str("cluster-put"));
    req.set("bucket", Value::str(bucket));
    req.set("key", Value::str(key));
    req.set("from", Value::str(path));
    req.set("size", Value::number((int64_t)size));
    req.set("meta", meta);
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        if (error) *error = "cannot open spool file";
        return false;
    }
    bool okv = coreCall(req, fd, nullptr);
    ::close(fd);
    if (!okv) {
        if (error) *error = "core put failed";
        return false;
    }
    return true;
}

bool ClusterClient::coreDelete(const std::string& bucket, const std::string& key, std::string* error) {
    Value req = Value::object();
    req.set("cmd", Value::str("cluster-del"));
    req.set("bucket", Value::str(bucket));
    req.set("key", Value::str(key));
    Value reply;
    if (!coreCall(req, -1, &reply)) {
        if (error) *error = "core delete failed";
        return false;
    }
    if (const Value* ok = reply.find("ok"); ok && ok->asBool(false)) return true;
    if (error) *error = reply.getString("error", "core delete rejected");
    return false;
}

} // namespace s3mm::s3mmc
