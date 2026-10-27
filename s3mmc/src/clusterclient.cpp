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
#include "s3mm/common/glob.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/time.hpp"

#include "configfile.hpp"

namespace s3mm::s3mmc {

namespace {

int64_t nowSec() { return (int64_t)tm::toSeconds(tm::now()); }

std::string newTaskId(const std::string& nodeId, std::atomic<uint64_t>& seq) {
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
        if (pr <= 0) {
            LOG_WARN("s3mmc: fd ", fd, " line read ", pr == 0 ? "timeout" : std::strerror(errno),
                     " after ", line.size(), " bytes");
            return false;
        }
        ssize_t n = ::recv(fd, &c, 1, 0);
        if (n <= 0) {
            if (n < 0) LOG_WARN("s3mmc: fd ", fd, " line read failed: ", std::strerror(errno));
            else LOG_DEBUG("s3mmc: fd ", fd, " closed while reading line (", line.size(), " bytes)");
            return false;
        }
        if (c == '\n') return true;
        if (c != '\r') line.push_back(c);
        if (line.size() > 16384) {
            LOG_WARN("s3mmc: fd ", fd, " request line exceeds 16384 bytes");
            return false;
        }
    }
}

bool writeAllFd(int fd, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            LOG_WARN("s3mmc: fd ", fd, " write failed after ", off, "/", data.size(), " bytes: ",
                     n < 0 ? std::strerror(errno) : "peer closed");
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
    if (out < 0) {
        LOG_ERROR("s3mmc: cannot create spool '", path, "': ", std::strerror(errno));
        return (uint64_t)-1;
    }
    uint64_t got = 0;
    char buf[65536];
    log::Stopwatch sw;
    while (got < len) {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, timeoutMs) <= 0) {
            LOG_WARN("s3mmc: body read timeout on fd ", fd, " at ", got, "/", len, " bytes");
            break;
        }
        size_t want = (size_t)std::min<uint64_t>(sizeof(buf), len - got);
        ssize_t n = ::recv(fd, buf, want, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            LOG_WARN("s3mmc: body read on fd ", fd, " stopped at ", got, "/", len, " bytes: ",
                     n < 0 ? std::strerror(errno) : "peer closed");
            break;
        }
        size_t off = 0;
        while (off < (size_t)n) {
            ssize_t w = ::write(out, buf + off, (size_t)n - off);
            if (w <= 0) {
                LOG_ERROR("s3mmc: spool write '", path, "' failed: ", std::strerror(errno));
                ::close(out);
                return got;
            }
            off += (size_t)w;
        }
        got += (size_t)n;
    }
    ::close(out);
    LOG_DEBUG("s3mmc: spooled ", got, "/", len, " bytes into '", path, "' in ", sw.ms(), " ms");
    return got;
}

int bindTcpListener(const std::string& address, int port, std::string* error) {
    LOG_DEBUG("s3mmc: binding peer listener ", address, ":", port);
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        *error = "socket failed";
        LOG_ERROR("s3mmc: peer listener socket(): ", std::strerror(errno));
        return -1;
    }
    int opt = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (::inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
        *error = "invalid listen address '" + address + "'";
        LOG_ERROR("s3mmc: ", *error);
        ::close(fd);
        return -1;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        *error = std::string("bind ") + address + ":" + std::to_string(port) + " failed: " + strerror(errno);
        LOG_ERROR("s3mmc: ", *error);
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 32) < 0) {
        *error = "listen failed";
        LOG_ERROR("s3mmc: listen on ", address, ":", port, " failed: ", std::strerror(errno));
        ::close(fd);
        return -1;
    }
    LOG_DEBUG("s3mmc: peer listener fd ", fd, " bound to ", address, ":", port);
    return fd;
}

int connectTcp(const std::string& host, int port, int timeoutSec) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    LOG_DEBUG("s3mmc: resolving ", host, ":", port, " (timeout ", timeoutSec, "s)");
    if (int gr = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res); gr != 0) {
        LOG_ERROR("s3mmc: cannot resolve ", host, ":", port, ": ", gai_strerror(gr));
        return -1;
    }
    int fd = -1;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        char ip[INET6_ADDRSTRLEN] = "?";
        if (ai->ai_family == AF_INET)
            ::inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr, ip, sizeof ip);
        else if (ai->ai_family == AF_INET6)
            ::inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr, ip, sizeof ip);
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            LOG_WARN("s3mmc: socket() for ", ip, ":", port, " failed: ", std::strerror(errno));
            continue;
        }
        LOG_DEBUG("s3mmc: connecting to ", host, " (", ip, "):", port);
        int flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0 && errno != EINPROGRESS) {
            LOG_WARN("s3mmc: connect to ", ip, ":", port, " failed: ", std::strerror(errno));
            ::close(fd); fd = -1; continue;
        }
        if (rc < 0) {
            pollfd p{fd, POLLOUT, 0};
            if (::poll(&p, 1, timeoutSec * 1000) <= 0) {
                LOG_WARN("s3mmc: connect to ", ip, ":", port, " timed out after ", timeoutSec, "s");
                ::close(fd); fd = -1; continue;
            }
            int err = 0;
            socklen_t elen = sizeof(err);
            ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (err != 0) {
                LOG_WARN("s3mmc: connect to ", ip, ":", port, " failed: ", std::strerror(err));
                ::close(fd); fd = -1; continue;
            }
        }
        LOG_DEBUG("s3mmc: TCP connected to ", host, " (", ip, "):", port, " fd ", fd);
        ::fcntl(fd, F_SETFL, flags); // back to blocking
        break;
    }
    freeaddrinfo(res);
    return fd;
}

int bindUnixListener(const std::string& path, mode_t perms = 0660) {
    LOG_DEBUG("s3mmc: binding UNIX socket ", path, " mode ", std::oct, perms, std::dec);
    if (!fs::mkdirp(fs::dirname(path))) LOG_WARN("s3mmc: cannot create directory ", fs::dirname(path));
    if (::unlink(path.c_str()) == 0) LOG_DEBUG("s3mmc: removed stale socket ", path);
    if (path.size() >= sizeof(sockaddr_un::sun_path))
        LOG_WARN("s3mmc: UNIX socket path too long (", path.size(), " bytes), will be truncated: ", path);
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("s3mmc: socket(AF_UNIX) for ", path, " failed: ", std::strerror(errno));
        return -1;
    }
    sockaddr_un un{};
    un.sun_family = AF_UNIX;
    std::strncpy(un.sun_path, path.c_str(), sizeof(un.sun_path) - 1);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) {
        LOG_ERROR("s3mmc: bind ", path, " failed: ", std::strerror(errno));
        ::close(fd);
        return -1;
    }
    // Restrict the socket explicitly: default umask would leave it world-writable
    // and any local process could use s3mmc as an authenticated S3 proxy.
    if (::chmod(path.c_str(), perms) < 0) {
        LOG_WARN("s3mmc: chmod ", path, " failed: ", std::strerror(errno));
    }
    if (::listen(fd, 64) < 0) {
        LOG_ERROR("s3mmc: listen on ", path, " failed: ", std::strerror(errno));
        ::close(fd);
        ::unlink(path.c_str());
        return -1;
    }
    LOG_DEBUG("s3mmc: UNIX socket ", path, " listening on fd ", fd);
    return fd;
}

// Peer credentials of a UNIX-socket client (uid/gid/pid), for audit logging.
bool peerCredentials(int fd, uid_t& uid, gid_t& gid, pid_t& pid) {
    sockaddr_un addr{};
    socklen_t len = sizeof(addr);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0 || len != sizeof(addr)) {
        LOG_DEBUG("s3mmc: getpeername on fd ", fd, " unavailable (len ", len, ")");
        return false;
    }
    struct ucred cred{};
    socklen_t clen = sizeof(cred);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0) {
        LOG_DEBUG("s3mmc: SO_PEERCRED on fd ", fd, " failed: ", std::strerror(errno));
        return false;
    }
    uid = cred.uid; gid = cred.gid; pid = cred.pid;
    return true;
}

} // namespace

// ---------------------------------------------------------------- construction --

ClusterClient::ClusterClient(Options opts, TlsConfig tls) : opts_(std::move(opts)), tls_(std::move(tls)) {
    if (opts_.nodeId.empty()) opts_.nodeId = "node-" + std::to_string(::getpid());
    spoolDir_ = opts_.spoolDir.empty() ? opts_.runDir + "/spool" : opts_.spoolDir;
    controlPath_ = opts_.runDir + "/" + opts_.nodeId + "/s3mmc.sock";
    coreSocketPath_ = opts_.coreSocket.empty() ? std::string("/run/s3mm/s3mm.sock") : opts_.coreSocket;
    LOG_DEBUG("s3mmc: client created node='", opts_.nodeId, "' run_dir=", opts_.runDir, " spool=", spoolDir_,
              " core=", coreSocketPath_);
}

ClusterClient::~ClusterClient() { stop(); }

// ------------------------------------------------------------------ configure --

Result<void> ClusterClient::setPeers(std::vector<PeerConfig> peers) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    LOG_DEBUG("s3mmc: setting ", peers.size(), " peers (replacing ", peers_.size(), ")");
    peers_.clear();
    byAddress_.clear();
    for (auto& p : peers) {
        if (p.id.empty()) {
            LOG_ERROR("s3mmc: setPeers: peer without id (address '", p.address, "')");
            return Result<void>::failure("peer requires an id");
        }
        if (p.address.empty()) {
            LOG_ERROR("s3mmc: setPeers: peer '", p.id, "' without address");
            return Result<void>::failure("peer '" + p.id + "' requires an address");
        }
        PeerRuntime& rt = peers_[p.id];
        rt.cfg = p;
        byAddress_[p.address] = p.id;
        LOG_DEBUG("s3mmc: peer '", p.id, "' address=", p.address, " dial=", p.dial ? "on" : "off",
                  " connect_timeout=", p.connectTimeoutSec, "s");
    }
    rebuildRoutesLocked();
    LOG_INFO("s3mmc: ", peers_.size(), " peers configured");
    return Result<void>::success();
}

Result<void> ClusterClient::addPeer(PeerConfig p) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (p.id.empty() || p.address.empty()) {
        LOG_ERROR("s3mmc: addPeer: id and address required (id='", p.id, "' address='", p.address, "')");
        return Result<void>::failure("peer add: id and address required");
    }
    PeerRuntime& rt = peers_[p.id];
    rt.cfg = std::move(p);
    byAddress_[rt.cfg.address] = rt.cfg.id;
    rebuildRoutesLocked();
    LOG_INFO("s3mmc: peer '", rt.cfg.id, "' added (", rt.cfg.address, ", dial ", rt.cfg.dial ? "on" : "off", ")");
    return Result<void>::success();
}

Result<void> ClusterClient::removePeer(const std::string& idOrAddress) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    auto it = peers_.find(idOrAddress);
    if (it == peers_.end()) {
        auto ad = byAddress_.find(idOrAddress);
        if (ad != byAddress_.end()) it = peers_.find(ad->second);
    }
    if (it == peers_.end()) {
        LOG_WARN("s3mmc: removePeer: unknown peer '", idOrAddress, "'");
        return Result<void>::failure("unknown peer '" + idOrAddress + "'");
    }
    LOG_INFO("s3mmc: removing peer '", it->first, "' (", it->second.cfg.address, ")");
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

Result<std::vector<std::string>> ClusterClient::parseExposeList(const std::string& spec) {
    // Normalise separators, keep "!" exclusions and glob chars intact.
    std::string norm;
    norm.reserve(spec.size());
    for (char c : spec) norm.push_back(c == ',' ? ' ' : c);
    auto parts = str::splitWS(norm);
    std::vector<std::string> out;
    bool sawStar = false, sawExcl = false;
    for (auto& p : parts) {
        if (p.empty()) continue;
        if (p == "none" || p == "off") continue;  // explicit none => nothing
        if (p[0] == '!') {
            if (p.size() < 2) {
                LOG_ERROR("s3mmc: expose '", spec, "': empty exclusion '!'");
                return Result<std::vector<std::string>>::failure("expose: empty exclusion '!'");
            }
            sawExcl = true;
            out.push_back(p);
            continue;
        }
        if (p == "*") sawStar = true;
        out.push_back(p);
    }
    if (sawStar && (out.size() > 1 || sawExcl)) {
        LOG_ERROR("s3mmc: expose '", spec, "': wildcard '*' combined with other elements");
        return Result<std::vector<std::string>>::failure(
            "expose: wildcard '*' must be the sole value or replaced by an explicit list");
    }
    LOG_DEBUG("s3mmc: expose '", spec, "' -> ", out.size(), " elements");
    return Result<std::vector<std::string>>(std::move(out));
}

Result<void> ClusterClient::configure(const Options& opts, const TlsConfig& tls) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (running_.load() && (opts.nodeId != opts_.nodeId || opts.runDir != opts_.runDir)) {
        LOG_ERROR("s3mmc: configure refused: node/run_dir change while running ('", opts_.nodeId, "' -> '",
                  opts.nodeId, "', ", opts_.runDir, " -> ", opts.runDir, ")");
        return Result<void>::failure("node/run_dir cannot change while s3mmc is running");
    }
    opts_ = opts;
    // Recompile the per-peer ACL table from raw expose rules so that callers
    // using configure() directly (not only config-file parsing) get ACLs too.
    auto aclR = compilePeerAcls(opts_);
    if (!aclR) {
        LOG_ERROR("s3mmc: configure: ACL compilation failed: ", aclR.error());
        return aclR;
    }
    if (opts_.nodeId.empty()) LOG_WARN("s3mmc: node id empty, using node-", ::getpid());
    if (opts_.nodeId.empty()) opts_.nodeId = "node-" + std::to_string(::getpid());
    // keep opts_.spoolDir as configured: an unset spool_dir follows run_dir
    spoolDir_ = opts_.spoolDir.empty() ? opts_.runDir + "/spool" : opts_.spoolDir;
    if (opts_.spoolDir.empty()) LOG_DEBUG("s3mmc: spool_dir not set, derived from run_dir: ", spoolDir_);
    controlPath_ = opts_.runDir + "/" + opts_.nodeId + "/s3mmc.sock";
    coreSocketPath_ = opts_.coreSocket.empty() ? std::string("/run/s3mm/s3mm.sock") : opts_.coreSocket;
    tls_ = tls;
    if (!tls_.certFile.empty() && !fs::exists(tls_.certFile)) {
        LOG_ERROR("s3mmc: tls cert file not found: ", tls_.certFile);
        return Result<void>::failure("tls cert file not found: " + tls_.certFile);
    }
    if (!tls_.keyFile.empty() && !fs::exists(tls_.keyFile)) {
        LOG_ERROR("s3mmc: tls key file not found: ", tls_.keyFile);
        return Result<void>::failure("tls key file not found: " + tls_.keyFile);
    }
    if (!tls_.caFile.empty() && !fs::exists(tls_.caFile)) {
        LOG_ERROR("s3mmc: tls ca file not found: ", tls_.caFile);
        return Result<void>::failure("tls ca file not found: " + tls_.caFile);
    }
    if (tls_.caFile.empty()) LOG_WARN("s3mmc: no tls ca configured: peer certificate verification is OFF");
    LOG_DEBUG("s3mmc: configured node='", opts_.nodeId, "' run_dir=", opts_.runDir, " spool=", spoolDir_,
              " core=", coreSocketPath_, " listen=", opts_.listenAddress, ":", opts_.listenPort,
              " poll=", opts_.pollModel, "/", opts_.pollIntervalSec, "s timeout=", opts_.pollTimeoutSec,
              "s core_timeout=", opts_.coreTimeoutSec, "s spool_threshold=", opts_.spoolThresholdBytes,
              " required_only=", opts_.requiredOnly ? "on" : "off", " managers=", opts_.managedNodes.size(),
              " expose_rules=", opts_.exposeRules.size(), " acls=", opts_.peerAcls.size(),
              " tls cert=", tls_.certFile, " key=", tls_.keyFile, " ca=", tls_.caFile);
    return Result<void>::success();
}

void ClusterClient::setLocalInventory(const peer::Inventory& inv) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    localInv_ = inv;
    localInv_.nodeId = opts_.nodeId;
    localInv_.revision = ++localRev_;
    localInv_.generatedAtSec = nowSec();
    LOG_DEBUG("s3mmc: local inventory rev ", localInv_.revision, ": ", localInv_.clusters.size(), " clusters, ",
              localInv_.replications.size(), " replications, ", localInv_.localClusters.size(), " local clusters");
    mergeViewsLocked();
    // push our fresh snapshot to every listener-side session (they dialed us;
    // we may initiate transfers towards them) when the model allows pushes
    if (opts_.pollModel == "push" || opts_.pollModel == "both") {
        for (auto& [id, rt] : peers_) {
            if (rt.connected && rt.direction == "in" && rt.channel) {
                // visibility is per-peer: managers see everything, others get
                // the snapshot filtered through `expose`
                Value frame = buildInventoryFrame(id);
                std::lock_guard<std::mutex> slk(rt.sendMutex);
                if (auto sr = rt.channel->send(frame); !sr)
                    LOG_WARN("s3mmc: inventory push to '", id, "' failed: ", sr.error());
                else
                    LOG_DEBUG("s3mmc: pushed inventory rev ", localInv_.revision, " to '", id, "'");
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
        if (m == "*" || m == peerId) {        // wildcard: every connected peer; CN == cluster id == peer id
            LOG_DEBUG("s3mmc: '", peerId, "' is a manager (matched '", m, "')");
            return true;
        }
    }
    return false;
}

void ClusterClient::setConfigPath(const std::string& path) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    LOG_DEBUG("s3mmc: config path set to ", path);
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
    LOG_DEBUG("s3mmc: secrets dir ", dir, masterKeyFile.empty() ? "" : " master key file ", masterKeyFile);
}

bool ClusterClient::currentConfigText(std::string* text, std::string* error) const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (configPath_.empty()) {
        *error = "no configuration file is associated with this instance";
        LOG_WARN("s3mmc: ", *error);
        return false;
    }
    auto content = fs::readFile(configPath_);
    if (!content) {
        *error = "cannot read '" + configPath_ + "'";
        LOG_ERROR("s3mmc: ", *error);
        return false;
    }
    *text = *content;
    LOG_DEBUG("s3mmc: read current config ", configPath_, " (", text->size(), " bytes)");
    return true;
}

Result<void> ClusterClient::applyConfigTextFrom(const std::string& text, const std::string& filename,
                                                const std::string& viaManager) {
    std::string targetPath;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        if (!viaManager.empty() && !isManagerOf(viaManager)) {
            LOG_WARN("s3mmc: config update from '", viaManager, "' denied: not a manager of ", opts_.nodeId);
            return Result<void>::failure("remote denied: '" + viaManager +
                                         "' is not a manager of " + opts_.nodeId);
        }
        targetPath = configPath_.empty() ? filename : configPath_;
    }
    LOG_INFO("s3mmc: applying config text (", text.size(), " bytes) to ", targetPath,
             viaManager.empty() ? " (local)" : " via manager '", viaManager, viaManager.empty() ? "" : "'");
    if (targetPath.empty()) {
        LOG_ERROR("s3mmc: no configuration file path known; refusing to apply");
        return Result<void>::failure("no configuration file path known; refusing to apply");
    }

    // Validate the candidate text against a throwaway client first so a bad
    // patch never overwrites the live file.
    {
        ClusterClient probe(options(), tlsConfig());
        auto vr = applyConfigText(probe, text, targetPath);
        if (!vr) {
            LOG_ERROR("s3mmc: config candidate rejected: ", vr.error());
            return Result<void>::failure("config rejected: " + vr.error());
        }
        LOG_DEBUG("s3mmc: config candidate validated");
    }

    // Persist over the live file (atomic), then hot-reload ourselves.
    std::string dir = fs::dirname(targetPath);
    if (!dir.empty()) fs::mkdirp(dir);
    if (!fs::writeFileAtomic(targetPath, text, /*fsyncDir=*/true)) {
        LOG_ERROR("s3mmc: cannot write config '", targetPath, "'");
        return Result<void>::failure("cannot write '" + targetPath + "'");
    }
    LOG_DEBUG("s3mmc: config persisted to ", targetPath);
    setConfigPath(targetPath);
    auto ar = applyConfigText(*this, text, targetPath);
    if (!ar) {
        LOG_ERROR("s3mmc: config persisted but reload failed: ", ar.error());
        return Result<void>::failure("applied but reload failed: " + ar.error());
    }
    LOG_INFO("s3mmc: configuration updated",
             viaManager.empty() ? "" : (" via manager '" + viaManager + "'"));
    return Result<void>::success();
}

// ---------------------------------------------- managed-nodes model (manager) --

Result<std::string> ClusterClient::pullPeerConfig(const std::string& peerId) {
    LOG_DEBUG("s3mmc: pulling config of peer '", peerId, "'");
    auto r = requestConfigFromPeer(peerId);
    if (!r) LOG_ERROR("s3mmc: config pull from '", peerId, "' failed: ", r.error());
    else LOG_INFO("s3mmc: pulled config of '", peerId, "' (", r.value().size(), " bytes)");
    return r;
}

Result<void> ClusterClient::pushPeerConfig(const std::string& peerId, const std::string& text,
                                           const std::string& filename) {
    log::Stopwatch sw;
    LOG_DEBUG("s3mmc: pushing config (", text.size(), " bytes, ", filename, ") to '", peerId, "'");
    if (!ensureSession(peerId)) {
        LOG_ERROR("s3mmc: config push: peer '", peerId, "' not reachable");
        return Result<void>::failure("peer '" + peerId + "' not reachable");
    }
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
        LOG_ERROR("s3mmc: config_set ", id, " to '", peerId, "' send failed: ", serr);
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_.erase(id);
        return Result<void>::failure(serr);
    }
    std::unique_lock<std::mutex> wl(waiter->mu);
    bool got = waiter->cv.wait_for(wl, std::chrono::seconds(opts_.pollTimeoutSec),
                                   [&] { return waiter->done; });
    if (!got) {
        LOG_ERROR("s3mmc: config_set ", id, " timed out on '", peerId, "' after ", sw.ms(), " ms");
        std::lock_guard<std::mutex> lk(reqMutex_);
        pendingReqs_.erase(id);
        return Result<void>::failure("config_set timed out on '" + peerId + "'");
    }
    const Value& reply = waiter->reply;
    if (reply.getString("status") != "ok") {
        LOG_ERROR("s3mmc: config_set ", id, " refused by '", peerId, "': ", reply.getString("reason", "config_set refused"));
        return Result<void>::failure(reply.getString("reason", "config_set refused"));
    }
    LOG_INFO("s3mmc: config pushed to '", peerId, "' in ", sw.ms(), " ms");
    return Result<void>::success();
}

Result<Value> ClusterClient::pullPeerCredentials(const std::string& peerId,
                                                 const std::string& clusterFilter) {
    LOG_DEBUG("s3mmc: pulling credentials from '", peerId, "' filter='", clusterFilter, "'");
    auto credsR = requestCredsFromPeer(peerId, clusterFilter);
    if (!credsR) {
        LOG_ERROR("s3mmc: credential pull from '", peerId, "' failed: ", credsR.error());
        return credsR;
    }
    // Hand the sealed blocks to our own core for import under our master key.
    // The core owns sealing/unsealing; s3mmc only transports them.
    Value req = Value::object();
    req.set("cmd", Value::str("cluster-import-credentials"));
    req.set("source_peer", Value::str(peerId));
    req.set("credentials", *credsR.value().find("credentials"));
    Value reply;
    if (!coreCall(req, -1, &reply)) {
        LOG_ERROR("s3mmc: core rejected credential import from '", peerId, "'");
        return Result<Value>::failure("core rejected credential import");
    }
    if (const Value* ok = reply.find("ok"); ok && ok->asBool(false)) {
        LOG_INFO("s3mmc: credentials from '", peerId, "' imported into core");
        return Result<Value>(credsR.value());
    }
    LOG_ERROR("s3mmc: core credential import from '", peerId, "' failed: ", reply.getString("error", "core credential import failed"));
    return Result<Value>::failure(reply.getString("error", "core credential import failed"));
}

// --------------------------------------------------------------------- start --

Result<void> ClusterClient::start() {
    if (running_.exchange(true)) {
        LOG_DEBUG("s3mmc: start() called while already running");
        return Result<void>::success();
    }
    LOG_DEBUG("s3mmc: starting node '", opts_.nodeId, "'");
    if (!fs::mkdirp(spoolDir_)) LOG_WARN("s3mmc: cannot create spool dir ", spoolDir_);

    std::string error;
    if (opts_.listenPort > 0) {
        peerListenFd_ = bindTcpListener(opts_.listenAddress, opts_.listenPort, &error);
        if (peerListenFd_ < 0) {
            LOG_ERROR("s3mmc: peer listener failed: ", error);
            running_ = false;
            return Result<void>::failure("peer listener: " + error);
        }
        LOG_NOTICE("s3mmc: listening for peers on ", opts_.listenAddress, ":", opts_.listenPort, " (mTLS)");
        threads_.emplace_back([this] { acceptLoop(); });
    } else {
        LOG_NOTICE("s3mmc: peer listener disabled (listen port 0)");
    }

    // remote[id] UNIX listeners: with requiredOnly=true only the clusters our
    // replication rules point at; otherwise everything the merged inventory
    // routes through us.
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        std::set<std::string> wanted;
        if (opts_.requiredOnly) {
            for (const auto& c : requiredClustersLocked()) wanted.insert(c);
        } else {
            for (const auto& [clusterId, hop] : routes_)
                if (!ownsClusterLocked(clusterId)) wanted.insert(clusterId);
        }
        LOG_DEBUG("s3mmc: ", wanted.size(), " remote sockets wanted at start (",
                  opts_.requiredOnly ? "required_only" : "all routed", ")");
        for (const auto& clusterId : wanted) {
            if (remoteFds_.count(clusterId)) continue;
            std::string path = opts_.runDir + "/" + opts_.nodeId + "/remote-" + clusterId + ".sock";
            int fd = bindUnixListener(path);
            if (fd < 0) { LOG_WARN("s3mmc: cannot bind ", path); continue; }
            LOG_INFO("s3mmc: remote[", clusterId, "] socket ", path);
            remoteFds_[clusterId] = fd;
            threads_.emplace_back([this, fd, clusterId] { unixAcceptLoop(fd, clusterId); });
        }
    }

    controlFd_ = bindUnixListener(controlPath_);
    if (controlFd_ >= 0) {
        LOG_INFO("s3mmc: control socket ", controlPath_);
        threads_.emplace_back([this] { controlLoop(); });
    } else {
        LOG_ERROR("s3mmc: cannot bind control socket ", controlPath_, " (status CLI unavailable)");
    }
    threads_.emplace_back([this] { dialLoop(); });
    threads_.emplace_back([this] { pollLoop(); });
    LOG_NOTICE("s3mmc node '", opts_.nodeId, "' started (peer port ", opts_.listenPort, ", run dir ",
             opts_.runDir, ")");
    return Result<void>::success();
}

void ClusterClient::stop() {
    if (!running_.exchange(false)) return;
    LOG_NOTICE("s3mmc: stopping node '", opts_.nodeId, "'");
    log::Stopwatch sw;
    if (peerListenFd_ >= 0) { ::close(peerListenFd_); peerListenFd_ = -1; LOG_DEBUG("s3mmc: peer listener closed"); }
    if (controlFd_ >= 0) {
        ::close(controlFd_); controlFd_ = -1; ::unlink(controlPath_.c_str());
        LOG_DEBUG("s3mmc: control socket ", controlPath_, " removed");
    }
    for (auto& [id, fd] : remoteFds_) {
        ::close(fd);
        std::string path = opts_.runDir + "/" + opts_.nodeId + "/remote-" + id + ".sock";
        if (::unlink(path.c_str()) == 0) LOG_DEBUG("s3mmc: remote[", id, "] socket ", path, " removed");
        else LOG_WARN("s3mmc: cannot remove ", path, ": ", std::strerror(errno));
    }
    remoteFds_.clear();
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        for (auto& [id, rt] : peers_) rt.channel.reset();
    }
    LOG_DEBUG("s3mmc: joining ", threads_.size(), " threads");
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    threads_.clear();
    LOG_NOTICE("s3mmc: node '", opts_.nodeId, "' stopped in ", sw.ms(), " ms");
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
    if (!readLineFd(fd, line, timeoutMs)) {
        LOG_WARN("s3mmc: fd ", fd, ": no request line");
        return r;
    }
    auto sp1 = line.find(' ');
    auto sp2 = sp1 == std::string::npos ? sp1 : line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) {
        LOG_WARN("s3mmc: fd ", fd, ": malformed request line '", log::clip(line, 128), "'");
        return r;
    }
    r.method = line.substr(0, sp1);
    r.target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    for (;;) {
        if (!readLineFd(fd, line, timeoutMs)) {
            LOG_WARN("s3mmc: fd ", fd, ": ", r.method, " ", r.target, ": headers truncated");
            return r;
        }
        if (line.empty()) break;
        auto colon = line.find(':');
        if (colon == std::string::npos) {
            LOG_DEBUG("s3mmc: fd ", fd, ": ignoring header line without colon");
            continue;
        }
        std::string name = str::toLower(str::trim(line.substr(0, colon)));
        std::string val = str::trim(line.substr(colon + 1));
        r.headers[name] = val;
    }
    r.ok = true;
    LOG_DEBUG("s3mmc: fd ", fd, ": ", r.method, " ", r.target, " (", r.headers.size(), " headers)");
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
    LOG_DEBUG("s3mmc: remote[", clusterId, "] accept loop started on fd ", fd);
    while (running_.load()) {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, 500) <= 0) continue;
        int client = ::accept(fd, nullptr, nullptr);
        if (client < 0) {
            if (running_.load()) LOG_WARN("s3mmc: remote[", clusterId, "] accept failed: ", std::strerror(errno));
            continue;
        }
        // Audit the kernel-provided peer credentials of the local connection.
        { uid_t u = 0; gid_t g = 0; pid_t p = 0;
          if (peerCredentials(client, u, g, p))
              LOG_DEBUG("s3mmc: core socket accept cluster='", clusterId, "' uid=", u, " pid=", p); }
        LOG_DEBUG("s3mmc: remote[", clusterId, "] accepted fd ", client);
        std::thread([this, client, clusterId] {
            std::string resp = handleCoreRequestOnSocket(client, clusterId);
            if (!resp.empty()) writeAllFd(client, resp);
            ::close(client);
        }).detach();
    }
    LOG_DEBUG("s3mmc: remote[", clusterId, "] accept loop finished");
}

std::string ClusterClient::handleCoreRequestOnSocket(int fd, const std::string& clusterId) {
    log::Stopwatch sw;
    auto req = parseHttpRequest(fd, (int)opts_.coreTimeoutSec * 1000);
    if (!req.ok) {
        LOG_WARN("s3mmc: remote[", clusterId, "] malformed request -> 400");
        return httpReply(400, "failed", "malformed request", 0);
    }
    // split /bucket/key
    std::string path = urlDecode(req.target);
    if (!path.empty() && path[0] == '/') path.erase(0, 1);
    auto q = path.find('?');
    if (q != std::string::npos) path = path.substr(0, q);
    auto slash = path.find('/');
    std::string bucket = slash == std::string::npos ? path : path.substr(0, slash);
    std::string key = slash == std::string::npos ? "" : path.substr(slash + 1);
    if (bucket.empty() || key.empty()) {
        LOG_WARN("s3mmc: remote[", clusterId, "] ", req.method, " ", req.target, ": bad resource path -> 400");
        return httpReply(400, "failed", "bad resource path", 0);
    }

    uint64_t contentLength = 0;
    if (auto it = req.headers.find("content-length"); it != req.headers.end())
        contentLength = (uint64_t)std::strtoull(it->second.c_str(), nullptr, 10);
    LOG_DEBUG("s3mmc: remote[", clusterId, "] ", req.method, " ", bucket, "/", key, " content-length ", contentLength);

    if (req.method == "PUT") {
        // spool the body, then route the task
        std::string spool = spoolDir_ + "/put-" + std::to_string((uint64_t)::time(nullptr)) + "-" +
                            std::to_string(taskSeq_.fetch_add(1)) + ".bin";
        uint64_t got = streamBodyToFile(fd, spool, contentLength, (int)opts_.coreTimeoutSec * 1000);
        if (got != contentLength) {
            LOG_ERROR("s3mmc: remote[", clusterId, "] PUT ", bucket, "/", key, ": short body read (",
                      (int64_t)got, "/", contentLength, ") -> 400");
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
        LOG_DEBUG("s3mmc: remote[", clusterId, "] PUT ", bucket, "/", key, " -> task ", spec.id,
                  " repl='", spec.replication, "' meta=", spec.meta.size());
        ServeOutcome out = routeTaskToCluster(clusterId, spec, spool);
        fs::removeFile(spool);
        if (out.ok) {
            LOG_INFO("s3mmc: remote[", clusterId, "] PUT ", bucket, "/", key, " ok (", out.bytesShipped,
                     " bytes, task ", spec.id, ") in ", sw.ms(), " ms");
            return httpReply(200, "ok", "", out.bytesShipped);
        }
        if (out.error.rfind("remote denied", 0) == 0) {
            LOG_WARN("s3mmc: remote[", clusterId, "] PUT ", bucket, "/", key, " denied (task ", spec.id, "): ",
                     out.error, " in ", sw.ms(), " ms");
            return httpReply(403, "denied", out.error, 0);
        }
        LOG_ERROR("s3mmc: remote[", clusterId, "] PUT ", bucket, "/", key, " failed (task ", spec.id, "): ",
                  out.error, " in ", sw.ms(), " ms");
        return httpReply(502, "failed", out.error, 0);
    }
    if (req.method == "DELETE") {
        peer::TaskSpec spec;
        spec.id = newTaskId(opts_.nodeId, taskSeq_);
        spec.origin = opts_.nodeId;
        spec.kind = "delete";
        spec.bucket = bucket;
        spec.key = key;
        LOG_DEBUG("s3mmc: remote[", clusterId, "] DELETE ", bucket, "/", key, " -> task ", spec.id);
        ServeOutcome out = routeTaskToCluster(clusterId, spec, "");
        if (out.ok) {
            LOG_INFO("s3mmc: remote[", clusterId, "] DELETE ", bucket, "/", key, " ok (task ", spec.id, ") in ",
                     sw.ms(), " ms");
            return httpReply(204, "ok", "", 0);
        }
        if (out.error.rfind("remote denied", 0) == 0) {
            LOG_WARN("s3mmc: remote[", clusterId, "] DELETE ", bucket, "/", key, " denied (task ", spec.id, "): ",
                     out.error, " in ", sw.ms(), " ms");
            return httpReply(403, "denied", out.error, 0);
        }
        LOG_ERROR("s3mmc: remote[", clusterId, "] DELETE ", bucket, "/", key, " failed (task ", spec.id, "): ",
                  out.error, " in ", sw.ms(), " ms");
        return httpReply(502, "failed", out.error, 0);
    }
    if (req.method == "GET" || req.method == "HEAD") {
        // serve from local storage through the core
        std::string error;
        if (req.method == "HEAD") {
            LOG_DEBUG("s3mmc: remote[", clusterId, "] HEAD ", bucket, "/", key, " -> 200");
            return httpReply(200, "ok", "", 0); // existence check only
        }
        std::string spool = spoolDir_ + "/get-" + std::to_string((uint64_t)::time(nullptr)) + "-" +
                            std::to_string(taskSeq_.fetch_add(1)) + ".bin";
        if (!coreGetToFile(bucket, key, spool, &error)) {
            LOG_WARN("s3mmc: remote[", clusterId, "] GET ", bucket, "/", key, " -> 404: ", error, " in ", sw.ms(), " ms");
            fs::removeFile(spool);
            return httpReply(404, "failed", error, 0);
        }
        auto sz = fs::fileSize(spool);
        std::ostringstream head;
        head << "HTTP/1.1 200 OK\r\nX-S3MM-Status: ok\r\nContent-Length: " << (sz ? *sz : 0) << "\r\n\r\n";
        writeAllFd(fd, head.str());
        auto body = fs::readFile(spool);
        if (body) writeAllFd(fd, *body);
        else LOG_ERROR("s3mmc: remote[", clusterId, "] GET ", bucket, "/", key, ": cannot read spool ", spool);
        fs::removeFile(spool);
        LOG_INFO("s3mmc: remote[", clusterId, "] GET ", bucket, "/", key, " ok (", sz ? *sz : 0, " bytes) in ",
                 sw.ms(), " ms");
        return ""; // already streamed
    }
    LOG_WARN("s3mmc: remote[", clusterId, "] ", req.method, " ", bucket, "/", key, ": method not supported -> 405");
    return httpReply(405, "failed", "method not supported", 0);
}

// ------------------------------------------------------------ task routing ---

ServeOutcome ClusterClient::routeTaskToCluster(const std::string& clusterId, const peer::TaskSpec& specIn,
                                               const std::string& spoolPath) {
    ServeOutcome out;
    peer::TaskSpec spec = specIn;
    spec.trail.push_back(opts_.nodeId);
    log::Stopwatch sw;
    LOG_DEBUG("s3mmc: routing task ", spec.id, " (", spec.kind, " ", spec.bucket, "/", spec.key, ", ", spec.size,
              " bytes) to cluster '", clusterId, "' trail=", spec.trail.size(), " hops");

    if (ownsCluster(clusterId)) {
        LOG_DEBUG("s3mmc: task ", spec.id, ": cluster '", clusterId, "' is local, applying via core");
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
            LOG_INFO("s3mmc: task ", spec.id, " applied locally on '", clusterId, "' (", spec.kind, " ", spec.bucket,
                     "/", spec.key, ") in ", sw.ms(), " ms");
        } else {
            out.error = error.empty() ? "local apply failed" : error;
            LOG_ERROR("s3mmc: task ", spec.id, " local apply on '", clusterId, "' failed: ", out.error);
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
        LOG_WARN("s3mmc: task ", spec.id, ": no route to cluster '", clusterId, "'");
        return out;
    }
    if (std::find(spec.trail.begin(), spec.trail.end(), hop) != spec.trail.end()) {
        out.error = "remote denied: routing loop via " + hop;
        LOG_WARN("s3mmc: task ", spec.id, ": routing loop via '", hop, "' (trail ", str::join(spec.trail, ","), ")");
        return out;
    }
    LOG_DEBUG("s3mmc: task ", spec.id, ": next hop for '", clusterId, "' is '", hop, "'");

    // ensure the channel to the hop exists
    if (!ensureSession(hop)) {
        out.error = "remote denied: peer '" + hop + "' unreachable";
        LOG_ERROR("s3mmc: task ", spec.id, ": next hop '", hop, "' unreachable");
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
                LOG_DEBUG("s3mmc: task ", spec.id, ": inlining ", *sz, " bytes payload");
            } else {
                LOG_WARN("s3mmc: task ", spec.id, ": cannot read spool ", spoolPath, ", sending without payload");
            }
        } else {
            // large object: ask the destination to pull it from us later
            frame.set("payload", Value::str("pull"));
            LOG_DEBUG("s3mmc: task ", spec.id, ": payload ", sz ? std::to_string(*sz) : std::string("?"),
                      " bytes exceeds threshold, destination will pull");
        }
    }

    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        taskNextHop_[spec.id] = hop;
    }

    std::string serr = sendOnPeer(hop, frame);
    if (!serr.empty()) {
        out.error = "remote denied: forward to '" + hop + "' failed: " + serr;
        LOG_ERROR("s3mmc: task ", spec.id, ": forward to '", hop, "' failed: ", serr);
        return out;
    }
    LOG_DEBUG("s3mmc: task ", spec.id, " forwarded to '", hop, "', awaiting verdict (", opts_.coreTimeoutSec, "s)");

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
                LOG_ERROR("s3mmc: task ", spec.id, ": timeout awaiting verdict from '", hop, "' after ", sw.ms(), " ms");
                return out;
            }
            auto it = verdicts_.find(spec.id);
            if (it != verdicts_.end()) {
                res = it->second;
                verdicts_.erase(it);
                have = true;
            }
        }
        if (!have || !running_.load()) {
            out.error = "remote denied: session closed";
            LOG_WARN("s3mmc: task ", spec.id, ": session closed while awaiting verdict from '", hop, "'");
            return out;
        }
        if (res.status == "ok") {
            out.ok = true;
            out.bytesShipped = res.bytesShipped;
            LOG_INFO("s3mmc: task ", spec.id, " to '", clusterId, "' via '", hop, "': ok by ", res.node, " (",
                     res.bytesShipped, " bytes) in ", sw.ms(), " ms");
            return out;
        }
        out.error = "remote denied: " + (res.reason.empty() ? res.status : res.reason);
        LOG_WARN("s3mmc: task ", spec.id, " to '", clusterId, "' via '", hop, "': ", res.status, " by ", res.node,
                 ": ", res.reason, " in ", sw.ms(), " ms");
        return out;
    }
}

// ------------------------------------------- socket provisioning (requiredOnly) --

std::vector<std::string> ClusterClient::requiredClustersLocked() {
    // Foreign clusters referenced by our own replication rules. The core owns
    // the truth; we ask it over the control socket and cache briefly so the
    // poll loop does not hammer it.
    static std::mutex cacheMu;
    static int64_t cacheAt = 0;
    static std::vector<std::string> cache;
    int64_t now = nowSec();
    {
        std::lock_guard<std::mutex> lk(cacheMu);
        if (!cache.empty() && now - cacheAt < 5) return cache;
    }
    std::vector<std::string> out;
    Value req = Value::object();
    req.set("cmd", Value::str("cluster-required"));
    Value reply = Value::object();
    if (coreCall(req, -1, &reply) && reply.isObject()) {
        const Value* arr = reply.find("clusters");
        if (arr && arr->isArray())
            for (const auto& e : arr->items())
                if (e.isString() && !ownsClusterLocked(e.asString()))
                    out.push_back(e.asString());
        LOG_DEBUG("s3mmc: core reports ", out.size(), " required foreign clusters: ", str::join(out, ","));
    } else {
        LOG_WARN("s3mmc: cannot query required clusters from core, using cached list");
    }
    std::lock_guard<std::mutex> lk(cacheMu);
    if (!out.empty() || cache.empty()) { cache = out; cacheAt = now; }
    return cache;
}

Result<void> ClusterClient::ensureRemoteSocket(const std::string& clusterId) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    if (ownsClusterLocked(clusterId)) {
        LOG_DEBUG("s3mmc: ensureRemoteSocket: cluster '", clusterId, "' is owned locally, no socket");
        return Result<void>::failure("cluster '" + clusterId + "' is owned locally");
    }
    if (remoteFds_.count(clusterId)) return Result<void>::success();
    std::string path = opts_.runDir + "/" + opts_.nodeId + "/remote-" + clusterId + ".sock";
    fs::mkdirp(opts_.runDir + "/" + opts_.nodeId);
    int fd = bindUnixListener(path);
    if (fd < 0) {
        LOG_ERROR("s3mmc: cannot provision remote[", clusterId, "] socket ", path);
        return Result<void>::failure("cannot bind " + path);
    }
    remoteFds_[clusterId] = fd;
    if (running_.load())
        std::thread([this, fd, clusterId] { unixAcceptLoop(fd, clusterId); }).detach();
    LOG_INFO("s3mmc: provisioned UNIX socket ", path,
             running_.load() ? "" : " (pending start)");
    return Result<void>::success();
}

// --------------------------------------------------------------- peer frames ---

peer::Inventory ClusterClient::filteredInventoryFor(const std::string& peerId) const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    // Managers always ignore ACLs and receive the full snapshot.
    if (isManagerOf(peerId)) {
        LOG_DEBUG("s3mmc: visibility for '", peerId, "': manager, full inventory");
        return localInv_;
    }
    // Effective element filter for this peer: per-peer ACL entry when one
    // exists, otherwise nothing is disclosed to non-managers unless an
    // explicit global expose list was configured (legacy `expose <list>;`).
    const Options::PeerAcl* acl = aclForLocked(peerId);
    static const std::vector<std::string> kNone{"none"};
    static const std::vector<std::string> kAll{"*"};
    std::vector<std::string> legacyGlobal;
    for (const auto& r : opts_.exposeRules)
        if (r.appliesTo == "unmanaged") legacyGlobal.push_back(r.spec);
    const std::vector<std::string>* patPtr = &kNone;
    if (acl) patPtr = &acl->elements;
    else if (!legacyGlobal.empty()) {
        auto el = parseExposeList(legacyGlobal.front());
        static thread_local std::vector<std::string> cache;
        if (el) { cache = el.value(); patPtr = &cache; }
    }
    const std::vector<std::string>& pat = *patPtr;
    LOG_DEBUG("s3mmc: visibility for '", peerId, "': ", acl ? "acl '" + acl->pattern + "'" : legacyGlobal.empty() ? std::string("default none") : std::string("legacy global"),
              " elements=[", str::join(pat, ","), "]");
    auto on = [&](const char* name) { return glob::matchFilter(pat, name); };
    peer::Inventory out;
    out.nodeId = localInv_.nodeId;
    out.revision = localInv_.revision;         // keep merge freshness comparable
    out.generatedAtSec = localInv_.generatedAtSec;
    bool wantClusters = on("clusters") || on("endpoints") || on("zones") || on("aliases");
    if (wantClusters) {
        bool fullClusters = on("clusters");
        for (const auto& c : localInv_.clusters) {
            peer::InventoryCluster cc = c;
            if (!fullClusters) {
                if (!on("endpoints")) cc.endpoints.clear();
                if (!on("zones")) cc.zone.clear();
                if (!on("aliases")) { cc.alias.clear(); cc.vendor.clear(); }
            }
            out.clusters.push_back(std::move(cc));
        }
    }
    if (on("replications")) out.replications = localInv_.replications;
    if (on("local_clusters")) out.localClusters = localInv_.localClusters;
    LOG_DEBUG("s3mmc: disclosing to '", peerId, "': ", out.clusters.size(), "/", localInv_.clusters.size(),
              " clusters, ", out.replications.size(), "/", localInv_.replications.size(), " replications, ",
              out.localClusters.size(), "/", localInv_.localClusters.size(), " local clusters");
    return out;
}

const ClusterClient::Options::PeerAcl* ClusterClient::aclForLocked(const std::string& peerId) const {
    if (opts_.peerAcls.empty()) return nullptr;
    const Options::PeerAcl* best = nullptr;
    for (const auto& a : opts_.peerAcls) {
        if (a.pattern == "all" || glob::match(a.pattern, peerId)) {
            // peerAcls is sorted by priority ascending, then line ascending;
            // first match wins.
            LOG_DEBUG("s3mmc: ACL for '", peerId, "' matched pattern '", a.pattern, "' priority ", a.priority);
            best = &a;
            break;
        }
    }
    if (!best) LOG_DEBUG("s3mmc: no ACL entry matches '", peerId, "'");
    return best;
}

Result<void> ClusterClient::compilePeerAcls(Options& opts) {
    std::vector<Options::PeerAcl> out;
    bool sawScoped = false;
    for (const auto& r : opts.exposeRules) {
        if (r.appliesTo != "unmanaged") sawScoped = true;
    }
    for (size_t i = 0; i < opts.exposeRules.size(); ++i) {
        const auto& r = opts.exposeRules[i];
        // Legacy bare `expose <list>;` rules (appliesTo == "unmanaged") are
        // ALSO compiled into a catch-all ACL so that scoped rules can override
        // them by priority; but only when at least one scoped rule exists —
        // otherwise the old global-filter path stays in effect unchanged.
        if (!sawScoped && r.appliesTo == "unmanaged") continue;
        auto el = parseExposeList(r.spec);
        if (!el) {
            LOG_ERROR("s3mmc: expose rule (line ", r.line, ") '", r.spec, "': ", el.error());
            return Result<void>::failure(el.error());
        }
        Options::PeerAcl a;
        a.pattern = (r.appliesTo == "unmanaged") ? "*" : r.appliesTo;
        a.priority = r.order * 1000 + (int)i;   // explicit order dominates, file order breaks ties
        a.elements = el.value();
        out.push_back(std::move(a));
    }
    std::stable_sort(out.begin(), out.end(), [](const Options::PeerAcl& x, const Options::PeerAcl& y) {
        return x.priority < y.priority;
    });
    opts.peerAcls = std::move(out);
    for (const auto& a : opts.peerAcls)
        LOG_DEBUG("s3mmc: ACL pattern '", a.pattern, "' priority ", a.priority, " elements=[", str::join(a.elements, ","), "]");
    LOG_DEBUG("s3mmc: compiled ", opts.peerAcls.size(), " peer ACL entries from ", opts.exposeRules.size(),
              " expose rules", sawScoped ? "" : " (legacy global mode)");
    return Result<void>::success();
}

Value ClusterClient::buildHelloFrame(const std::string& forPeer) {
    Value f = Value::object();
    f.set("type", Value::str("hello"));
    f.set("from", Value::str(opts_.nodeId));
    f.set("version", Value::number((int64_t)s3mm::peer::kProtocolVersion));
    f.set("inventory", filteredInventoryFor(forPeer).toJson());
    return f;
}

Value ClusterClient::buildInventoryFrame(const std::string& forPeer) {
    Value f = Value::object();
    f.set("type", Value::str("inventory"));
    f.set("from", Value::str(opts_.nodeId));
    f.set("inventory", filteredInventoryFor(forPeer).toJson());
    return f;
}

std::string ClusterClient::sendOnPeer(const std::string& peerId, const Value& frame) {
    std::shared_ptr<Channel> ch;
    std::mutex* sm = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        if (it == peers_.end() || !it->second.connected || !it->second.channel) {
            LOG_WARN("s3mmc: cannot send '", frame.getString("type"), "' to '", peerId, "': not connected");
            return "peer '" + peerId + "' not connected";
        }
        ch = it->second.channel;
        sm = &it->second.sendMutex;
    }
    std::lock_guard<std::mutex> slk(*sm);
    auto r = ch->send(frame);
    if (!r) LOG_ERROR("s3mmc: send '", frame.getString("type"), "' to '", peerId, "' failed: ", r.error());
    else LOG_DEBUG("s3mmc: sent '", frame.getString("type"), "' to '", peerId, "'");
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
    LOG_DEBUG("s3mmc: frame '", type, "' from '", peerId, "'", from != peerId && !from.empty() ? " (from=" + from + ")" : "",
              " id=", frame.getString("id"));
    if (type == "hello") return {onHello(peerId, frame, ch)};
    if (type == "inventory") { onInventory(peerId, frame); return {}; }
    if (type == "inventory_req") return {buildInventoryFrame(peerId)};
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
    if (type == "pong") return {};
    if (type == "error") {
        LOG_ERROR("s3mmc: peer '", peerId, "' reported error: ", frame.getString("reason"));
        return {};
    }
    LOG_WARN("s3mmc: unknown frame type '", type, "' from '", peerId, "' ignored");
    return {};
}

Value ClusterClient::onHello(const std::string& peerId, const Value& frame, std::shared_ptr<Channel> ch) {
    std::string theirNode = frame.getString("from");
    bool dialectOk = frame.find("version") && frame.find("version")->asInt(0) == s3mm::peer::kProtocolVersion;
    if (!dialectOk) {
        LOG_ERROR("s3mmc: hello from '", peerId, "' (node '", theirNode, "'): protocol version mismatch (theirs ",
                  frame.find("version") ? frame.find("version")->asInt(0) : -1, ", ours ", s3mm::peer::kProtocolVersion, ")");
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
        } else {
            LOG_DEBUG("s3mmc: hello from unconfigured peer '", peerId, "'");
        }
    }
    LOG_INFO("s3mmc: hello from '", peerId, "' (node '", theirNode, "')");
    if (frame.find("inventory")) {
        auto inv = peer::Inventory::fromJson(*frame.find("inventory"));
        if (inv) applyInventoryFrom(peerId, inv.value());
        else LOG_WARN("s3mmc: hello from '", peerId, "' carries bad inventory: ", inv.error());
    }
    return buildHelloFrame(peerId);
}

void ClusterClient::onInventory(const std::string& peerId, const Value& frame) {
    if (!frame.find("inventory")) {
        LOG_WARN("s3mmc: inventory frame from '", peerId, "' without inventory");
        return;
    }
    auto inv = peer::Inventory::fromJson(*frame.find("inventory"));
    if (inv) applyInventoryFrom(peerId, inv.value());
    else LOG_WARN("s3mmc: bad inventory from '", peerId, "': ", inv.error());
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
        PeerRuntime& rt = peers_[peerId];
        rt.cfg = cfg;
        it = peers_.find(peerId);
        LOG_INFO("s3mmc: adopted discovered peer '", peerId, "'");
    }
    if (it->second.hasInventory && it->second.inventory.revision == inv.revision)
        LOG_DEBUG("s3mmc: inventory of '", peerId, "' unchanged (rev ", inv.revision, ")");
    else
        LOG_INFO("s3mmc: inventory from '", peerId, "' rev ", inv.revision, ": ", inv.clusters.size(), " clusters, ",
                 inv.replications.size(), " replications, ", inv.localClusters.size(), " local clusters");
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
        LOG_ERROR("s3mmc: malformed task from '", peerId, "': ", specR.error());
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
            LOG_DEBUG("s3mmc: task ", spec.id, " from '", peerId, "' is a duplicate, acking");
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
        LOG_WARN("s3mmc: task ", spec.id, " from '", peerId, "' denied: routing loop (trail ",
                 str::join(spec.trail, ","), ")");
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
    log::Stopwatch sw;
    LOG_INFO("s3mmc: task ", spec.id, " from '", peerId, "': ", spec.kind, " ", spec.bucket, "/", spec.key, " (",
             spec.size, " bytes) -> cluster '", destCluster, "' origin ", spec.origin);
    if (const Value* d = frame.find("data"); d && d->isObject()) {
        if (const Value* b64 = d->find("b64"); b64 && b64->isString()) {
            auto body = crypto::base64Decode(b64->asString());
            if (body) {
                FILE* fp = std::fopen(spool.c_str(), "wb");
                if (fp) {
                    std::fwrite(body->data(), 1, body->size(), fp);
                    std::fclose(fp);
                    haveData = true;
                    LOG_DEBUG("s3mmc: task ", spec.id, ": inline payload ", body->size(), " bytes -> ", spool);
                } else {
                    LOG_ERROR("s3mmc: task ", spec.id, ": cannot write spool ", spool, ": ", std::strerror(errno));
                }
            } else {
                LOG_ERROR("s3mmc: task ", spec.id, ": inline payload is not valid base64");
            }
        }
    }
    if (spec.kind == "object" && !haveData) {
        LOG_DEBUG("s3mmc: task ", spec.id, ": pulling payload from '", peerId, "'");
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
            LOG_ERROR("s3mmc: task ", spec.id, ": payload pull request to '", peerId, "' failed: ", serr);
            res.status = "failed";
            res.reason = "payload pull failed: " + serr;
        } else {
            // wait for object_data to land (bounded)
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(opts_.coreTimeoutSec);
            std::unique_lock<std::mutex> lk(waitMutex_);
            bool arrived = waitCv_.wait_until(lk, deadline, [&] { return fileExists(spool); });
            if (arrived) {
                haveData = true;
                LOG_DEBUG("s3mmc: task ", spec.id, ": payload pulled in ", sw.ms(), " ms");
            } else {
                LOG_ERROR("s3mmc: task ", spec.id, ": payload pull from '", peerId, "' timed out after ", sw.ms(), " ms");
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
    if (res.status == "ok")
        LOG_INFO("s3mmc: task ", spec.id, " from '", peerId, "' -> ok (", res.bytesShipped, " bytes) in ", sw.ms(), " ms");
    else
        LOG_WARN("s3mmc: task ", spec.id, " from '", peerId, "' -> ", res.status, ": ", res.reason, " in ", sw.ms(), " ms");

    Value f = Value::object();
    f.set("type", Value::str("task_result"));
    f.set("from", Value::str(opts_.nodeId));
    f.set("result", res.toJson());
    fs::removeFile(spool);
    return f;
}

void ClusterClient::onTaskResult(const std::string& peerId, const Value& frame) {
    if (!frame.find("result")) {
        LOG_WARN("s3mmc: task_result from '", peerId, "' without result");
        return;
    }
    auto resR = peer::TaskResult::fromJson(*frame.find("result"));
    if (!resR) {
        LOG_WARN("s3mmc: bad task_result from '", peerId, "': ", resR.error());
        return;
    }
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
        LOG_DEBUG("s3mmc: relaying verdict ", res.status, " of task ", res.taskId, " from '", peerId, "' to '", nextHop, "'");
        std::string serr = sendOnPeer(nextHop, f);
        if (!serr.empty())
            LOG_ERROR("s3mmc: relaying verdict of task ", res.taskId, " to '", nextHop, "' failed: ", serr);
        return;
    }
    LOG_DEBUG("s3mmc: verdict ", res.status, " for own task ", res.taskId, " from '", peerId, "'");
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
    LOG_DEBUG("s3mmc: object_req ", frame.getString("id"), " from '", peerId, "' for ", bucket, "/", key);
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
            LOG_ERROR("s3mmc: object_req ", bucket, "/", key, " from '", peerId, "': object too large for inline transfer (",
                      sz ? std::to_string(*sz) : std::string("?"), " bytes, threshold ", opts_.spoolThresholdBytes, ")");
            f.set("status", Value::str("failed"));
            f.set("error", Value::str("object too large for inline transfer"));
            fs::removeFile(spool);
            return f;
        }
        f.set("data", data);
        f.set("status", Value::str("ok"));
        fs::removeFile(spool);
        LOG_INFO("s3mmc: object_req ", bucket, "/", key, " from '", peerId, "' served (", *sz, " bytes)");
    } else {
        LOG_ERROR("s3mmc: object_req ", bucket, "/", key, " from '", peerId, "': core GET failed: ", error);
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
                        LOG_DEBUG("s3mmc: object_data for task ", taskId, " from '", peerId, "': ", body->size(), " bytes");
                    } else {
                        LOG_ERROR("s3mmc: object_data for task ", taskId, ": cannot write ", spool, ": ", std::strerror(errno));
                    }
                } else {
                    LOG_ERROR("s3mmc: object_data for task ", taskId, " from '", peerId, "': invalid base64");
                }
            }
        } else {
            LOG_WARN("s3mmc: object_data for task ", taskId, " from '", peerId, "' has no data");
        }
    } else {
        LOG_WARN("s3mmc: object_data for task ", taskId, " from '", peerId, "' failed: ", frame.getString("error"));
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
    if (!isManagerOf(peerId)) {
        LOG_WARN("s3mmc: config_get from '", peerId, "' denied: not a manager");
        return makeManagerReply("config_response", frame, false, "denied",
                                "remote denied: not a manager of " + opts_.nodeId, nullptr);
    }
    std::string text, err;
    if (!currentConfigText(&text, &err)) {
        LOG_ERROR("s3mmc: config_get from '", peerId, "' failed: ", err);
        return makeManagerReply("config_response", frame, false, "failed", err, nullptr);
    }
    LOG_INFO("s3mmc: config sent to manager '", peerId, "' (", text.size(), " bytes)");
    Value res = Value::object();
    res.set("filename", Value::str(configPath_));
    res.set("text", Value::str(text));
    return makeManagerReply("config_response", frame, true, "ok", "", &res);
}

Value ClusterClient::onConfigSet(const std::string& peerId, const Value& frame) {
    if (!isManagerOf(peerId)) {
        LOG_WARN("s3mmc: config_set from '", peerId, "' denied: not a manager");
        return makeManagerReply("config_ack", frame, false, "denied",
                                "remote denied: not a manager of " + opts_.nodeId, nullptr);
    }
    const Value* res = frame.find("result");
    if (!res || !res->isString()) {
        LOG_WARN("s3mmc: malformed config_set from '", peerId, "'");
        return makeManagerReply("config_ack", frame, false, "denied", "malformed config_set", nullptr);
    }
    auto r = applyConfigTextFrom(res->asString(), frame.getString("filename"), peerId);
    if (!r) {
        LOG_ERROR("s3mmc: config_set from '", peerId, "' failed: ", r.error());
        return makeManagerReply("config_ack", frame, false, "failed", r.error(), nullptr);
    }
    LOG_NOTICE("s3mmc: configuration replaced by manager '", peerId, "'");
    return makeManagerReply("config_ack", frame, true, "ok", "", nullptr);
}

Value ClusterClient::onCredRequest(const std::string& peerId, const Value& frame) {
    // Credential export is permitted for managers (always) and for peers whose
    // visibility ACL explicitly grants the `credentials` element.
    bool aclGrants = false;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        const Options::PeerAcl* acl = aclForLocked(peerId);
        if (acl) aclGrants = glob::matchFilter(acl->elements, "credentials");
        else for (const auto& r : opts_.exposeRules) {
            if (r.appliesTo != "unmanaged") continue;
            auto el = parseExposeList(r.spec);
            if (el && glob::matchFilter(el.value(), "credentials")) { aclGrants = true; break; }
        }
    }
    bool manager = isManagerOf(peerId);
    bool allowed = manager || aclGrants;
    LOG_DEBUG("s3mmc: cred_request from '", peerId, "': manager=", manager, " acl_grants=", aclGrants);
    if (!allowed) {
        LOG_WARN("s3mmc: cred_request from '", peerId, "' denied: credential export not permitted");
        return makeManagerReply("cred_response", frame, false, "denied",
                                "remote denied: credential export not permitted for '" +
                                    peerId + "'", nullptr);
    }
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
            if (!content) {
                LOG_WARN("s3mmc: cannot read sealed credential ", fs::joinPath(secretsDir_, name));
                continue;
            }
            LOG_DEBUG("s3mmc: exporting sealed credential '", name, "' (", log::redact(*content), ")");
            Value item = Value::object();
            item.set("name", Value::str(name));
            item.set("sealed", Value::str(*content));
            arr.push(item);
        }
    }
    else LOG_WARN("s3mmc: secrets dir ", secretsDir_, " does not exist, exporting nothing");
    LOG_INFO("s3mmc: exported ", arr.items().size(), " sealed credential blocks to '", peerId, "'",
             filter.empty() ? "" : " (filter '", filter, filter.empty() ? "" : "')");
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
        if (it == pendingReqs_.end()) {
            LOG_WARN("s3mmc: ", frame.getString("type"), " from '", peerId, "' for unknown/expired request '", id, "'");
            return;
        }
        waiter = it->second;
        pendingReqs_.erase(it);
    }
    {
        std::lock_guard<std::mutex> lk(waiter->mu);
        waiter->reply = frame;
        waiter->done = true;
    }
    LOG_DEBUG("s3mmc: ", frame.getString("type"), " ", id, " from '", peerId, "': ", frame.getString("status"));
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
    return Result<std::string>(res->asString());
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
    return Result<Value>(*res);
}

// ------------------------------------------------------------------- loops ---

void ClusterClient::controlLoop() {
    LOG_DEBUG("s3mmc: control loop started on ", controlPath_);
    while (running_.load()) {
        pollfd p{controlFd_, POLLIN, 0};
        if (::poll(&p, 1, 500) <= 0) continue;
        int client = ::accept(controlFd_, nullptr, nullptr);
        if (client < 0) {
            if (running_.load()) LOG_WARN("s3mmc: control accept failed: ", std::strerror(errno));
            continue;
        }
        { uid_t u = 0; gid_t g = 0; pid_t pid = 0;
          if (peerCredentials(client, u, g, pid))
              LOG_DEBUG("s3mmc: control connection fd ", client, " uid=", u, " gid=", g, " pid=", pid); }
        std::thread([this, client] {
            std::string line;
            if (!readLineFd(client, line, 5000)) {
                LOG_WARN("s3mmc: control fd ", client, ": no request received");
                ::close(client);
                return;
            }
            log::Stopwatch sw;
            std::string err;
            auto req = Value::parseJson(line, &err);
            Value reply = Value::object();
            if (req.isObject())
                LOG_INFO("s3mmc: control command '", req.getString("cmd"), "'",
                         req.getString("peer").empty() ? "" : " peer=", req.getString("peer"),
                         req.getString("id").empty() ? "" : " id=", req.getString("id"));
            if (!err.empty() || !req.isObject()) {
                LOG_WARN("s3mmc: malformed control request: ", err.empty() ? "not an object" : err,
                         " (", log::clip(line, 128), ")");
                reply.set("ok", Value::boolean(false));
                reply.set("error", Value::str("malformed control request"));
            } else if (req.getString("cmd") == "status") {
                reply = statusValue();
                reply.set("ok", Value::boolean(true));
            } else if (req.getString("cmd") == "visibility") {
                std::string peer = req.getString("peer");
                reply = Value::object();
                if (peer.empty()) {
                    reply.set("ok", Value::boolean(false));
                    reply.set("error", Value::str("visibility: \"peer\" field required"));
                } else {
                    reply = describeVisibility(peer);
                    reply.set("ok", Value::boolean(true));
                }
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
            } else if (req.getString("cmd") == "peers") {
                // Full peer table: direction, link state, CN, managed flag.
                reply = Value::object();
                reply.set("ok", Value::boolean(true));
                Value arr = Value::array();
                std::lock_guard<std::recursive_mutex> lk(mutex_);
                for (const auto& [id, pr] : peers_) {
                    Value pv = Value::object();
                    pv.set("id", Value::str(id));
                    pv.set("address", Value::str(pr.cfg.address));
                    pv.set("direction", Value::str(pr.direction));
                    pv.set("connected", Value::boolean(pr.connected));
                    pv.set("cn", Value::str(pr.peerCN));
                    pv.set("managed_by_us", Value::boolean(isManagerOf(id)));
                    pv.set("inventory_revision",
                          Value::number(pr.hasInventory ? (int64_t)pr.inventory.revision : 0));
                    arr.push(pv);
                }
                reply.set("peers", arr);
                Value mg = Value::array();
                for (const auto& m : opts_.managedNodes) mg.push(Value::str(m));
                reply.set("managed", mg);
            } else if (req.getString("cmd") == "add-peer") {
                PeerConfig pc;
                pc.id = req.getString("id");
                pc.address = req.getString("address");
                if (const Value* c = req.find("dial"); c && c->type() == Value::Type::Bool) pc.dial = c->asBool(true);
                if (pc.id.empty() || pc.address.empty()) {
                    reply.set("ok", Value::boolean(false));
                    reply.set("error", Value::str("add-peer: \"id\" and \"address\" required"));
                } else {
                    auto r = addPeer(pc);
                    reply.set("ok", Value::boolean(static_cast<bool>(r)));
                    if (!r) reply.set("error", Value::str(r.error()));
                }
            } else if (req.getString("cmd") == "remove-peer") {
                auto r = removePeer(req.getString("id"));
                reply.set("ok", Value::boolean(static_cast<bool>(r)));
                if (!r) reply.set("error", Value::str(r.error()));
            } else if (req.getString("cmd") == "set-managed") {
                // Replace the managed list live. Persistence is the operator's
                // job (edit s3mmc.conf or push it via push-config), because a
                // manager may rewrite the whole file anyway.
                const Value* lst = req.find("nodes");
                if (!lst || !lst->isArray()) {
                    reply.set("ok", Value::boolean(false));
                    reply.set("error", Value::str("set-managed: \"nodes\" array required"));
                } else {
                    std::vector<std::string> nodes;
                    for (const auto& v : lst->items()) nodes.push_back(v.asString());
                    auto cur = options();
                    cur.managedNodes = nodes;
                    auto r = configure(cur, tls_);
                    reply.set("ok", Value::boolean(static_cast<bool>(r)));
                    if (!r) reply.set("error", Value::str(r.error()));
                }
            } else if (req.getString("cmd") == "sync-inventory") {
                // Force one inventory exchange round immediately.
                if (opts_.pollModel == "pull" || opts_.pollModel == "both") {
                    std::vector<std::pair<std::string, std::shared_ptr<Channel>>> targets;
                    {
                        std::lock_guard<std::recursive_mutex> lk(mutex_);
                        for (auto& [id, rt] : peers_)
                            if (rt.connected && rt.channel && rt.direction == "out")
                                targets.emplace_back(id, rt.channel);
                    }
                    Value req2 = Value::object();
                    req2.set("type", Value::str("inventory_req"));
                    req2.set("from", Value::str(opts_.nodeId));
                    for (auto& [id, ch] : targets) {
                        std::lock_guard<std::recursive_mutex> lk(mutex_);
                        auto it = peers_.find(id);
                        if (it == peers_.end()) continue;
                        std::lock_guard<std::mutex> slk(it->second.sendMutex);
                        if (auto sr = ch->send(req2); !sr)
                            LOG_WARN("s3mmc: forced inventory_req to '", id, "' failed: ", sr.error());
                    }
                    LOG_INFO("s3mmc: forced inventory sync: requested from ", targets.size(), " peers");
                } else {
                    LOG_DEBUG("s3mmc: sync-inventory: poll model '", opts_.pollModel, "' does not pull");
                }
                reply = statusValue();
                reply.set("ok", Value::boolean(true));
            } else if (req.getString("cmd") == "pull-config") {
                auto r = pullPeerConfig(req.getString("peer"));
                reply.set("ok", Value::boolean(static_cast<bool>(r)));
                if (r) reply.set("text", Value::str(r.value()));
                else reply.set("error", Value::str(r.error()));
            } else if (req.getString("cmd") == "push-config") {
                std::string peer = req.getString("peer");
                std::string text = req.getString("text");
                std::string filename = req.getString("filename");
                if (filename.empty()) filename = "s3mmc.conf";
                LOG_DEBUG("s3mmc: push-config to '", peer, "' (", text.size(), " bytes, ", filename, ")");
                if (peer.empty() || text.empty()) {
                    reply.set("ok", Value::boolean(false));
                    reply.set("error", Value::str("push-config: \"peer\" and \"text\" required"));
                } else {
                    auto r = pushPeerConfig(peer, text, filename);
                    reply.set("ok", Value::boolean(static_cast<bool>(r)));
                    if (!r) reply.set("error", Value::str(r.error()));
                }
            } else if (req.getString("cmd") == "request-creds") {
                auto r = pullPeerCredentials(req.getString("peer"), req.getString("cluster"));
                reply.set("ok", Value::boolean(static_cast<bool>(r)));
                if (r) reply.set("credentials", *r.value().find("credentials"));
                else reply.set("error", Value::str(r.error()));
            } else {
                LOG_WARN("s3mmc: unknown control command '", req.getString("cmd"), "'");
                reply.set("ok", Value::boolean(false));
                reply.set("error", Value::str("unknown command: " + req.getString("cmd")));
            }
            if (const Value* ok = reply.find("ok"); ok && !ok->asBool(false))
                LOG_WARN("s3mmc: control command '", req.getString("cmd"), "' failed: ", reply.getString("error"));
            std::string out = reply.toJson() + "\n";
            if (!writeAllFd(client, out)) LOG_WARN("s3mmc: control reply write failed");
            else LOG_DEBUG("s3mmc: control reply ", out.size(), " bytes in ", sw.ms(), " ms");
            ::close(client);
        }).detach();
    }
    LOG_DEBUG("s3mmc: control loop finished");
}

void ClusterClient::acceptLoop() {
    LOG_DEBUG("s3mmc: peer accept loop started");
    while (running_.load()) {
        pollfd p{peerListenFd_, POLLIN, 0};
        if (::poll(&p, 1, 500) <= 0) continue;
        sockaddr_storage ss{};
        socklen_t sl = sizeof(ss);
        int client = ::accept(peerListenFd_, reinterpret_cast<sockaddr*>(&ss), &sl);
        if (client < 0) {
            if (running_.load()) LOG_WARN("s3mmc: peer accept failed: ", std::strerror(errno));
            continue;
        }
        std::string remote = "?";
        {
            char ip[INET6_ADDRSTRLEN] = "?";
            int rport = 0;
            if (ss.ss_family == AF_INET) {
                auto* a = reinterpret_cast<sockaddr_in*>(&ss);
                ::inet_ntop(AF_INET, &a->sin_addr, ip, sizeof ip);
                rport = ntohs(a->sin_port);
            } else if (ss.ss_family == AF_INET6) {
                auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
                ::inet_ntop(AF_INET6, &a->sin6_addr, ip, sizeof ip);
                rport = ntohs(a->sin6_port);
            }
            remote = std::string(ip) + ":" + std::to_string(rport);
        }
        LOG_DEBUG("s3mmc: inbound peer connection from ", remote, " fd ", client);
        auto chR = makeTlsChannel(client, /*clientRole=*/false, tls_.certFile, tls_.keyFile, tls_.caFile);
        if (!chR) {
            LOG_WARN("s3mmc: inbound TLS handshake from ", remote, " failed: ", chR.error());
            ::close(client);
            continue;
        }
        LOG_INFO("s3mmc: inbound peer session from ", remote, " (CN '", tlsPeerCommonName(chR.value()), "')");
        std::thread([this, ch = chR.value()] { sessionLoop(ch, "", false); }).detach();
    }
    LOG_DEBUG("s3mmc: peer accept loop finished");
}

void ClusterClient::sessionLoop(std::shared_ptr<Channel> ch, std::string peerIdHint, bool dialed) {
    std::string peerId = peerIdHint;
    LOG_DEBUG("s3mmc: session loop started (", dialed ? "outbound" : "inbound", ", peer '", peerId, "')");
    uint64_t frames = 0;
    // outbound side sends hello first; inbound side answers hellos
    if (dialed) {
        Value hello = buildHelloFrame(peerId);
        auto sr = ch->send(hello);
        if (!sr) {
            LOG_ERROR("s3mmc: hello to '", peerId, "' failed: ", sr.error());
            dropSessionByChannel(ch, "hello send failed");
            return;
        }
    }
    for (;;) {
        if (!running_.load()) break;
        auto fr = ch->recv();
        if (!fr) {
            LOG_WARN("s3mmc: session with '", peerId, "' (", dialed ? "out" : "in", ") ended after ", frames,
                     " frames: ", fr.error());
            dropSessionByChannel(ch, fr.error());
            break;
        }
        ++frames;
        const Value& frame = fr.value();
        std::string type = frame.getString("type");
        std::string from = frame.getString("from");
        if (peerId.empty() && !from.empty()) {
            peerId = from;
            std::string cn = tlsPeerCommonName(ch);
            if (!cn.empty() && cn != peerId)
                LOG_WARN("s3mmc: inbound session identifies as '", peerId, "' but certificate CN is '", cn, "'");
            LOG_INFO("s3mmc: inbound session identified as peer '", peerId, "' (CN '", cn, "')");
            // adopt/confirm the runtime entry for this session
            std::lock_guard<std::recursive_mutex> lk(mutex_);
            auto it = peers_.find(peerId);
            if (it == peers_.end()) {
                LOG_INFO("s3mmc: adopting unconfigured inbound peer '", peerId, "'");
                PeerConfig cfg;
                cfg.id = peerId;
                cfg.address = "inbound";
                cfg.dial = false;
                PeerRuntime& rt = peers_[peerId];
                rt.cfg = cfg;
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
            Result<void> sr = Result<void>::success();
            if (sm) {
                std::lock_guard<std::mutex> slk(*sm);
                sr = ch->send(r);
            } else {
                sr = ch->send(r);
            }
            if (!sr) LOG_WARN("s3mmc: reply '", r.getString("type"), "' to '", peerId, "' failed: ", sr.error());
            else LOG_DEBUG("s3mmc: replied '", r.getString("type"), "' to '", peerId, "' (for '", type, "')");
        }
        (void)type;
    }
    LOG_DEBUG("s3mmc: session loop with '", peerId, "' finished");
}

void ClusterClient::dropSession(const std::string& peerId, const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    auto it = peers_.find(peerId);
    if (it == peers_.end()) {
        LOG_DEBUG("s3mmc: dropSession: unknown peer '", peerId, "' (", reason, ")");
        return;
    }
    if (it->second.connected) LOG_WARN("s3mmc: peer '", peerId, "' disconnected: ", reason);
    else LOG_DEBUG("s3mmc: peer '", peerId, "' still down: ", reason);
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
            LOG_WARN("s3mmc: peer '", id, "' (", rt.direction, ") disconnected: ", reason, " (reconnects ",
                     rt.reconnects + 1, ")");
            rt.connected = false;
            rt.channel.reset();
            rt.lastError = reason;
            rt.lastErrorSec = nowSec();
            rt.reconnects++;
            return;
        }
    }
    LOG_DEBUG("s3mmc: session closed (no peer bound to channel): ", reason);
}

bool ClusterClient::ensureSession(const std::string& peerId) {
    std::shared_ptr<Channel> existing;
    PeerConfig cfg;
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        if (it == peers_.end()) {
            LOG_WARN("s3mmc: ensureSession: unknown peer '", peerId, "'");
            return false;
        }
        if (it->second.connected && it->second.channel) return true;
        cfg = it->second.cfg;
    }
    // dial: host:port
    auto colon = cfg.address.rfind(':');
    if (colon == std::string::npos) {
        LOG_DEBUG("s3mmc: peer '", peerId, "' address '", cfg.address, "' is not dialable");
        return false;
    }
    std::string host = cfg.address.substr(0, colon);
    int port = std::atoi(cfg.address.substr(colon + 1).c_str());
    log::Stopwatch sw;
    LOG_DEBUG("s3mmc: dialing peer '", peerId, "' at ", host, ":", port, " (timeout ", cfg.connectTimeoutSec, "s)");
    int fd = connectTcp(host, port, cfg.connectTimeoutSec);
    if (fd < 0) {
        LOG_WARN("s3mmc: connect to peer '", peerId, "' at ", cfg.address, " failed after ", sw.ms(), " ms");
        dropSession(peerId, "tcp connect failed");
        return false;
    }
    auto chR = makeTlsChannel(fd, /*clientRole=*/true, tls_.certFile, tls_.keyFile, tls_.caFile);
    if (!chR) {
        LOG_ERROR("s3mmc: TLS with peer '", peerId, "' at ", cfg.address, " failed: ", chR.error());
        ::close(fd);
        dropSession(peerId, chR.error());
        return false;
    }
    auto ch = chR.value();
    std::string cn = tlsPeerCommonName(ch);
    if (!cn.empty() && cn != peerId)
        LOG_WARN("s3mmc: peer '", peerId, "' presented certificate CN '", cn, "'");
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        if (it == peers_.end()) {
            LOG_WARN("s3mmc: peer '", peerId, "' removed while dialing, dropping session");
            return false;
        }
        it->second.connected = true;
        it->second.channel = ch;
        it->second.direction = "out";
        it->second.sinceSec = nowSec();
    }
    Value hello = buildHelloFrame(peerId);
    {
        std::lock_guard<std::recursive_mutex> lk(mutex_);
        auto it = peers_.find(peerId);
        if (it == peers_.end() || it->second.channel != ch) {
            LOG_WARN("s3mmc: peer '", peerId, "' removed or rebound before hello, dropping session");
            return false;
        }
        std::lock_guard<std::mutex> slk(it->second.sendMutex);
        auto sr = ch->send(hello);
        if (!sr) {
            LOG_ERROR("s3mmc: hello to peer '", peerId, "' failed: ", sr.error());
            dropSession(peerId, "hello send failed");
            return false;
        }
    }
    LOG_INFO("s3mmc: connected to peer '", peerId, "' at ", cfg.address, " (CN '", cn, "') in ", sw.ms(), " ms");
    // spawn the reader loop for this session
    std::thread([this, ch, peerId] { sessionLoop(ch, peerId, true); }).detach();
    return true;
}

void ClusterClient::dialLoop() {
    LOG_DEBUG("s3mmc: dial loop started");
    while (running_.load()) {
        {
            std::lock_guard<std::recursive_mutex> lk(mutex_);
            for (auto& [id, rt] : peers_) {
                if (!rt.cfg.dial) continue; // we are the listener side
                if (rt.connected) continue;
                // release lock around blocking connect: copy id
                std::string peerId = id;
                int64_t attempts = rt.reconnects;
                mutex_.unlock();
                if (!ensureSession(peerId))
                    LOG_DEBUG("s3mmc: peer '", peerId, "' unreachable (", attempts + 1, " failures), retrying in 5s");
                mutex_.lock();
            }
        }
        for (int i = 0; i < 50 && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    LOG_DEBUG("s3mmc: dial loop finished");
}

void ClusterClient::pollLoop() {
    LOG_DEBUG("s3mmc: poll loop started (", opts_.pollModel, " every ", opts_.pollIntervalSec, "s)");
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
            LOG_DEBUG("s3mmc: sync cycle: requesting inventory from ", targets.size(), " outbound peers");
            for (auto& [id, ch] : targets) {
                std::lock_guard<std::recursive_mutex> lk(mutex_);
                auto it = peers_.find(id);
                if (it == peers_.end()) continue;
                std::lock_guard<std::mutex> slk(it->second.sendMutex);
                if (auto sr = ch->send(req); !sr)
                    LOG_WARN("s3mmc: inventory_req to '", id, "' failed: ", sr.error());
            }
        } else {
            LOG_DEBUG("s3mmc: sync cycle: poll model '", opts_.pollModel, "', nothing to pull");
        }
    }
    LOG_DEBUG("s3mmc: poll loop finished");
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
    LOG_DEBUG("s3mmc: merged view rev ", merged.revision, ": ", merged.clusters.size(), " clusters, ",
              merged.replications.size(), " replications");
    rebuildRoutesLocked();
}

void ClusterClient::rebuildRoutesLocked() {
    auto oldRoutes = routes_;
    routes_.clear();
    // A peer advertising cluster X (or having X among its local clusters) can
    // serve X: local -> remote[X]. Clusters owned locally are never routed.
    for (const auto& [id, rt] : peers_) {
        if (!rt.hasInventory) continue;
        for (const auto& c : rt.inventory.localClusters)
            if (!ownsClusterLocked(c)) routes_.emplace(c, id);
        for (const auto& c : rt.inventory.clusters)
            if (!ownsClusterLocked(c.id)) routes_.emplace(c.id, id);
    }
    if (routes_ != oldRoutes) {
        for (const auto& [c, hop] : routes_) {
            auto o = oldRoutes.find(c);
            if (o == oldRoutes.end()) LOG_INFO("s3mmc: route added remote[", c, "] via '", hop, "'");
            else if (o->second != hop) LOG_INFO("s3mmc: route remote[", c, "] moved '", o->second, "' -> '", hop, "'");
        }
        for (const auto& [c, hop] : oldRoutes)
            if (!routes_.count(c)) LOG_INFO("s3mmc: route removed remote[", c, "] (was via '", hop, "')");
    }
    LOG_DEBUG("s3mmc: route table: ", routes_.size(), " routes");
    // Provision remote[id] UNIX listeners. With requiredOnly=true we bind a
    // socket only for clusters that local replication rules actually reference
    // (the rest are reachable via routeTaskToCluster forwarding anyway, and
    // get bound later the moment they become "required"). With requiredOnly=
    // false every routed cluster gets a socket immediately.
    std::set<std::string> wanted;
    if (opts_.requiredOnly) {
        for (const auto& c : requiredClustersLocked()) wanted.insert(c);
    } else {
        for (const auto& [clusterId, hop] : routes_) wanted.insert(clusterId);
    }
    for (const auto& clusterId : wanted) {
        if (remoteFds_.count(clusterId)) continue;
        std::string path = opts_.runDir + "/" + opts_.nodeId + "/remote-" + clusterId + ".sock";
        int fd = bindUnixListener(path);
        if (fd >= 0) {
            remoteFds_[clusterId] = fd;
            LOG_INFO("s3mmc: provisioned remote[", clusterId, "] socket ", path);
            if (running_.load())
                std::thread([this, fd, clusterId] { unixAcceptLoop(fd, clusterId); }).detach();
        } else {
            LOG_ERROR("s3mmc: cannot provision remote[", clusterId, "] socket ", path);
        }
    }
    // Drop sockets for clusters nobody needs any more (only in requiredOnly
    // mode — otherwise the set is "everything known").
    if (opts_.requiredOnly) {
        for (auto it = remoteFds_.begin(); it != remoteFds_.end();) {
            if (!wanted.count(it->first) && !routes_.count(it->first)) {
                LOG_INFO("s3mmc: remote[", it->first, "] no longer needed, removing its socket");
                ::close(it->second);
                ::unlink((opts_.runDir + "/" + opts_.nodeId + "/remote-" + it->first + ".sock").c_str());
                it = remoteFds_.erase(it);
            } else ++it;
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
    // Visibility: managed list + effective per-peer ACL view.
    {
        Value ml = Value::array();
        for (const auto& m : opts_.managedNodes) ml.push(Value::str(m));
        v.set("managed", ml);
        Value acls = Value::array();
        for (const auto& a : opts_.peerAcls) {
            Value av = Value::object();
            av.set("to", Value::str(a.pattern));
            av.set("priority", Value::number((int64_t)a.priority));
            Value el = Value::array();
            for (const auto& e : a.elements) el.push(Value::str(e));
            av.set("elements", el);
            acls.push(av);
        }
        v.set("expose_acls", acls);
    }
    return v;
}

/// Effective visibility summary for one peer: manager flag + the element
/// filter it is served under. Used by the control socket `visibility` cmd.
Value ClusterClient::describeVisibility(const std::string& peerId) const {
    std::lock_guard<std::recursive_mutex> lk(mutex_);
    LOG_DEBUG("s3mmc: describing visibility for '", peerId, "'");
    Value v = Value::object();
    v.set("peer", Value::str(peerId));
    bool mgr = isManagerOf(peerId);
    v.set("manager", Value::boolean(mgr));
    if (mgr) {
        v.set("mode", Value::str("full"));
        Value el = Value::array();
        for (const char* n : {"clusters","endpoints","zones","aliases","vendor",
                              "replications","local_clusters","credentials"})
            el.push(Value::str(n));
        v.set("elements", el);
        return v;
    }
    const Options::PeerAcl* acl = aclForLocked(peerId);
    static const std::vector<std::string> kNone{"none"};
    const std::vector<std::string>* pat = &kNone;
    if (acl) pat = &acl->elements;
    else {
        static thread_local std::vector<std::string> legacy;
        legacy.clear();
        for (const auto& r : opts_.exposeRules)
            if (r.appliesTo == "unmanaged") { legacy.push_back(r.spec); break; }
        if (!legacy.empty()) pat = &legacy;  // spec string doubles as single pattern
    }
    bool hidden = pat->empty() || (pat->size() == 1 && ((*pat)[0] == "none" || (*pat)[0].empty()));
    v.set("mode", Value::str(acl ? "acl" : (hidden ? "hidden" : "global-expose")));
    Value el = Value::array();
    for (const auto& p : *pat) el.push(Value::str(p));
    v.set("elements", el);
    // What would actually be disclosed right now:
    peer::Inventory probe = filteredInventoryFor(peerId);
    Value seen = Value::object();
    seen.set("clusters", Value::number((int64_t)probe.clusters.size()));
    seen.set("replications", Value::number((int64_t)probe.replications.size()));
    seen.set("local_clusters", Value::number((int64_t)probe.localClusters.size()));
    v.set("would_disclose", seen);
    return v;
}

// ------------------------------------------------------------- core bridge ---

namespace {

int connectCoreCtl(const std::string& coreSocketPath) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("s3mmc: socket(AF_UNIX) for core ", coreSocketPath, " failed: ", std::strerror(errno));
        return -1;
    }
    sockaddr_un un{};
    un.sun_family = AF_UNIX;
    std::strncpy(un.sun_path, coreSocketPath.c_str(), sizeof(un.sun_path) - 1);
    LOG_DEBUG("s3mmc: connecting to core ", coreSocketPath);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) {
        LOG_ERROR("s3mmc: cannot connect to core ", coreSocketPath, ": ", std::strerror(errno));
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
    std::string cmd = request.getString("cmd");
    log::Stopwatch sw;
    int fd = connectCoreCtl(coreSocketPath_);
    if (fd < 0) return false;
    LOG_DEBUG("s3mmc: core call '", cmd, "' (", line.size(), " bytes", extraFd >= 0 ? ", with blob" : "", ")");
    if (!writeAllFd(fd, line)) {
        LOG_ERROR("s3mmc: core call '", cmd, "': request write failed");
        ::close(fd);
        return false;
    }
    // optional blob: 8-byte BE length + raw bytes follow the request line
    if (extraFd >= 0) {
        auto sz = fs::fileSize(std::string(request.getString("from")));
        uint64_t len = sz ? *sz : 0;
        unsigned char hdr[8];
        uint64_t t = len;
        for (int i = 7; i >= 0; --i) { hdr[i] = (unsigned char)(t & 0xFF); t >>= 8; }
        if (!writeAllFd(fd, std::string((char*)hdr, 8))) {
            LOG_ERROR("s3mmc: core call '", cmd, "': blob header write failed");
            ::close(fd);
            return false;
        }
        char buf[65536];
        uint64_t sent = 0;
        while (sent < len) {
            ssize_t n = ::read(extraFd, buf, sizeof(buf));
            if (n <= 0) {
                LOG_WARN("s3mmc: core call '", cmd, "': blob source ended at ", sent, "/", len, " bytes",
                         n < 0 ? std::string(": ") + std::strerror(errno) : std::string());
                break;
            }
            if (!writeAllFd(fd, std::string(buf, (size_t)n))) {
                LOG_ERROR("s3mmc: core call '", cmd, "': blob write failed at ", sent, "/", len, " bytes");
                ::close(fd);
                return false;
            }
            sent += (uint64_t)n;
        }
        LOG_DEBUG("s3mmc: core call '", cmd, "': streamed ", sent, " bytes blob");
    }
    std::string resp;
    if (!readLineFd(fd, resp, (int)opts_.coreTimeoutSec * 1000)) {
        LOG_ERROR("s3mmc: core call '", cmd, "': no reply after ", sw.ms(), " ms");
        ::close(fd);
        return false;
    }
    ::close(fd);
    std::string err;
    auto v = Value::parseJson(resp, &err);
    if (!err.empty() || !v.isObject()) {
        LOG_ERROR("s3mmc: core call '", cmd, "': bad reply: ", err.empty() ? "not an object" : err, " (",
                  cmd.find("credential") != std::string::npos ? log::redact(resp) : log::clip(resp), ")");
        return false;
    }
    LOG_DEBUG("s3mmc: core call '", cmd, "' -> ",
              cmd.find("credential") != std::string::npos ? log::redact(resp) : log::clip(resp), " in ", sw.ms(), " ms");
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
    LOG_DEBUG("s3mmc: core GET ", bucket, "/", key, " -> ", path);
    if (!coreCall(req, -1, &reply)) {
        LOG_ERROR("s3mmc: core GET ", bucket, "/", key, " failed");
        if (error) *error = "core get failed";
        return false;
    }
    if (const Value* ok = reply.find("ok"); ok && ok->asBool(false)) return true;
    if (error) *error = reply.getString("error", "core get rejected");
    LOG_WARN("s3mmc: core GET ", bucket, "/", key, " rejected: ", reply.getString("error", "core get rejected"));
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
        LOG_ERROR("s3mmc: core PUT ", bucket, "/", key, ": cannot open spool '", path, "': ", std::strerror(errno));
        if (error) *error = "cannot open spool file";
        return false;
    }
    LOG_DEBUG("s3mmc: core PUT ", bucket, "/", key, " from ", path, " (", size, " bytes)");
    Value reply;
    bool okv = coreCall(req, fd, &reply);
    ::close(fd);
    if (!okv) {
        LOG_ERROR("s3mmc: core PUT ", bucket, "/", key, " failed");
        if (error) *error = "core put failed";
        return false;
    }
    if (const Value* ok = reply.find("ok"); ok && ok->asBool(false)) return true;
    if (error) *error = reply.getString("error", "core put rejected");
    LOG_ERROR("s3mmc: core PUT ", bucket, "/", key, " rejected: ", reply.getString("error", "core put rejected"));
    return false;
}

bool ClusterClient::coreDelete(const std::string& bucket, const std::string& key, std::string* error) {
    Value req = Value::object();
    req.set("cmd", Value::str("cluster-del"));
    req.set("bucket", Value::str(bucket));
    req.set("key", Value::str(key));
    Value reply;
    LOG_DEBUG("s3mmc: core DELETE ", bucket, "/", key);
    if (!coreCall(req, -1, &reply)) {
        LOG_ERROR("s3mmc: core DELETE ", bucket, "/", key, " failed");
        if (error) *error = "core delete failed";
        return false;
    }
    if (const Value* ok = reply.find("ok"); ok && ok->asBool(false)) return true;
    if (error) *error = reply.getString("error", "core delete rejected");
    LOG_WARN("s3mmc: core DELETE ", bucket, "/", key, " rejected: ", reply.getString("error", "core delete rejected"));
    return false;
}

} // namespace s3mm::s3mmc
