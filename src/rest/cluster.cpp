#include "s3mm/rest/cluster.hpp"
#include <fstream>
#include <random>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <algorithm>
#include <cerrno>
#include <cstring>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/crypto.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::rest {

static std::string genId() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    uint64_t x = dis(gen);
    std::ostringstream oss;
    oss << std::hex << x;
    return oss.str();
}

ClusterManager::ClusterManager() {
    cfg_.nodeId = genId();
    LOG_DEBUG("wscluster: generated node id ", cfg_.nodeId);
}

std::string ClusterManager::peersPath() const {
    std::string base = cfg_.certsDir.empty() ? "/var/lib/s3mmws/cluster" : cfg_.certsDir;
    return base + "/peers.json";
}

void ClusterManager::loadPeers() {
    LOG_DEBUG("wscluster: loading peers from ", peersPath());
    auto content = fs::readFile(peersPath());
    if (!content) {
        LOG_DEBUG("wscluster: no peers file at ", peersPath());
        return;
    }
    std::string err; Value v = Value::parseJson(*content, &err);
    if (!err.empty() || !v.isArray())
        LOG_ERROR("wscluster: peers file ", peersPath(), " is not a JSON array", err.empty() ? std::string() : ": " + err);
    if (err.empty() && v.isArray()) {
        std::lock_guard<std::mutex> lk(mtx_);
        peers_.clear();
        for (auto& pv2 : v.items()) {
            const Value* pv = &pv2;
            if (pv && pv->isObject()) {
                PeerInfo pi;
                if (pv->find("address") && pv->find("address")->isString()) pi.address = pv->find("address")->asString();
                if (pv->find("node_id") && pv->find("node_id")->isString()) pi.nodeId = pv->find("node_id")->asString();
                if (!pi.address.empty()) {
                    peers_.push_back(pi);
                    LOG_DEBUG("wscluster: peer ", pi.address, " (node ", pi.nodeId.empty() ? "?" : pi.nodeId, ")");
                } else {
                    LOG_WARN("wscluster: skipping peer entry without address in ", peersPath());
                }
            }
        }
        LOG_INFO("wscluster: loaded ", peers_.size(), " peers from ", peersPath());
    }
}

void ClusterManager::savePeers() const {
    Value arr = Value::array();
    for (auto& p : peers_) {
        Value v = Value::object();
        v.set("address", Value::str(p.address));
        v.set("node_id", Value::str(p.nodeId));
        arr.push(v);
    }
    if (!fs::mkdirp(fs::dirname(peersPath())))
        LOG_ERROR("wscluster: cannot create directory ", fs::dirname(peersPath()), ": ", std::strerror(errno));
    if (fs::writeFileAtomic(peersPath(), arr.toJson(2)))
        LOG_DEBUG("wscluster: saved ", peers_.size(), " peers to ", peersPath());
    else
        LOG_ERROR("wscluster: failed to write peers file ", peersPath(), ": ", std::strerror(errno));
}

bool ClusterManager::ensureCa() {
    if (cfg_.certsDir.empty()) {
        std::string base = "/var/lib/s3mmws";
        cfg_.certsDir = base + "/cluster";
        LOG_DEBUG("wscluster: certs_dir not set, using ", cfg_.certsDir);
    }
    if (!fs::mkdirp(cfg_.certsDir))
        LOG_ERROR("wscluster: cannot create certs dir ", cfg_.certsDir, ": ", std::strerror(errno));
    std::string caCert = cfg_.certsDir + "/ca.crt";
    std::string caKey = cfg_.certsDir + "/ca.key";
    if (fs::exists(caCert) && fs::exists(caKey)) {
        LOG_DEBUG("wscluster: using existing CA ", caCert);
        cfg_.caCert = caCert;
        cfg_.caKey = caKey;
        return true;
    }
    LOG_NOTICE("wscluster: generating cluster CA in ", cfg_.certsDir);
    std::string cmd = "openssl req -x509 -newkey rsa:2048 -keyout " + caKey + " -out " + caCert + " -days 3650 -nodes -subj '/CN=s3mmws-ca' 2>/dev/null";
    int rc = system(cmd.c_str());
    if (rc == 0 && fs::exists(caCert) && fs::exists(caKey)) {
        if (chmod(caKey.c_str(), 0600) != 0) LOG_WARN("wscluster: chmod 0600 ", caKey, " failed: ", std::strerror(errno));
        cfg_.caCert = caCert;
        cfg_.caKey = caKey;
        LOG_INFO("wscluster: generated CA certificate ", caCert);
        return true;
    }
    LOG_ERROR("wscluster: CA generation failed (openssl exit status ", rc, ") in ", cfg_.certsDir);
    return false;
}

bool ClusterManager::ensureNodeCert() {
    if (!ensureCa()) {
        LOG_ERROR("wscluster: cannot issue node certificate without a CA");
        return false;
    }
    if (cfg_.certsDir.empty()) return false;
    std::string nCert = cfg_.certsDir + "/node-" + cfg_.nodeId + ".crt";
    std::string nKey = cfg_.certsDir + "/node-" + cfg_.nodeId + ".key";
    std::string csr = cfg_.certsDir + "/node-" + cfg_.nodeId + ".csr";
    if (fs::exists(nCert) && fs::exists(nKey)) {
        LOG_DEBUG("wscluster: using existing node certificate ", nCert);
        cfg_.nodeCert = nCert;
        cfg_.nodeKey = nKey;
        return true;
    }
    LOG_NOTICE("wscluster: issuing node certificate for ", cfg_.nodeId);
    std::string cmd = "openssl req -new -newkey rsa:2048 -keyout " + nKey + " -out " + csr + " -nodes -subj '/CN=" + cfg_.nodeId + "' 2>/dev/null";
    if (int rc = system(cmd.c_str()); rc != 0) {
        LOG_ERROR("wscluster: node CSR generation failed (openssl exit status ", rc, ")");
        return false;
    }
    cmd = "openssl x509 -req -in " + csr + " -CA " + cfg_.caCert + " -CAkey " + cfg_.caKey + " -CAcreateserial -out " + nCert + " -days 825 -sha256 2>/dev/null";
    if (int rc = system(cmd.c_str()); rc != 0) {
        LOG_ERROR("wscluster: signing node certificate failed (openssl exit status ", rc, ")");
        return false;
    }
    if (unlink(csr.c_str()) != 0) LOG_WARN("wscluster: cannot remove CSR ", csr, ": ", std::strerror(errno));
    if (chmod(nKey.c_str(), 0600) != 0) LOG_WARN("wscluster: chmod 0600 ", nKey, " failed: ", std::strerror(errno));
    cfg_.nodeCert = nCert;
    cfg_.nodeKey = nKey;
    LOG_INFO("wscluster: issued node certificate ", nCert);
    return true;
}

Value ClusterManager::getStatus() const {
    Value v = Value::object();
    v.set("enabled", Value::boolean(cfg_.enabled));
    v.set("node_id", Value::str(cfg_.nodeId));
    v.set("bind", Value::str(cfg_.bind));
    v.set("port", Value::number((double)cfg_.port));
    v.set("use_mtls", Value::boolean(cfg_.useMtls));
    v.set("certs_dir", Value::str(cfg_.certsDir));
    v.set("has_ca", Value::boolean(fs::exists(cfg_.caCert)));
    v.set("has_node_cert", Value::boolean(fs::exists(cfg_.nodeCert)));
    v.set("peers", listPeers());
    return v;
}

Value ClusterManager::initFromLogin(const std::string& username, const std::string& password) {
    (void)password;
    LOG_INFO("wscluster: init requested", username.empty() ? std::string() : " by '" + username + "'");
    if (!ensureNodeCert()) {
        LOG_ERROR("wscluster: init failed: certificates could not be generated");
        Value err = Value::object();
        err.set("error", Value::str("failed to generate certificates"));
        return err;
    }
    Value v = Value::object();
    v.set("ok", Value::boolean(true));
    v.set("node_id", Value::str(cfg_.nodeId));
    if (auto ca = fs::readFile(cfg_.caCert)) v.set("ca_cert", Value::str(*ca));
    if (auto nc = fs::readFile(cfg_.nodeCert)) v.set("node_cert", Value::str(*nc));
    if (auto nk = fs::readFile(cfg_.nodeKey)) v.set("node_key", Value::str(*nk));
    else LOG_WARN("wscluster: node key ", cfg_.nodeKey, " is unreadable");
    LOG_NOTICE("wscluster: handed out CA and node key material for node ", cfg_.nodeId);
    return v;
}

Value ClusterManager::listPeers() const {
    std::lock_guard<std::mutex> lk(mtx_);
    Value arr = Value::array();
    for (auto& p : peers_) {
        Value v = Value::object();
        v.set("address", Value::str(p.address));
        v.set("node_id", Value::str(p.nodeId));
        arr.push(v);
    }
    return arr;
}

bool ClusterManager::addPeer(const std::string& address, const std::string& nodeId) {
    if (address.empty()) {
        LOG_WARN("wscluster: add peer with empty address ignored");
        return false;
    }
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& p : peers_) if (p.address == address) {
        if (!nodeId.empty()) p.nodeId = nodeId;
        savePeers();
        LOG_INFO("wscluster: peer ", address, " already known, node id ", p.nodeId.empty() ? "?" : p.nodeId);
        return true;
    }
    PeerInfo pi; pi.address = address; pi.nodeId = nodeId;
    peers_.push_back(pi);
    savePeers();
    LOG_NOTICE("wscluster: added peer ", address, " (node ", nodeId.empty() ? "?" : nodeId, "), ", peers_.size(), " peers total");
    return true;
}

bool ClusterManager::removePeer(const std::string& address) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = std::remove_if(peers_.begin(), peers_.end(), [&](const PeerInfo& p){ return p.address == address; });
    if (it == peers_.end()) {
        LOG_WARN("wscluster: remove peer ", address, ": not found");
        return false;
    }
    peers_.erase(it, peers_.end());
    savePeers();
    LOG_NOTICE("wscluster: removed peer ", address, ", ", peers_.size(), " peers left");
    return true;
}

std::vector<PeerInfo> ClusterManager::peers() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return peers_;
}

void ClusterManager::start() {}
void ClusterManager::stop() {}

}
