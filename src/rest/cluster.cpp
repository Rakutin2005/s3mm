#include "s3mm/rest/cluster.hpp"
#include <fstream>
#include <random>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <algorithm>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/crypto.hpp"
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
}

std::string ClusterManager::peersPath() const {
    std::string base = cfg_.certsDir.empty() ? "/var/lib/s3mmws/cluster" : cfg_.certsDir;
    return base + "/peers.json";
}

void ClusterManager::loadPeers() {
    auto content = fs::readFile(peersPath());
    if (!content) return;
    std::string err; Value v = Value::parseJson(*content, &err);
    if (err.empty() && v.isArray()) {
        std::lock_guard<std::mutex> lk(mtx_);
        peers_.clear();
        for (auto& pv2 : v.items()) {
            const Value* pv = &pv2;
            if (pv && pv->isObject()) {
                PeerInfo pi;
                if (pv->find("address") && pv->find("address")->isString()) pi.address = pv->find("address")->asString();
                if (pv->find("node_id") && pv->find("node_id")->isString()) pi.nodeId = pv->find("node_id")->asString();
                if (!pi.address.empty()) peers_.push_back(pi);
            }
        }
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
    fs::mkdirp(fs::dirname(peersPath()));
    fs::writeFileAtomic(peersPath(), arr.toJson(2));
}

bool ClusterManager::ensureCa() {
    if (cfg_.certsDir.empty()) {
        std::string base = "/var/lib/s3mmws";
        cfg_.certsDir = base + "/cluster";
    }
    fs::mkdirp(cfg_.certsDir);
    std::string caCert = cfg_.certsDir + "/ca.crt";
    std::string caKey = cfg_.certsDir + "/ca.key";
    if (fs::exists(caCert) && fs::exists(caKey)) {
        cfg_.caCert = caCert;
        cfg_.caKey = caKey;
        return true;
    }
    std::string cmd = "openssl req -x509 -newkey rsa:2048 -keyout " + caKey + " -out " + caCert + " -days 3650 -nodes -subj '/CN=s3mmws-ca' 2>/dev/null";
    int rc = system(cmd.c_str());
    if (rc == 0 && fs::exists(caCert) && fs::exists(caKey)) {
        chmod(caKey.c_str(), 0600);
        cfg_.caCert = caCert;
        cfg_.caKey = caKey;
        return true;
    }
    return false;
}

bool ClusterManager::ensureNodeCert() {
    if (!ensureCa()) return false;
    if (cfg_.certsDir.empty()) return false;
    std::string nCert = cfg_.certsDir + "/node-" + cfg_.nodeId + ".crt";
    std::string nKey = cfg_.certsDir + "/node-" + cfg_.nodeId + ".key";
    std::string csr = cfg_.certsDir + "/node-" + cfg_.nodeId + ".csr";
    if (fs::exists(nCert) && fs::exists(nKey)) {
        cfg_.nodeCert = nCert;
        cfg_.nodeKey = nKey;
        return true;
    }
    std::string cmd = "openssl req -new -newkey rsa:2048 -keyout " + nKey + " -out " + csr + " -nodes -subj '/CN=" + cfg_.nodeId + "' 2>/dev/null";
    if (system(cmd.c_str()) != 0) return false;
    cmd = "openssl x509 -req -in " + csr + " -CA " + cfg_.caCert + " -CAkey " + cfg_.caKey + " -CAcreateserial -out " + nCert + " -days 825 -sha256 2>/dev/null";
    if (system(cmd.c_str()) != 0) return false;
    unlink(csr.c_str());
    chmod(nKey.c_str(), 0600);
    cfg_.nodeCert = nCert;
    cfg_.nodeKey = nKey;
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
    (void)username; (void)password;
    if (!ensureNodeCert()) {
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
    if (address.empty()) return false;
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& p : peers_) if (p.address == address) { if (!nodeId.empty()) p.nodeId = nodeId; savePeers(); return true; }
    PeerInfo pi; pi.address = address; pi.nodeId = nodeId;
    peers_.push_back(pi);
    savePeers();
    return true;
}

bool ClusterManager::removePeer(const std::string& address) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = std::remove_if(peers_.begin(), peers_.end(), [&](const PeerInfo& p){ return p.address == address; });
    if (it == peers_.end()) return false;
    peers_.erase(it, peers_.end());
    savePeers();
    return true;
}

std::vector<PeerInfo> ClusterManager::peers() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return peers_;
}

void ClusterManager::start() {}
void ClusterManager::stop() {}

}
