#pragma once
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "s3mm/common/value.hpp"

namespace s3mm::rest {

struct ClusterConfig {
    bool enabled = false;
    std::string nodeId;
    std::string bind = "127.0.0.1";
    int port = 9443;
    std::string peersFile;
    bool useMtls = true;
    std::string caCert;
    std::string caKey;
    std::string nodeCert;
    std::string nodeKey;
    std::string certsDir;
    std::string clusterSecret;
};

struct PeerInfo {
    std::string address;
    std::string nodeId;
};

class ClusterManager {
public:
    ClusterManager();
    void setConfig(const ClusterConfig& cfg) { cfg_ = cfg; loadPeers(); }
    const ClusterConfig& config() const { return cfg_; }
    std::string nodeId() const { return cfg_.nodeId; }
    bool ensureCa();
    bool ensureNodeCert();
    Value getStatus() const;
    Value initFromLogin(const std::string& username, const std::string& password);
    Value listPeers() const;
    bool addPeer(const std::string& address, const std::string& nodeId="");
    bool removePeer(const std::string& address);
    std::vector<PeerInfo> peers() const;
    void start();
    void stop();
private:
    ClusterConfig cfg_;
    mutable std::mutex mtx_;
    std::vector<PeerInfo> peers_;
    std::string peersPath() const;
    void loadPeers();
    void savePeers() const;
};

}
