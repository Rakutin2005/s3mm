#pragma once
#include <functional>
#include <string>

#include "s3mm/common/result.hpp"

namespace s3mm::daemon {

class PeerServer {
public:
    using Handler = std::function<std::string(const std::string&)>;
    PeerServer();
    ~PeerServer();
    Result<void> listen(const std::string& address, int port,
                       const std::string& certFile, const std::string& keyFile,
                       const std::string& caFile);
    void setHandler(Handler h) { handler_ = std::move(h); }
    void close();
    int fd() const { return fd_; }
private:
    int fd_ = -1;
    Handler handler_;
    // TLS context stored as opaque pointer to avoid header deps
    void* ctx_ = nullptr;
    void* sslCtx_ = nullptr;
    std::string certFile_, keyFile_, caFile_;
};

} // namespace s3mm::daemon
