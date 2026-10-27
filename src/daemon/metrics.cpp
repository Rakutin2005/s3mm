#include "s3mm/daemon/metrics.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "s3mm/common/error.hpp"
#include "s3mm/common/log.hpp"

namespace s3mm::daemon {

MetricsServer::~MetricsServer() { close(); }

Result<int> MetricsServer::listen(const std::string& address) {
    LOG_DEBUG("metrics: listen on ", address);
    auto colon = address.rfind(':');
    if (colon == std::string::npos) {
        LOG_ERROR("metrics: address must be host:port, got '", address, "'");
        return Result<int>::failure("metrics address must be host:port, got '" + address + "'");
    }
    std::string host = address.substr(0, colon);
    int port = std::atoi(address.c_str() + colon + 1);
    if (port <= 0 || port > 65535) {
        LOG_ERROR("metrics: bad port in '", address, "'");
        return Result<int>::failure("bad metrics port in '" + address + "'");
    }

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("metrics: socket(AF_INET): ", std::strerror(errno));
        return Result<int>::failure("socket: " + std::string(std::strerror(errno)));
    }
    int one = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
        LOG_WARN("metrics: SO_REUSEADDR: ", std::strerror(errno));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (host.empty() || host == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        LOG_ERROR("metrics: bad host '", host, "' (IPv4 address expected)");
        ::close(fd);
        return Result<int>::failure("bad metrics host '" + host + "'");
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::string err = std::strerror(errno);
        LOG_ERROR("metrics: bind ", address, ": ", err);
        ::close(fd);
        return Result<int>::failure("bind " + address + ": " + err);
    }
    if (::listen(fd, 8) < 0) {
        std::string err = std::strerror(errno);
        LOG_ERROR("metrics: listen ", address, ": ", err);
        ::close(fd);
        return Result<int>::failure("listen: " + err);
    }
    fd_ = fd;
    LOG_INFO("metrics: listening on ", address, " (fd ", fd, ")");
    return Result<int>(fd);
}

void MetricsServer::acceptOne(const Handler& handler) {
    sockaddr_in peerAddr{};
    socklen_t peerLen = sizeof(peerAddr);
    int client = ::accept(fd_, reinterpret_cast<sockaddr*>(&peerAddr), &peerLen);
    if (client < 0) {
        LOG_WARN("metrics: accept failed: ", std::strerror(errno));
        return;
    }
    log::Stopwatch sw;
    char peerHost[INET_ADDRSTRLEN] = "?";
    ::inet_ntop(AF_INET, &peerAddr.sin_addr, peerHost, sizeof(peerHost));
    std::string peer = std::string(peerHost) + ":" + std::to_string(ntohs(peerAddr.sin_port));
    LOG_DEBUG("metrics: accepted connection from ", peer);
    char buf[2048];
    ssize_t n = ::read(client, buf, sizeof(buf) - 1);
    if (n < 0) LOG_WARN("metrics: read from ", peer, " failed: ", std::strerror(errno));
    else if (n == 0) LOG_DEBUG("metrics: ", peer, " closed without a request");
    if (n > 0) {
        buf[n] = '\0';
        std::string request(buf);
        bool isMetrics = request.rfind("GET /metrics", 0) == 0;
        std::string body = isMetrics ? handler() : "not found\n";
        std::string status = isMetrics ? "200 OK" : "404 Not Found";
        std::string contentType = isMetrics ? "text/plain; version=0.0.4" : "text/plain";
        std::string head = "HTTP/1.0 " + status + "\r\nServer: s3mm\r\nContent-Type: " + contentType +
                           "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
        size_t sent = 0;
        std::string payload = head + body;
        while (sent < payload.size()) {
            ssize_t w = ::write(client, payload.data() + sent, payload.size() - sent);
            if (w <= 0) {
                LOG_WARN("metrics: write to ", peer, " failed after ", sent, "/", payload.size(), " bytes: ",
                         w < 0 ? std::strerror(errno) : "connection closed");
                break;
            }
            sent += (size_t)w;
        }
        LOG_DEBUG("metrics: ", peer, " \"", request.substr(0, request.find_first_of("\r\n")), "\" -> ", status, ", ",
                  body.size(), " bytes in ", sw.ms(), " ms");
    }
    ::close(client);
}

void MetricsServer::close() {
    if (fd_ >= 0) {
        LOG_INFO("metrics: closing listener fd ", fd_);
        ::close(fd_);
        fd_ = -1;
    }
}

} // namespace s3mm::daemon
