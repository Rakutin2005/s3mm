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
    auto colon = address.rfind(':');
    if (colon == std::string::npos) return Result<int>::failure("metrics address must be host:port, got '" + address + "'");
    std::string host = address.substr(0, colon);
    int port = std::atoi(address.c_str() + colon + 1);
    if (port <= 0 || port > 65535) return Result<int>::failure("bad metrics port in '" + address + "'");

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return Result<int>::failure("socket: " + std::string(std::strerror(errno)));
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (host.empty() || host == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        return Result<int>::failure("bad metrics host '" + host + "'");
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::string err = std::strerror(errno);
        ::close(fd);
        return Result<int>::failure("bind " + address + ": " + err);
    }
    if (::listen(fd, 8) < 0) {
        std::string err = std::strerror(errno);
        ::close(fd);
        return Result<int>::failure("listen: " + err);
    }
    fd_ = fd;
    return Result<int>(fd);
}

void MetricsServer::acceptOne(const Handler& handler) {
    int client = ::accept(fd_, nullptr, nullptr);
    if (client < 0) return;
    char buf[2048];
    ssize_t n = ::read(client, buf, sizeof(buf) - 1);
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
            if (w <= 0) break;
            sent += (size_t)w;
        }
    }
    ::close(client);
}

void MetricsServer::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

} // namespace s3mm::daemon
