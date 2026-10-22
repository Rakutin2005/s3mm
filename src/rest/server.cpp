#include "s3mm/rest/server.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "s3mm/common/log.hpp"

namespace s3mm::rest {

Result<void> HttpServer::listen(const std::string& address, int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return Result<void>::failure("socket failed");
    int opt = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (::inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        return Result<void>::failure("invalid listen address: " + address);
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return Result<void>::failure("bind failed");
    }
    if (::listen(fd, 16) < 0) {
        ::close(fd);
        return Result<void>::failure("listen failed");
    }
    fd_ = fd;
    return Result<void>::success();
}

void HttpServer::acceptOne(const Handler& handler) {
    int client = ::accept(fd_, nullptr, nullptr);
    if (client < 0) return;

    std::string raw;
    char buf[8192];
    // Read headers.
    for (;;) {
        ssize_t n = ::read(client, buf, sizeof(buf));
        if (n <= 0) break;
        raw.append(buf, (size_t)n);
        if (raw.find("\r\n\r\n") != std::string::npos) break;
        if (raw.size() > 1024 * 1024) break;
    }

    RestRequest req;
    RestResponse res;
    // Parse request line.
    auto lineEnd = raw.find("\r\n");
    if (lineEnd != std::string::npos) {
        std::string requestLine = raw.substr(0, lineEnd);
        std::istringstream iss(requestLine);
        iss >> req.method >> req.path;
        // Parse headers.
        size_t pos = lineEnd + 2;
        while (true) {
            size_t next = raw.find("\r\n", pos);
            if (next == std::string::npos || next == pos) break;
            std::string header = raw.substr(pos, next - pos);
            auto colon = header.find(':');
            if (colon != std::string::npos) {
                std::string key = header.substr(0, colon);
                std::string value = header.substr(colon + 1);
                // trim
                auto trim = [](std::string s) {
                    size_t a = s.find_first_not_of(" \t");
                    size_t b = s.find_last_not_of(" \t");
                    if (a == std::string::npos) return std::string();
                    return s.substr(a, b - a + 1);
                };
                req.headers[trim(key)] = trim(value);
            }
            pos = next + 2;
        }
        // Parse query.
        auto qpos = req.path.find('?');
        if (qpos != std::string::npos) {
            std::string query = req.path.substr(qpos + 1);
            req.path = req.path.substr(0, qpos);
            size_t start = 0;
            while (start < query.size()) {
                size_t amp = query.find('&', start);
                std::string pair = query.substr(start, amp == std::string::npos ? std::string::npos : amp - start);
                auto eq = pair.find('=');
                if (eq != std::string::npos) req.query[pair.substr(0, eq)] = pair.substr(eq + 1);
                else if (!pair.empty()) req.query[pair] = "";
                if (amp == std::string::npos) break;
                start = amp + 1;
            }
        }
        // Body based on Content-Length.
        auto it = req.headers.find("Content-Length");
        if (it != req.headers.end()) {
            size_t len = (size_t)std::stoul(it->second);
            size_t headerEnd = raw.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                size_t bodyStart = headerEnd + 4;
                if (raw.size() >= bodyStart + len) req.body = raw.substr(bodyStart, len);
                else req.body = raw.substr(bodyStart);
            }
        }
    }

    if (req.method == "OPTIONS") {
        res.status = 204;
        res.body.clear();
    } else if (req.method.empty()) {
        res.status = 400;
        res.text("bad request");
    } else {
        handler(req, res);
    }

    std::ostringstream out;
    out << "HTTP/1.1 " << res.status << " " << (res.status == 200 ? "OK" : "ERROR") << "\r\n";
    if (res.headers.find("Content-Type") == res.headers.end()) res.headers["Content-Type"] = "application/json";
    for (const auto& [k, v] : res.headers) out << k << ": " << v << "\r\n";
    out << "Access-Control-Allow-Origin: *\r\n";
    out << "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
    out << "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n";
    out << "Content-Length: " << res.body.size() << "\r\n";
    out << "Connection: close\r\n\r\n";
    out << res.body;
    std::string response = out.str();
    size_t sent = 0;
    while (sent < response.size()) {
        ssize_t n = ::write(client, response.data() + sent, response.size() - sent);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    ::close(client);
}

void HttpServer::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

} // namespace s3mm::rest
