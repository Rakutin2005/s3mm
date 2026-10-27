#include "s3mm/rest/server.hpp"

#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "s3mm/common/log.hpp"

namespace s3mm::rest {

namespace {
constexpr size_t kMaxBody = 256ull * 1024 * 1024;
uint64_t gRequestSeq = 0;
thread_local uint64_t gCurrentRequest = 0;

bool sensitiveHeader(const std::string& name) {
    std::string n;
    for (char c : name) n += (char)std::tolower((unsigned char)c);
    return n == "authorization" || n == "x-auth-token" || n == "x-cluster-secret" || n == "cookie" ||
           n == "set-cookie" || n == "proxy-authorization";
}

std::string describeHeaders(const std::map<std::string, std::string>& headers) {
    std::string out;
    for (const auto& [k, v] : headers) {
        if (!out.empty()) out += ", ";
        out += k + "=" + (sensitiveHeader(k) ? log::redact(v) : log::clip(v, 128));
    }
    return out;
}
}

// application/x-www-form-urlencoded / RFC 3986 percent-decoding ('+' only in queries).
static std::string urlDecode(const std::string& in, bool plusIsSpace) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '+' && plusIsSpace) {
            out += ' ';
        } else if (c == '%' && i + 2 < in.size() && std::isxdigit((unsigned char)in[i + 1]) &&
                   std::isxdigit((unsigned char)in[i + 2])) {
            out += (char)std::stoi(in.substr(i + 1, 2), nullptr, 16);
            i += 2;
        } else {
            out += c;
        }
    }
    return out;
}

static const char* reasonPhrase(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default: return status < 400 ? "OK" : "Error";
    }
}

uint64_t currentRequestId() { return gCurrentRequest; }

std::string requestTag() { return "req#" + std::to_string(gCurrentRequest) + " "; }

Result<void> HttpServer::listen(const std::string& address, int port) {
    LOG_DEBUG("http: creating listening socket for ", address, ":", port);
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::string err = std::strerror(errno);
        LOG_ERROR("http: socket() failed: ", err);
        return Result<void>::failure("socket failed: " + err);
    }
    int opt = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0)
        LOG_WARN("http: setsockopt(SO_REUSEADDR) failed: ", std::strerror(errno));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (::inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        LOG_ERROR("http: invalid listen address '", address, "' (only IPv4 literals are supported)");
        return Result<void>::failure("invalid listen address: " + address);
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::string err = std::strerror(errno);
        ::close(fd);
        LOG_ERROR("http: bind(", address, ":", port, ") failed: ", err);
        return Result<void>::failure("bind " + address + ":" + std::to_string(port) + " failed: " + err);
    }
    if (::listen(fd, 16) < 0) {
        std::string err = std::strerror(errno);
        ::close(fd);
        LOG_ERROR("http: listen(", address, ":", port, ") failed: ", err);
        return Result<void>::failure("listen failed: " + err);
    }
    fd_ = fd;
    LOG_INFO("http: listening on ", address, ":", port, " (fd ", fd, ", backlog 16)");
    return Result<void>::success();
}

void HttpServer::acceptOne(const Handler& handler) {
    sockaddr_in peer{};
    socklen_t peerLen = sizeof(peer);
    int client = ::accept(fd_, reinterpret_cast<sockaddr*>(&peer), &peerLen);
    if (client < 0) {
        LOG_WARN("http: accept() failed: ", std::strerror(errno));
        return;
    }
    log::Stopwatch sw;
    gCurrentRequest = ++gRequestSeq;
    char peerHost[INET_ADDRSTRLEN] = "?";
    ::inet_ntop(AF_INET, &peer.sin_addr, peerHost, sizeof peerHost);
    std::string peerName = std::string(peerHost) + ":" + std::to_string(ntohs(peer.sin_port));
    LOG_DEBUG(requestTag(), "http: accepted connection from ", peerName, " (fd ", client, ")");

    std::string raw;
    char buf[8192];
    // Read headers.
    for (;;) {
        ssize_t n = ::read(client, buf, sizeof(buf));
        if (n < 0) {
            LOG_WARN(requestTag(), "http: read from ", peerName, " failed: ", std::strerror(errno));
            break;
        }
        if (n == 0) {
            LOG_DEBUG(requestTag(), "http: ", peerName, " closed the connection after ", raw.size(), " bytes");
            break;
        }
        raw.append(buf, (size_t)n);
        if (raw.find("\r\n\r\n") != std::string::npos) break;
        if (raw.size() > 1024 * 1024) {
            LOG_WARN(requestTag(), "http: request headers from ", peerName, " exceed 1 MiB, stop reading");
            break;
        }
    }
    LOG_DEBUG(requestTag(), "http: read ", raw.size(), " bytes from ", peerName);

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
                if (eq != std::string::npos) req.query[urlDecode(pair.substr(0, eq), true)] = urlDecode(pair.substr(eq + 1), true);
                else if (!pair.empty()) req.query[urlDecode(pair, true)] = "";
                if (amp == std::string::npos) break;
                start = amp + 1;
            }
        }
        req.path = urlDecode(req.path, false);
        // Body based on Content-Length.
        auto it = req.headers.find("Content-Length");
        size_t len = 0;
        bool lenOk = it != req.headers.end();
        if (lenOk) {
            try {
                len = (size_t)std::stoul(it->second);
            } catch (const std::exception&) {
                lenOk = false;
                req.method.clear(); // answered with 400 below
                LOG_WARN(requestTag(), "http: invalid Content-Length '", log::clip(it->second, 64), "' from ", peerName);
            }
        }
        if (lenOk) {
            size_t headerEnd = raw.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                size_t bodyStart = headerEnd + 4;
                while (raw.size() < bodyStart + len && raw.size() < bodyStart + kMaxBody) {
                    ssize_t n = ::read(client, buf, sizeof(buf));
                    if (n <= 0) break;
                    raw.append(buf, (size_t)n);
                }
                if (raw.size() >= bodyStart + len) req.body = raw.substr(bodyStart, len);
                else {
                    req.body = raw.substr(bodyStart);
                    LOG_WARN(requestTag(), "http: body from ", peerName, " is truncated: Content-Length ", len,
                             ", received ", req.body.size());
                }
            }
        }
        std::string queryStr;
        for (const auto& [k, v] : req.query) queryStr += (queryStr.empty() ? "" : "&") + k + "=" + log::clip(v, 128);
        LOG_DEBUG(requestTag(), "http: parsed ", req.method, " ", req.path, queryStr.empty() ? "" : "?", queryStr,
                  " from ", peerName, ", ", req.headers.size(), " headers, body ", req.body.size(), " bytes");
        LOG_DEBUG(requestTag(), "http: headers: ", describeHeaders(req.headers));
    } else {
        LOG_WARN(requestTag(), "http: malformed request from ", peerName, ": no request line (", raw.size(), " bytes)");
    }

    if (req.method == "OPTIONS") {
        LOG_DEBUG(requestTag(), "http: CORS preflight for ", req.path, " answered with 204");
        res.status = 204;
        res.body.clear();
    } else if (req.method.empty()) {
        LOG_WARN(requestTag(), "http: rejecting request from ", peerName, " with 400: empty method");
        res.status = 400;
        res.text("bad request");
    } else {
        try {
            handler(req, res);
        } catch (const std::exception& e) {
            LOG_ERROR(requestTag(), "http: unhandled exception in handler for ", req.method, " ", req.path, ": ", e.what());
            res = RestResponse{};
            res.status = 500;
            res.json(Value::object().set("error", Value::str("internal error")));
        }
    }

    std::ostringstream out;
    out << "HTTP/1.1 " << res.status << " " << reasonPhrase(res.status) << "\r\n";
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
        if (n <= 0) {
            LOG_WARN(requestTag(), "http: write to ", peerName, " failed after ", sent, "/", response.size(),
                     " bytes: ", n < 0 ? std::strerror(errno) : "connection closed");
            break;
        }
        sent += (size_t)n;
    }
    ::close(client);

    auto level = res.status >= 500 ? log::Level::Error : res.status >= 400 ? log::Level::Warning : log::Level::Info;
    S3MM_LOG_AT(level, requestTag(), "http: ", peerName, " \"", req.method.empty() ? "-" : req.method, " ",
                req.path.empty() ? "-" : req.path, "\" -> ", res.status, ", in ", req.body.size(), " B, out ",
                res.body.size(), " B, ", sw.ms(), " ms",
                res.status >= 400 && !res.body.empty() ? ", error: " + log::clip(res.body, 512) : std::string());
}

void HttpServer::close() {
    if (fd_ >= 0) {
        LOG_INFO("http: closing listening socket (fd ", fd_, ")");
        ::close(fd_);
        fd_ = -1;
    }
}

} // namespace s3mm::rest
