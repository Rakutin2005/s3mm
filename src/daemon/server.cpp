#include "s3mm/daemon/server.hpp"

#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "s3mm/common/error.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"

namespace s3mm::daemon {

Result<void> ControlServer::listen(const std::string& socketPath) {
    if (socketPath.empty()) return Result<void>::failure("control socket path is empty");
    if (socketPath.find("://") != std::string::npos) {
        return Result<void>::failure("s3mmd control socket must be a Unix socket path, not a URI");
    }
    if (socketPath.find(':') != std::string::npos && socketPath.find('/') == std::string::npos) {
        return Result<void>::failure("s3mmd control socket must be a Unix socket path, not a network address");
    }
    std::string dir = fs::dirname(socketPath);
    if (!dir.empty() && !fs::mkdirp(dir))
        return Result<void>::failure("cannot create socket directory " + dir);

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return Result<void>::failure("socket: " + std::string(std::strerror(errno)));

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        return Result<void>::failure("socket path too long: " + socketPath);
    }
    std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
    ::unlink(socketPath.c_str());
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::string err = std::strerror(errno);
        ::close(fd);
        return Result<void>::failure("bind " + socketPath + ": " + err);
    }
    fs::setPermissions(socketPath, 0660);
    if (::listen(fd, 16) < 0) {
        std::string err = std::strerror(errno);
        ::close(fd);
        return Result<void>::failure("listen: " + err);
    }
    fd_ = fd;
    path_ = socketPath;
    return Result<void>::success();
}

void ControlServer::acceptOne(const Handler& handler) {
    int client = ::accept(fd_, nullptr, nullptr);
    if (client < 0) return;

    // read one request line (bounded: config mutations are small)
    std::string request;
    char buf[8192];
    for (;;) {
        ssize_t n = ::read(client, buf, sizeof(buf));
        if (n <= 0) break;
        request.append(buf, (size_t)n);
        if (request.find('\n') != std::string::npos || request.size() > 1024 * 1024) break;
    }

    Value response;
    if (request.empty()) {
        response.set("ok", Value::boolean(false));
        response.set("error", Value::str("empty request"));
    } else {
        std::string parseError;
        Value parsed = Value::parseJson(request, &parseError);
        if (!parseError.empty() || !parsed.isObject()) {
            response.set("ok", Value::boolean(false));
            response.set("error", Value::str("bad request: " + (parseError.empty() ? "not an object" : parseError)));
        } else {
            try {
                response.set("ok", Value::boolean(true));
                response.set("data", handler(parsed));
            } catch (const Error& e) {
                response = Value::object();
                response.set("ok", Value::boolean(false));
                response.set("error", Value::str(e.what()));
            } catch (const std::exception& e) {
                response = Value::object();
                response.set("ok", Value::boolean(false));
                response.set("error", Value::str(e.what()));
            }
        }
    }
    std::string line = response.toJson(0) + "\n";
    size_t sent = 0;
    while (sent < line.size()) {
        ssize_t n = ::write(client, line.data() + sent, line.size() - sent);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    ::close(client);
}

void ControlServer::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    if (!path_.empty()) {
        ::unlink(path_.c_str());
        path_.clear();
    }
}

} // namespace s3mm::daemon
