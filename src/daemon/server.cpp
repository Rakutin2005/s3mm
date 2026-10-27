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
    LOG_DEBUG("control: listen on ", socketPath);
    if (socketPath.empty()) {
        LOG_ERROR("control: socket path is empty");
        return Result<void>::failure("control socket path is empty");
    }
    if (socketPath.find("://") != std::string::npos) {
        LOG_ERROR("control: socket path '", socketPath, "' is a URI, not a Unix socket path");
        return Result<void>::failure("s3mmd control socket must be a Unix socket path, not a URI");
    }
    if (socketPath.find(':') != std::string::npos && socketPath.find('/') == std::string::npos) {
        LOG_ERROR("control: socket path '", socketPath, "' is a network address, not a Unix socket path");
        return Result<void>::failure("s3mmd control socket must be a Unix socket path, not a network address");
    }
    std::string dir = fs::dirname(socketPath);
    if (!dir.empty() && !fs::mkdirp(dir)) {
        LOG_ERROR("control: cannot create socket directory ", dir);
        return Result<void>::failure("cannot create socket directory " + dir);
    }

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_ERROR("control: socket(AF_UNIX): ", std::strerror(errno));
        return Result<void>::failure("socket: " + std::string(std::strerror(errno)));
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(addr.sun_path)) {
        LOG_ERROR("control: socket path too long (", socketPath.size(), " bytes): ", socketPath);
        ::close(fd);
        return Result<void>::failure("socket path too long: " + socketPath);
    }
    std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);
    if (::unlink(socketPath.c_str()) == 0) LOG_DEBUG("control: removed stale socket ", socketPath);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::string err = std::strerror(errno);
        LOG_ERROR("control: bind ", socketPath, ": ", err);
        ::close(fd);
        return Result<void>::failure("bind " + socketPath + ": " + err);
    }
    if (!fs::setPermissions(socketPath, 0660)) LOG_WARN("control: cannot chmod 0660 ", socketPath);
    if (::listen(fd, 16) < 0) {
        std::string err = std::strerror(errno);
        LOG_ERROR("control: listen ", socketPath, ": ", err);
        ::close(fd);
        return Result<void>::failure("listen: " + err);
    }
    fd_ = fd;
    path_ = socketPath;
    LOG_INFO("control: listening on ", socketPath, " (fd ", fd, ")");
    return Result<void>::success();
}

void ControlServer::acceptOne(const Handler& handler) {
    int client = ::accept(fd_, nullptr, nullptr);
    if (client < 0) {
        LOG_WARN("control: accept failed: ", std::strerror(errno));
        return;
    }
    log::Stopwatch sw;
    std::string peer;
    {
        ucred cred{};
        socklen_t len = sizeof(cred);
        if (::getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0)
            peer = "pid=" + std::to_string(cred.pid) + " uid=" + std::to_string(cred.uid);
    }
    LOG_DEBUG("control: accepted connection fd ", client, peer.empty() ? "" : " from ", peer);

    // read one request line (bounded: config mutations are small)
    std::string request;
    char buf[8192];
    for (;;) {
        ssize_t n = ::read(client, buf, sizeof(buf));
        if (n < 0) LOG_WARN("control: read from client failed: ", std::strerror(errno));
        if (n <= 0) break;
        request.append(buf, (size_t)n);
        if (request.find('\n') != std::string::npos || request.size() > 1024 * 1024) break;
    }

    LOG_DEBUG("control: read ", request.size(), " byte(s) request");

    Value response;
    std::string cmd;
    if (request.empty()) {
        LOG_WARN("control: empty request", peer.empty() ? "" : " from ", peer);
        response.set("ok", Value::boolean(false));
        response.set("error", Value::str("empty request"));
    } else {
        std::string parseError;
        Value parsed = Value::parseJson(request, &parseError);
        if (!parseError.empty() || !parsed.isObject()) {
            LOG_WARN("control: bad request (", parseError.empty() ? "not an object" : parseError, "), ",
                     request.size(), " bytes", peer.empty() ? "" : " from ", peer);
            response.set("ok", Value::boolean(false));
            response.set("error", Value::str("bad request: " + (parseError.empty() ? "not an object" : parseError)));
        } else {
            cmd = parsed.getString("cmd");
            try {
                response.set("ok", Value::boolean(true));
                response.set("data", handler(parsed));
                LOG_INFO("control: command '", cmd, "' ok in ", sw.ms(), " ms", peer.empty() ? "" : " (", peer,
                         peer.empty() ? "" : ")");
            } catch (const Error& e) {
                LOG_ERROR("control: command '", cmd, "' failed in ", sw.ms(), " ms: ", e.what());
                response = Value::object();
                response.set("ok", Value::boolean(false));
                response.set("error", Value::str(e.what()));
            } catch (const std::exception& e) {
                LOG_ERROR("control: command '", cmd, "' raised ", e.what(), " after ", sw.ms(), " ms");
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
        if (n <= 0) {
            LOG_WARN("control: write of response to client failed after ", sent, "/", line.size(), " bytes: ",
                     n < 0 ? std::strerror(errno) : "connection closed");
            break;
        }
        sent += (size_t)n;
    }
    ::close(client);
    LOG_DEBUG("control: connection closed (", sent, " byte(s) response, ", sw.ms(), " ms)");
}

void ControlServer::close() {
    if (fd_ >= 0 || !path_.empty()) LOG_INFO("control: closing ", path_);
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
