#include "s3mm/cli/client.hpp"

#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "s3mm/common/error.hpp"
#include "s3mm/common/log.hpp"

namespace s3mm::cli {

Client::Client(std::string socketPath) : socketPath_(std::move(socketPath)) {}

Value Client::call(const Value& request) {
    log::Stopwatch sw;
    std::string cmd = request.getString("cmd");
    std::string kind = request.getString("kind");
    std::string what = cmd + (kind.empty() ? "" : " " + kind);
    LOG_DEBUG("control: calling '", what, "' on ", socketPath_);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socketPath_.size() >= sizeof(addr.sun_path)) {
        LOG_ERROR("control: socket path too long (", socketPath_.size(), " bytes): ", socketPath_);
        throw ConnectionError("socket path too long: " + socketPath_);
    }
    std::strncpy(addr.sun_path, socketPath_.c_str(), sizeof(addr.sun_path) - 1);

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        std::string err = std::strerror(errno);
        LOG_ERROR("control: socket() for ", socketPath_, " failed: ", err);
        throw ConnectionError("socket " + socketPath_ + ": " + err);
    }

    // Only a failed connect marks the daemon as unreachable: once connected,
    // I/O failures are reported as regular errors so that a mutation which may
    // already have been applied is never replayed in offline mode.
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::string err = std::strerror(errno);
        ::close(fd);
        LOG_ERROR("control: cannot connect to s3mmd at ", socketPath_, ": ", err);
        throw ConnectionError("cannot connect to " + socketPath_ + ": " + err);
    }
    LOG_DEBUG("control: connected to ", socketPath_, " (fd ", fd, ")");

    std::string line = request.toJson(0) + "\n";
    size_t sent = 0;
    while (sent < line.size()) {
        ssize_t n = ::write(fd, line.data() + sent, line.size() - sent);
        if (n <= 0) {
            std::string err = std::strerror(errno);
            ::close(fd);
            LOG_ERROR("control: write of '", what, "' to ", socketPath_, " failed after ", sent, "/", line.size(),
                      " bytes: ", err);
            throw Error("write to " + socketPath_ + " failed: " + err);
        }
        sent += (size_t)n;
    }

    // Read the single reply; the daemon closes the connection afterwards.
    std::string reply;
    char buf[8192];
    for (;;) {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0) {
            std::string err = std::strerror(errno);
            ::close(fd);
            LOG_ERROR("control: read of reply to '", what, "' from ", socketPath_, " failed: ", err);
            throw Error("read from " + socketPath_ + " failed: " + err);
        }
        if (n == 0) break;
        reply.append(buf, (size_t)n);
        if (reply.size() > 64ull * 1024 * 1024) {
            LOG_WARN("control: reply to '", what, "' exceeds 64 MiB, truncating");
            break; // safety valve
        }
    }
    ::close(fd);
    LOG_DEBUG("control: sent ", line.size(), " bytes, received ", reply.size(), " bytes for '", what, "'");

    std::string parseError;
    Value parsed = Value::parseJson(reply, &parseError);
    if (!parseError.empty() || !parsed.isObject()) {
        LOG_ERROR("control: unreadable reply to '", what, "' from ", socketPath_, ": ",
                  parseError.empty() ? log::clip(reply) : parseError);
        throw Error("daemon replied with an unreadable message: " +
                    (parseError.empty() ? reply : parseError));
    }
    const Value* ok = parsed.find("ok");
    if (!ok || !ok->asBool(false)) {
        LOG_WARN("control: s3mmd rejected '", what, "': ", parsed.getString("error", "daemon error"), " (", sw.ms(), " ms)");
        throw Error(parsed.getString("error", "daemon error"));
    }
    LOG_DEBUG("control: '", what, "' succeeded in ", sw.ms(), " ms");
    const Value* data = parsed.find("data");
    return data ? *data : Value::null();
}

} // namespace s3mm::cli
