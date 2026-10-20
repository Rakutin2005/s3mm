#include "s3mm/cli/client.hpp"

#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "s3mm/common/error.hpp"

namespace s3mm::cli {

Client::Client(std::string socketPath) : socketPath_(std::move(socketPath)) {}

Value Client::call(const Value& request) {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socketPath_.size() >= sizeof(addr.sun_path))
        throw ConnectionError("socket path too long: " + socketPath_);
    std::strncpy(addr.sun_path, socketPath_.c_str(), sizeof(addr.sun_path) - 1);

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        throw ConnectionError("socket " + socketPath_ + ": " + std::strerror(errno));

    // Only a failed connect marks the daemon as unreachable: once connected,
    // I/O failures are reported as regular errors so that a mutation which may
    // already have been applied is never replayed in offline mode.
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::string err = std::strerror(errno);
        ::close(fd);
        throw ConnectionError("cannot connect to " + socketPath_ + ": " + err);
    }

    std::string line = request.toJson(0) + "\n";
    size_t sent = 0;
    while (sent < line.size()) {
        ssize_t n = ::write(fd, line.data() + sent, line.size() - sent);
        if (n <= 0) {
            std::string err = std::strerror(errno);
            ::close(fd);
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
            throw Error("read from " + socketPath_ + " failed: " + err);
        }
        if (n == 0) break;
        reply.append(buf, (size_t)n);
        if (reply.size() > 64ull * 1024 * 1024) break; // safety valve
    }
    ::close(fd);

    std::string parseError;
    Value parsed = Value::parseJson(reply, &parseError);
    if (!parseError.empty() || !parsed.isObject())
        throw Error("daemon replied with an unreadable message: " +
                    (parseError.empty() ? reply : parseError));
    const Value* ok = parsed.find("ok");
    if (!ok || !ok->asBool(false))
        throw Error(parsed.getString("error", "daemon error"));
    const Value* data = parsed.find("data");
    return data ? *data : Value::null();
}

} // namespace s3mm::cli
