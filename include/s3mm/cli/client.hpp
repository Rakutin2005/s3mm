#pragma once
#include <stdexcept>
#include <string>

#include "s3mm/common/value.hpp"

namespace s3mm::cli {

/// The control socket could not be reached (daemon not running, bad path, ...).
class ConnectionError : public std::runtime_error {
public:
    explicit ConnectionError(const std::string& message) : std::runtime_error(message) {}
};

/// Newline-delimited JSON client for the daemon control socket.
/// Protocol: one connection = one request; the daemon replies with a single
/// line `{"ok":true,"data":...}` / `{"ok":false,"error":...}` and closes.
class Client {
public:
    explicit Client(std::string socketPath);

    /// Throws ConnectionError when the daemon cannot be reached,
    /// Error when the daemon answers with {"ok":false,...}.
    Value call(const Value& request);

    const std::string& socketPath() const { return socketPath_; }

private:
    std::string socketPath_;
};

} // namespace s3mm::cli
