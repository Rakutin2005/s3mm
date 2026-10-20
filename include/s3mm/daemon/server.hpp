#pragma once
#include <functional>
#include <string>

#include "s3mm/common/value.hpp"
#include "s3mm/common/result.hpp"

namespace s3mm::daemon {

/// CLI control server on a UNIX socket. The protocol is one JSON request line
/// followed by one JSON response line:
///
///   -> {"cmd":"list","kind":"clusters"}
///   <- {"ok":true,"data":[...]}
///   <- {"ok":false,"error":"unknown cluster 'x'"}
class ControlServer {
public:
    /// Handler for a decoded request; returns the "data" payload or throws
    /// s3mm::Error to signal a failure.
    using Handler = std::function<Value(const Value& request)>;

    Result<void> listen(const std::string& socketPath);
    /// Handle one pending connection.
    void acceptOne(const Handler& handler);
    void close();

    int fd() const { return fd_; }
    const std::string& path() const { return path_; }

private:
    int fd_ = -1;
    std::string path_;
};

} // namespace s3mm::daemon
