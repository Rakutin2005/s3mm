#pragma once
#include <functional>
#include <string>

#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::daemon {

/// Minimal HTTP/1.0 responder for the Prometheus endpoint (`/metrics`).
/// Runs inside the daemon's poll loop: one request per connection.
class MetricsServer {
public:
    using Handler = std::function<std::string()>;

    MetricsServer() = default;
    ~MetricsServer();

    /// "127.0.0.1:9108"; returns the bound socket fd or an error.
    Result<int> listen(const std::string& address);
    /// Handle one pending connection (non-blocking fd assumed ready).
    void acceptOne(const Handler& handler);
    void close();

    int fd() const { return fd_; }

private:
    int fd_ = -1;
};

} // namespace s3mm::daemon
