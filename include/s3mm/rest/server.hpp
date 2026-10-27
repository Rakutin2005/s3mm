#pragma once
#include <cstdint>
#include <functional>
#include <string>

#include "s3mm/common/result.hpp"
#include "s3mm/rest/module.hpp"

namespace s3mm::rest {

/// Sequence number of the request being handled (0 outside a request).
uint64_t currentRequestId();
/// "req#N " prefix for log lines that belong to the current request.
std::string requestTag();

class HttpServer {
public:
    using Handler = std::function<void(const RestRequest&, RestResponse&)>;
    Result<void> listen(const std::string& address, int port);
    void acceptOne(const Handler& handler);
    void close();
    int fd() const { return fd_; }
private:
    int fd_ = -1;
};

} // namespace s3mm::rest
