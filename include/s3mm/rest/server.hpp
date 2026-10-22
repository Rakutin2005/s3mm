#pragma once
#include <functional>
#include <string>

#include "s3mm/common/result.hpp"
#include "s3mm/rest/module.hpp"

namespace s3mm::rest {

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
