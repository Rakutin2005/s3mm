#pragma once
#include <functional>
#include <map>
#include <string>

#include "s3mm/rest/module.hpp"

namespace s3mm::rest {

class Router {
public:
    using Handler = std::function<void(const RestRequest&, RestResponse&)>;
    void add(const std::string& method, const std::string& path, Handler h);
    bool route(const RestRequest& req, RestResponse& res) const;
private:
    std::map<std::string, Handler> handlers_;
    static std::string key(const std::string& method, const std::string& path);
};

} // namespace s3mm::rest
