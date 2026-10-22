#include "s3mm/rest/router.hpp"

namespace s3mm::rest {

std::string Router::key(const std::string& method, const std::string& path) {
    return method + " " + path;
}

void Router::add(const std::string& method, const std::string& path, Handler h) {
    handlers_[key(method, path)] = std::move(h);
}

bool Router::route(const RestRequest& req, RestResponse& res) const {
    auto it = handlers_.find(key(req.method, req.path));
    if (it == handlers_.end()) return false;
    it->second(req, res);
    return true;
}

} // namespace s3mm::rest
