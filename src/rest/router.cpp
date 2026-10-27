#include "s3mm/rest/router.hpp"

#include "s3mm/common/log.hpp"
#include "s3mm/rest/server.hpp"

namespace s3mm::rest {

std::string Router::key(const std::string& method, const std::string& path) {
    return method + " " + path;
}

void Router::add(const std::string& method, const std::string& path, Handler h) {
    if (handlers_.count(key(method, path))) LOG_WARN("router: route ", method, " ", path, " registered twice, replacing");
    else LOG_DEBUG("router: registered route ", method, " ", path);
    handlers_[key(method, path)] = std::move(h);
}

bool Router::route(const RestRequest& req, RestResponse& res) const {
    auto it = handlers_.find(key(req.method, req.path));
    if (it == handlers_.end()) {
        LOG_DEBUG(requestTag(), "router: no route for ", req.method, " ", req.path);
        return false;
    }
    LOG_DEBUG(requestTag(), "router: dispatching ", req.method, " ", req.path);
    log::Stopwatch sw;
    it->second(req, res);
    LOG_DEBUG(requestTag(), "router: handler ", req.method, " ", req.path, " finished with ", res.status, " in ", sw.ms(), " ms");
    return true;
}

} // namespace s3mm::rest
