#pragma once
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"
#include "s3mm/cli/client.hpp"

namespace s3mm::rest {

struct RestRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> query;
    std::string body;
};

struct RestResponse {
    int status = 200;
    std::map<std::string, std::string> headers;
    std::string body;

    void json(const Value& v) {
        body = v.toJson(0);
        headers["Content-Type"] = "application/json";
    }
    void text(const std::string& s, const std::string& contentType = "text/plain") {
        body = s;
        headers["Content-Type"] = contentType;
    }
};

struct RestModuleInfo {
    const char* name = "unknown";
    const char* version = "0.1.0";
    const char* vendor = "generic";
};

class Router;

class RestContext {
public:
    RestContext(cli::Client& daemon, const std::string& modulesDir)
        : daemon_(daemon), modulesDir_(modulesDir) {}
    cli::Client& daemon() { return daemon_; }
    const std::string& modulesDir() const { return modulesDir_; }
private:
    cli::Client& daemon_;
    std::string modulesDir_;
};

class IRestModule {
public:
    virtual ~IRestModule() = default;
    virtual RestModuleInfo info() const = 0;
    virtual void onLoad(RestContext&) {}
    virtual bool authenticate(const RestRequest&, RestResponse&) { return true; }
    virtual bool process(const RestRequest&, RestResponse&) { return false; }
    virtual void registerRoutes(Router&) {}
};

extern "C" {
typedef IRestModule* (*CreateRestModuleFn)();
}

#define S3MM_REST_MODULE_ENTRY(ClassName) \
    extern "C" s3mm::rest::IRestModule* s3mm_rest_module_entry() { return new ClassName(); }

} // namespace s3mm::rest
