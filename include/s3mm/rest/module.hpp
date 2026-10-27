#pragma once
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"
#include "s3mm/cli/client.hpp"
#include "s3mm/config/config.hpp"

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

/// A REST module (s3mmws_mod_<name>.so) is loaded only when the s3mmws
/// configuration has a `module <name> { ... }` block; the block is handed to
/// configure() before onLoad(). Its routes should live under /ext/<name>/.
///
/// uiExtension() describes a page that the web UI adds to its navigation
/// while the module is loaded (GET /ui/extensions). Schema:
///   { "id": "<name>", "title": "...", "icon": "cluster|api|cloud|database|
///     link|monitor|setting", "refresh": <seconds>, "sections": [ <section> ] }
/// <section>:
///   { "type": "kv",    "title": "...", "source": "/ext/..", "path": "a.b",
///     "fields": [ {"key": "...", "title": "..."} ] }            // object view
///   { "type": "table", "title": "...", "source": "/ext/..", "path": "a.b",
///     "rowKey": "id", "columns": [ {"key": "...", "title": "...",
///     "type": "text|bool|tag|json"} ],
///     "rowActions": [ <action> ] }                              // array view
///   { "type": "actions", "title": "...", "actions": [ <action> ] }
///   { "type": "json",  "title": "...", "source": "/ext/..", "path": "a.b" }
/// <action>: { "label": "...", "method": "POST|PUT|DELETE",
///   "endpoint": "/ext/..?x={field}", "body": { "k": "{field}" },
///   "fields": [ {"name": "...", "label": "...", "type": "text|bool|number",
///   "required": true} ], "confirm": "...", "danger": true }
///   "{name}" placeholders are filled from the form fields or the table row.
class IRestModule {
public:
    virtual ~IRestModule() = default;
    virtual RestModuleInfo info() const = 0;
    /// `module <name> { ... }` block of the s3mmws configuration.
    virtual Result<void> configure(const config::Node&) { return Result<void>::success(); }
    /// Web UI page of the module, Value::null() when it has none.
    virtual Value uiExtension() const { return Value::null(); }
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
