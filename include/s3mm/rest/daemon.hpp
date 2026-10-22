#pragma once
#include <string>

#include "s3mm/common/result.hpp"
#include "s3mm/rest/server.hpp"
#include "s3mm/rest/router.hpp"
#include "s3mm/rest/loader.hpp"
#include "s3mm/rest/module.hpp"
#include "s3mm/registry/registry.hpp"
#include "s3mm/s3/client.hpp"
#include "s3mm/cli/client.hpp"

namespace s3mm::rest {

struct Options {
    std::string config = "/etc/s3mm/s3mm.conf";
    std::string socket;          // main daemon socket
    std::string listen = "127.0.0.1";
    int port = 8080;
    std::string modulesDir;
    bool daemonize = false;
    bool validateOnly = false;
};

class RestDaemon {
public:
    explicit RestDaemon(Options options);
    int run();
private:
    Options options_;
    cli::Client daemonClient_;
    RestModuleLoader loader_;
    std::unique_ptr<registry::Registry> registry_;
    std::unique_ptr<s3::Client> makeClient(const std::string& clusterName);
    std::vector<IRestModule*> modules_;
    Router router_;
    HttpServer http_;
    void registerDefaults();
};

} // namespace s3mm::rest
