#pragma once
#include <memory>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/rest/server.hpp"
#include "s3mm/rest/router.hpp"
#include "s3mm/rest/loader.hpp"
#include "s3mm/rest/module.hpp"
#include "s3mm/rest/auth.hpp"
#include "s3mm/rest/rbac.hpp"
#include "s3mm/rest/cluster.hpp"
#include "s3mm/registry/registry.hpp"
#include "s3mm/s3/client.hpp"
#include "s3mm/cli/client.hpp"

namespace s3mm::rest {

struct AuthSettings {
    bool enabled = false;
    int sessionTtl = 3600;
    std::string rbacStorePath;
    std::string usersFile;
    LdapConfig ldap;
    KeycloakConfig keycloak;
    bool localEnabled = true;
};

struct WsClusterSettings {
    bool enabled = false;
    std::string bind = "127.0.0.1";
    int port = 9443;
    std::string certsDir;
    bool useMtls = true;
    std::string clusterSecret;
    std::vector<std::string> peers;
};

struct Options {
    std::string config = "/etc/s3mm/s3mm.conf";
    std::string socket;
    std::string listen = "127.0.0.1";
    int port = 8080;
    std::string modulesDir;
    bool daemonize = false;
    bool validateOnly = false;
    AuthSettings auth;
    WsClusterSettings wscluster;
};

class RestDaemon {
public:
    explicit RestDaemon(Options options);
    int run();
    // accessors for handlers
    SessionManager& sessions() { return *sessions_; }
    RbacStore& rbac() { return *rbac_; }
    LocalAuthProvider* local() { return local_.get(); }
    LdapAuthProvider* ldap() { return ldap_.get(); }
    KeycloakAuthProvider* keycloak() { return keycloak_.get(); }
    bool authEnabled() const { return options_.auth.enabled; }
    const AuthSettings& authSettings() const { return options_.auth; }
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
    std::unique_ptr<SessionManager> sessions_;
    std::unique_ptr<RbacStore> rbac_;
    std::unique_ptr<LocalAuthProvider> local_;
    std::unique_ptr<LdapAuthProvider> ldap_;
    std::unique_ptr<KeycloakAuthProvider> keycloak_;
    std::unique_ptr<ClusterManager> cluster_;
};

} // namespace s3mm::rest
