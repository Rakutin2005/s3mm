// Standalone s3mmws configuration parser.
//
// s3mmws no longer piggybacks on /etc/s3mm/s3mm.conf (the core daemon's file).
// It reads its own nginx-style config; the root block is `s3mmws { ... }`.
// Unknown directives inside the block are reported as validation errors so a
// typo never silently changes behaviour.
#include "s3mm/rest/wsconfig.hpp"

#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string>

#include "s3mm/common/fs.hpp"
#include "s3mm/config/config.hpp"

namespace s3mm::rest {

namespace {

/// Parse "k1=v1;k2=v2" into a map (used by ldap group_role_map).
std::map<std::string, std::string> parsePairList(const std::string& text) {
    std::map<std::string, std::string> out;
    auto trim = [](const std::string& x) {
        size_t a = x.find_first_not_of(" \t");
        size_t b = x.find_last_not_of(" \t");
        if (a == std::string::npos) return std::string();
        return x.substr(a, b - a + 1);
    };
    std::istringstream iss(text);
    std::string tok;
    while (std::getline(iss, tok, ';')) {
        size_t eq = tok.find('=');
        if (eq != std::string::npos) out[trim(tok.substr(0, eq))] = trim(tok.substr(eq + 1));
    }
    return out;
}

void applyAuthBlock(const config::Node* authn, AuthSettings& auth) {
    if (!authn || !authn->block) return;
    const config::Node* loc = authn->find("local");
    if (loc && loc->block) {
        auth.localEnabled = loc->boolValue("enabled", true);
        if (!loc->value("users_file").empty()) auth.usersFile = loc->value("users_file");
    }
    const config::Node* ldap = authn->find("ldap");
    if (ldap && ldap->block) {
        auth.ldap.enabled = ldap->boolValue("enabled", false);
        if (!ldap->value("url").empty()) auth.ldap.url = ldap->value("url");
        if (!ldap->value("bind_dn").empty()) auth.ldap.bindDn = ldap->value("bind_dn");
        // bind_password may come inline or from a file (preferred).
        std::string bp = ldap->value("bind_password");
        std::string bpf = ldap->value("bind_password_file");
        if (!bpf.empty()) {
            auto content = fs::readFile(bpf);
            if (content) auth.ldap.bindPassword = *content;
        } else if (!bp.empty()) {
            auth.ldap.bindPassword = bp;
        }
        if (!ldap->value("user_search_base").empty()) auth.ldap.userSearchBase = ldap->value("user_search_base");
        if (!ldap->value("user_filter").empty()) auth.ldap.userFilter = ldap->value("user_filter");
        if (!ldap->value("group_search_base").empty()) auth.ldap.groupSearchBase = ldap->value("group_search_base");
        if (!ldap->value("group_filter").empty()) auth.ldap.groupFilter = ldap->value("group_filter");
        if (!ldap->value("attr_uid").empty()) auth.ldap.attrUid = ldap->value("attr_uid");
        if (!ldap->value("attr_mail").empty()) auth.ldap.attrMail = ldap->value("attr_mail");
        if (!ldap->value("attr_display_name").empty()) auth.ldap.attrDisplayName = ldap->value("attr_display_name");
        std::string gm = ldap->value("group_role_map");
        if (!gm.empty()) auth.ldap.groupRoleMap = parsePairList(gm);
    }
    const config::Node* kc = authn->find("keycloak");
    if (kc && kc->block) {
        auth.keycloak.enabled = kc->boolValue("enabled", false);
        if (!kc->value("issuer").empty()) auth.keycloak.issuer = kc->value("issuer");
        if (!kc->value("client_id").empty()) auth.keycloak.clientId = kc->value("client_id");
        std::string cs = kc->value("client_secret");
        std::string csf = kc->value("client_secret_file");
        if (!csf.empty()) {
            auto content = fs::readFile(csf);
            if (content) auth.keycloak.clientSecret = *content;
        } else if (!cs.empty()) {
            auth.keycloak.clientSecret = cs;
        }
        if (!kc->value("realm_roles_map").empty()) auth.keycloak.realmRolesMap = kc->value("realm_roles_map");
        auth.keycloak.useIntrospection = kc->boolValue("use_introspection", auth.keycloak.useIntrospection);
    }
}

// Directive whitelist for better error messages: name -> minimum args.
// A directive not present here is rejected ("unknown directive").
const std::map<std::string, size_t>& wsDirectives() {
    static const std::map<std::string, size_t> d = {
        {"socket", 1}, {"modules_dir", 1}, {"listen", 1}, {"port", 1},
        {"auth_enabled", 1}, {"session_ttl", 1}, {"rbac_store", 1}, {"users_file", 1},
    };
    return d;
}
const std::set<std::string>& wsBlocks() {
    static const std::set<std::string> b = {"auth", "wscluster"};
    return b;
}

Result<Options> loadAndApply(const std::string& path, const Options& base, bool validateOnly) {
    Options o = base;
    auto cfg = config::Config::load(path);
    if (!cfg) return Result<Options>::failure(path + ": " + cfg.error());
    const config::Node* root = cfg.value().s3mm();
    // Config keeps the first top-level block as s3mm(); our root block is
    // named "s3mmws". Fall back to scanning roots explicitly.
    if (!root || root->name != "s3mmws") {
        root = nullptr;
        for (const auto& n : cfg.value().roots()) {
            if (n.name == "s3mmws") { root = &n; break; }
        }
    }
    if (!root) {
        return Result<Options>::failure(path + ": missing 's3mmws { }' root block");
    }

    // Whitelist check: reject unknown directives/blocks early.
    for (const auto& child : root->children) {
        if (child.block) {
            if (!wsBlocks().count(child.name))
                return Result<Options>::failure(path + ":" + std::to_string(child.line) +
                                                ": unknown block '" + child.name + "' in s3mmws");
        } else {
            auto it = wsDirectives().find(child.name);
            if (it == wsDirectives().end())
                return Result<Options>::failure(path + ":" + std::to_string(child.line) +
                                                ": unknown directive '" + child.name + "' in s3mmws");
            if (child.args.size() < it->second)
                return Result<Options>::failure(path + ":" + std::to_string(child.line) +
                                                ": directive '" + child.name + "' requires an argument");
        }
    }

    if (!validateOnly) {
        // Transport / integration settings. Only fill what the CLI left unset.
        if (!base.socketSet && !root->value("socket").empty()) o.socket = root->value("socket");
        if (!base.modulesDirSet && !root->value("modules_dir").empty()) o.modulesDir = root->value("modules_dir");
        if (!base.listenSet && !root->value("listen").empty()) o.listen = root->value("listen");
        if (!base.portSet && root->int64Value("port", 0) > 0) o.port = (int)root->int64Value("port", o.port);

        // Auth settings (file may override defaults; CLI flags still win via *Set).
        if (root->findName("auth_enabled")) o.auth.enabled = root->boolValue("auth_enabled", o.auth.enabled);
        if (root->int64Value("session_ttl", 0) > 0) o.auth.sessionTtl = (int)root->int64Value("session_ttl", o.auth.sessionTtl);
        if (!root->value("rbac_store").empty()) o.auth.rbacStorePath = root->value("rbac_store");
        if (!root->value("users_file").empty()) o.auth.usersFile = root->value("users_file");
        applyAuthBlock(root->find("auth"), o.auth);

        // WS cluster (peer mesh of s3mmws instances).
        const config::Node* wc = root->find("wscluster");
        if (wc && wc->block) {
            o.wscluster.enabled = wc->boolValue("enabled", false);
            if (!wc->value("bind").empty()) o.wscluster.bind = wc->value("bind");
            if (wc->int64Value("port", 0) > 0) o.wscluster.port = (int)wc->int64Value("port", o.wscluster.port);
            o.wscluster.certsDir = wc->value("certs_dir");
            o.wscluster.useMtls = wc->boolValue("use_mtls", o.wscluster.useMtls);
            o.wscluster.clusterSecret = wc->value("cluster_secret");
            for (const auto* p : wc->findAll("peer"))
                if (p->hasArg(0)) o.wscluster.peers.push_back(p->arg(0));
        }
    }
    return o;
}

}  // namespace

Result<Options> WsConfig::apply(const std::string& path, const Options& base) {
    return loadAndApply(path, base, /*validateOnly=*/false);
}

Result<bool> WsConfig::validate(const std::string& path) {
    Options probe;
    auto r = loadAndApply(path, probe, /*validateOnly=*/true);
    if (!r) return Result<bool>::failure(r.error());
    return Result<bool>(true);
}

}  // namespace s3mm::rest
