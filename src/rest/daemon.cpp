#include "s3mm/rest/daemon.hpp"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <chrono>
#include <poll.h>
#include <unistd.h>
#include "s3mm/rest/cluster.hpp"
#include "s3mm/rest/module.hpp"
#include <curl/curl.h>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/time.hpp"
#include "s3mm/common/units.hpp"
#include "s3mm/common/crypto.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/registry/registry.hpp"
#include "s3mm/s3/client.hpp"
#include "s3mm/s3/http.hpp"
#include "s3mm/rest/rbac.hpp"

namespace s3mm::rest {

namespace {
volatile std::sig_atomic_t gStop = 0;
volatile std::sig_atomic_t gSignal = 0;
void onSignal(int sig) { gStop = 1; gSignal = sig; }
volatile std::sig_atomic_t gHup = 0;
void onReloadSignal(int) { gHup = 1; }

// Identity of the caller of the request being handled, for audit lines.
std::string gUser = "-";
std::string who() { return requestTag() + "user '" + gUser + "': "; }

static void logPeerCall(const char* method, const std::string& url, CURL* curl, CURLcode rc, const char* errbuf,
                        size_t sentBytes, size_t respBytes, const log::Stopwatch& sw) {
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc != CURLE_OK) {
        LOG_ERROR(requestTag(), "peer: ", method, " ", url, " failed: ", curl_easy_strerror(rc),
                  errbuf[0] ? std::string(" (") + errbuf + ")" : std::string(), " after ", sw.ms(), " ms");
        return;
    }
    if (status >= 400)
        LOG_WARN(requestTag(), "peer: ", method, " ", url, " -> HTTP ", status, ", sent ", sentBytes, " B, received ",
                 respBytes, " B, ", sw.ms(), " ms");
    else
        LOG_DEBUG(requestTag(), "peer: ", method, " ", url, " -> HTTP ", status, ", sent ", sentBytes, " B, received ",
                  respBytes, " B, ", sw.ms(), " ms");
}

static size_t curlWriteCb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* s = (std::string*)userdata;
    s->append(ptr, size*nmemb);
    return size*nmemb;
}

static std::string httpGetJson(const std::string& address, const std::string& path, const std::string& secret="") {
    CURL* curl = curl_easy_init();
    if (!curl) {
        LOG_ERROR(requestTag(), "peer: curl_easy_init failed for ", address, path);
        return "";
    }
    log::Stopwatch sw;
    char errbuf[CURL_ERROR_SIZE] = "";
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    std::string url = address;
    if (url.find("http") != 0) url = "http://" + url;
    if (url.back() == '/') url.pop_back();
    url += path;
    LOG_DEBUG(requestTag(), "peer: GET ", url, " (cluster secret ", secret.empty() ? "not sent" : "sent", ")");
    std::string resp;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "X-No-Peer-Merge: 1");
    if (!secret.empty()) {
        std::string h = "X-Cluster-Secret: " + secret;
        headers = curl_slist_append(headers, h.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    CURLcode rc = curl_easy_perform(curl);
    logPeerCall("GET", url, curl, rc, errbuf, 0, resp.size(), sw);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}

static std::string httpPutJson(const std::string& address, const std::string& path, const std::string& body, const std::string& secret="") {
    CURL* curl = curl_easy_init();
    if (!curl) {
        LOG_ERROR(requestTag(), "peer: curl_easy_init failed for ", address, path);
        return "";
    }
    log::Stopwatch sw;
    char errbuf[CURL_ERROR_SIZE] = "";
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    std::string url = address;
    if (url.find("http") != 0) url = "http://" + url;
    if (url.back() == '/') url.pop_back();
    url += path;
    LOG_DEBUG(requestTag(), "peer: PUT ", url, " (", body.size(), " B, cluster secret ", secret.empty() ? "not sent" : "sent", ")");
    std::string resp;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "X-No-Peer-Merge: 1");
    if (!secret.empty()) {
        std::string h = "X-Cluster-Secret: " + secret;
        headers = curl_slist_append(headers, h.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    CURLcode rc = curl_easy_perform(curl);
    logPeerCall("PUT", url, curl, rc, errbuf, body.size(), resp.size(), sw);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}

static std::string httpPostJson(const std::string& address, const std::string& path, const std::string& body, const std::string& secret="") {
    CURL* curl = curl_easy_init();
    if (!curl) {
        LOG_ERROR(requestTag(), "peer: curl_easy_init failed for ", address, path);
        return "";
    }
    log::Stopwatch sw;
    char errbuf[CURL_ERROR_SIZE] = "";
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    std::string url = address;
    if (url.find("http") != 0) url = "http://" + url;
    if (url.back() == '/') url.pop_back();
    url += path;
    LOG_DEBUG(requestTag(), "peer: POST ", url, " (", body.size(), " B, cluster secret ", secret.empty() ? "not sent" : "sent", ")");
    std::string resp;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "X-No-Peer-Merge: 1");
    if (!secret.empty()) {
        std::string h = "X-Cluster-Secret: " + secret;
        headers = curl_slist_append(headers, h.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    CURLcode rc = curl_easy_perform(curl);
    logPeerCall("POST", url, curl, rc, errbuf, body.size(), resp.size(), sw);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}
}

RestDaemon::RestDaemon(Options options)
    : options_(std::move(options)),
      daemonClient_(options_.socket.empty() ? "/run/s3mm/s3mm.sock" : options_.socket) {}

std::unique_ptr<s3::Client> RestDaemon::makeClient(const std::string& clusterName) {
    if (!registry_) {
        LOG_ERROR(who(), "s3: no registry loaded (configuration missing or invalid), cannot reach cluster '", clusterName, "'");
        return nullptr;
    }
    const registry::Cluster* cluster = registry_->cluster(clusterName);
    if (!cluster) {
        LOG_WARN(who(), "s3: cluster '", clusterName, "' is not defined in the configuration");
        return nullptr;
    }
    const registry::Credential* cred = registry_->bestCredential(*cluster);
    if (!cred) {
        LOG_ERROR(who(), "s3: cluster '", clusterName, "' has no usable credential");
        return nullptr;
    }
    s3::ClientOptions opts;
    opts.endpoints = cluster->endpoints;
    opts.pathStyle = cluster->pathStyle;
    opts.insecure = cluster->insecure;
    opts.timeoutSec = cluster->timeoutSec;
    opts.connectTimeoutSec = cluster->connectTimeoutSec;
    opts.rateLimitPerSec = cluster->rateLimitPerSec;
    opts.maxRetries = cluster->retries;
    sigv4::Credentials credentials{cred->accessKey, cred->secretKey, cred->sessionToken, cred->region};
    LOG_DEBUG(who(), "s3: client for cluster '", clusterName, "': endpoints [", str::join(opts.endpoints, ","),
              "], path_style ", opts.pathStyle ? "on" : "off", ", insecure ", opts.insecure ? "on" : "off", ", timeout ",
              opts.timeoutSec, "s, connect timeout ", opts.connectTimeoutSec, "s, retries ", opts.maxRetries,
              ", credential '", cred->name, "' (access key ", cred->accessKey, ", region ", cred->region, ")");
    return std::make_unique<s3::Client>(opts, credentials);
}

void RestDaemon::registerDefaults() {
    router_.add("GET", "/health", [](const RestRequest&, RestResponse& res) {
        res.json(Value::object());
        res.body = "{\"ok\":true}\n";
    });
    router_.add("GET", "/status", [this](const RestRequest&, RestResponse& res) {
        try {
            Value data = daemonClient_.call(Value::object().set("cmd", Value::str("status")));
            LOG_DEBUG(who(), "status: s3mmd answered");
            res.json(data);
        } catch (const std::exception& e) {
            LOG_ERROR(who(), "status: s3mmd at ", daemonClient_.socketPath(), " unavailable: ", e.what());
            res.status = 502;
            res.json(Value::object().set("error", Value::str(e.what())));
        }
    });
    router_.add("GET", "/modules", [this](const RestRequest&, RestResponse& res) {
        Value arr = Value::array();
        for (const auto* m : modules_) {
            Value v = Value::object();
            auto info = m->info();
            v.set("name", Value::str(info.name));
            v.set("version", Value::str(info.version));
            v.set("vendor", Value::str(info.vendor));
            v.set("ui", Value::boolean(!m->uiExtension().isNull()));
            arr.push(v);
        }
        res.json(arr);
    });
    router_.add("GET", "/ui/extensions", [this](const RestRequest&, RestResponse& res) {
        Value arr = Value::array();
        for (const auto* m : modules_) {
            Value ext = m->uiExtension();
            if (ext.isNull() || !ext.isObject()) continue;
            if (ext.getString("id").empty()) ext.set("id", Value::str(m->info().name));
            ext.set("module", Value::str(m->info().name));
            arr.push(ext);
        }
        LOG_DEBUG(who(), "ui: ", arr.items().size(), " web UI extension(s) served");
        res.json(arr);
    });
    router_.add("POST", "/rpc", [this](const RestRequest& req, RestResponse& res) {
        std::string parseError;
        Value parsed = Value::parseJson(req.body, &parseError);
        if (!parseError.empty() || !parsed.isObject()) {
            LOG_WARN(who(), "rpc: invalid JSON body: ", parseError.empty() ? "not an object" : parseError);
            res.status = 400;
            res.json(Value::object().set("error", Value::str("bad request")));
            return;
        }
        std::string rpcWhat = parsed.getString("cmd") + " " + parsed.getString("kind") + " " + parsed.getString("name");
        LOG_INFO(who(), "rpc: forwarding '", str::trim(rpcWhat), "' to s3mmd");
        try {
            Value data = daemonClient_.call(parsed);
            // If this is a list command, tag ownership and merge from peers.
            std::string cmd = parsed.find("cmd") && parsed.find("cmd")->isString() ? parsed.find("cmd")->asString() : "";
            std::string kind = parsed.find("kind") && parsed.find("kind")->isString() ? parsed.find("kind")->asString() : "";
            bool noMerge = req.headers.count("X-No-Peer-Merge") > 0;
            bool isList = (cmd == "list");
            bool isResource = (kind == "cluster" || kind == "credential" || kind == "replication" || kind == "target" || kind == "policy");
            if (isList && isResource && data.isArray() && cluster_ && !noMerge) {
                LOG_DEBUG(who(), "rpc: merging '", kind, "' list (", data.items().size(), " local items) with ",
                          cluster_->peers().size(), " peers");
                std::string localOwner = "local";
                Value merged = Value::array();
                for (auto& it : data.items()) {
                    Value copy = it;
                    if (copy.isObject()) copy.set("_owner", Value::str(localOwner));
                    merged.push(copy);
                }
                for (auto& peer : cluster_->peers()) {
                    std::string peerResp = httpPostJson(peer.address, "/rpc", req.body, cluster_ ? cluster_->config().clusterSecret : "");
                    std::string perr; Value pv = Value::parseJson(peerResp, &perr);
                    if (!perr.empty() || !pv.isArray())
                        LOG_WARN(who(), "rpc: peer ", peer.address, " returned no usable '", kind, "' list (",
                                 perr.empty() ? "not an array" : perr, "), skipping it");
                    if (perr.empty() && pv.isArray()) {
                        LOG_DEBUG(who(), "rpc: peer ", peer.address, " returned ", pv.items().size(), " items");
                        std::string owner = peer.address;
                        for (auto& it : pv.items()) {
                            if (it.isObject() && it.find("name") && it.find("name")->isString()) {
                                std::string nm = it.find("name")->asString();
                                // skip proxy clusters and duplicates of local clusters
                                if (nm.rfind("peer-", 0) == 0) continue;
                                bool existsLocal = false;
                                for (auto& lit : data.items()) {
                                    if (lit.isObject() && lit.find("name") && lit.find("name")->isString() && lit.find("name")->asString() == nm) { existsLocal = true; break; }
                                }
                                if (existsLocal) continue;
                            }
                            Value copy = it;
                            if (copy.isObject()) copy.set("_owner", Value::str(owner));
                            merged.push(copy);
                        }
                    }
                }
                data = merged;
                LOG_DEBUG(who(), "rpc: merged list has ", data.items().size(), " items");
            } else if (isList && isResource && noMerge) {
                LOG_DEBUG(who(), "rpc: peer merge suppressed by X-No-Peer-Merge");
            }
            LOG_DEBUG(who(), "rpc: '", str::trim(rpcWhat), "' succeeded");
            res.json(data);
        } catch (const std::exception& e) {
            LOG_ERROR(who(), "rpc: '", str::trim(rpcWhat), "' failed: ", e.what());
            res.status = 502;
            res.json(Value::object().set("error", Value::str(e.what())));
        }
    });
    // ---- Auth endpoints ----
    router_.add("GET", "/auth/config", [this](const RestRequest&, RestResponse& res) {
        Value out = Value::object();
        Value loc = Value::object(); loc.set("enabled", Value::boolean(local_ && local_->enabled())); loc.set("users_file", Value::str(options_.auth.usersFile)); out.set("local", loc);
        Value ldap = Value::object();
        ldap.set("enabled", Value::boolean(options_.auth.ldap.enabled));
        ldap.set("url", Value::str(options_.auth.ldap.url));
        ldap.set("bind_dn", Value::str(options_.auth.ldap.bindDn));
        ldap.set("user_search_base", Value::str(options_.auth.ldap.userSearchBase));
        ldap.set("user_filter", Value::str(options_.auth.ldap.userFilter));
        ldap.set("group_search_base", Value::str(options_.auth.ldap.groupSearchBase));
        ldap.set("group_filter", Value::str(options_.auth.ldap.groupFilter));
        ldap.set("attr_uid", Value::str(options_.auth.ldap.attrUid));
        ldap.set("attr_mail", Value::str(options_.auth.ldap.attrMail));
        ldap.set("attr_display_name", Value::str(options_.auth.ldap.attrDisplayName));
        // group_role_map as string
        std::ostringstream gm;
        bool first=true;
        for (auto& [k,v] : options_.auth.ldap.groupRoleMap) { if(!first) gm<<";"; first=false; gm<<k<<"="<<v; }
        ldap.set("group_role_map", Value::str(gm.str()));
        out.set("ldap", ldap);
        Value kc = Value::object();
        kc.set("enabled", Value::boolean(options_.auth.keycloak.enabled));
        kc.set("issuer", Value::str(options_.auth.keycloak.issuer));
        kc.set("client_id", Value::str(options_.auth.keycloak.clientId));
        kc.set("realm_roles_map", Value::str(options_.auth.keycloak.realmRolesMap));
        kc.set("use_introspection", Value::boolean(options_.auth.keycloak.useIntrospection));
        out.set("keycloak", kc);
        res.json(out);
    });
    router_.add("PUT", "/auth/config", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body,&pe);
        if (pe.size()||!body.isObject()){res.status=400;res.json(Value::object().set("error",Value::str("bad request")));return;}
        LOG_NOTICE(who(), "auth config: update requested for sections [", body.find("local") ? "local " : "",
                   body.find("ldap") ? "ldap " : "", body.find("keycloak") ? "keycloak" : "", "]");
        if (const Value* loc = body.find("local")) if (loc && loc->isObject()) {
            if (loc->find("enabled")) options_.auth.localEnabled = loc->find("enabled")->asBool(options_.auth.localEnabled);
            if (auto v=loc->find("users_file")) if (v && v->isString()) options_.auth.usersFile = v->asString();
            if (local_) local_->setEnabled(options_.auth.localEnabled);
            LOG_INFO(who(), "auth config: local provider ", options_.auth.localEnabled ? "enabled" : "disabled",
                     ", users file ", options_.auth.usersFile);
        }
        if (const Value* l = body.find("ldap")) if (l && l->isObject()) {
            if (l->find("enabled")) options_.auth.ldap.enabled = l->find("enabled")->asBool(options_.auth.ldap.enabled);
            if (auto v=l->find("url")) if(v&&v->isString()) options_.auth.ldap.url=v->asString();
            if (auto v=l->find("bind_dn")) if(v&&v->isString()) options_.auth.ldap.bindDn=v->asString();
            if (auto v=l->find("bind_password")) if(v&&v->isString()) options_.auth.ldap.bindPassword=v->asString();
            if (auto v=l->find("user_search_base")) if(v&&v->isString()) options_.auth.ldap.userSearchBase=v->asString();
            if (auto v=l->find("user_filter")) if(v&&v->isString()) options_.auth.ldap.userFilter=v->asString();
            if (auto v=l->find("group_search_base")) if(v&&v->isString()) options_.auth.ldap.groupSearchBase=v->asString();
            if (auto v=l->find("group_filter")) if(v&&v->isString()) options_.auth.ldap.groupFilter=v->asString();
            if (auto v=l->find("attr_uid")) if(v&&v->isString()) options_.auth.ldap.attrUid=v->asString();
            if (auto v=l->find("attr_mail")) if(v&&v->isString()) options_.auth.ldap.attrMail=v->asString();
            if (auto v=l->find("attr_display_name")) if(v&&v->isString()) options_.auth.ldap.attrDisplayName=v->asString();
            if (auto v=l->find("group_role_map")) if(v&&v->isString()) {
                // parse
                std::map<std::string,std::string> m;
                std::string s=v->asString(); size_t start=0;
                while(true){ size_t semi=s.find(';',start); std::string part=(semi==std::string::npos)?s.substr(start):s.substr(start,semi-start); size_t eq=part.find('='); if(eq!=std::string::npos){ auto trim=[](std::string x){size_t a=x.find_first_not_of(" \t");size_t b=x.find_last_not_of(" \t"); if(a==std::string::npos)return std::string(); return x.substr(a,b-a+1);}; m[trim(part.substr(0,eq))]=trim(part.substr(eq+1)); } if(semi==std::string::npos) break; start=semi+1; }
                options_.auth.ldap.groupRoleMap=m;
            }
            if (ldap_) ldap_->setConfig(options_.auth.ldap);
            LOG_INFO(who(), "auth config: ldap ", options_.auth.ldap.enabled ? "enabled" : "disabled", ", url '",
                     options_.auth.ldap.url, "', bind_dn '", options_.auth.ldap.bindDn, "', bind password ",
                     l->find("bind_password") ? "changed" : "unchanged", ", ", options_.auth.ldap.groupRoleMap.size(),
                     " group mappings");
        }
        if (const Value* k = body.find("keycloak")) if (k && k->isObject()) {
            if (k->find("enabled")) options_.auth.keycloak.enabled = k->find("enabled")->asBool(options_.auth.keycloak.enabled);
            if (auto v=k->find("issuer")) if(v&&v->isString()) options_.auth.keycloak.issuer=v->asString();
            if (auto v=k->find("client_id")) if(v&&v->isString()) options_.auth.keycloak.clientId=v->asString();
            if (auto v=k->find("client_secret")) if(v&&v->isString()) options_.auth.keycloak.clientSecret=v->asString();
            if (auto v=k->find("realm_roles_map")) if(v&&v->isString()) options_.auth.keycloak.realmRolesMap=v->asString();
            if (k->find("use_introspection")) options_.auth.keycloak.useIntrospection = k->find("use_introspection")->asBool(options_.auth.keycloak.useIntrospection);
            if (keycloak_) keycloak_->setConfig(options_.auth.keycloak);
            LOG_INFO(who(), "auth config: keycloak ", options_.auth.keycloak.enabled ? "enabled" : "disabled",
                     ", issuer '", options_.auth.keycloak.issuer, "', client_id '", options_.auth.keycloak.clientId,
                     "', client secret ", k->find("client_secret") ? "changed" : "unchanged");
        }
        // persist to auth_config.json next to rbac store
        std::string dir = options_.auth.rbacStorePath;
        size_t slash = dir.find_last_of("/\\");
        std::string cfgPath = (slash==std::string::npos ? std::string(".") : dir.substr(0,slash)) + "/auth_config.json";
        Value cfg = Value::object();
        // reuse GET serialization by building minimal
        Value loc = Value::object(); loc.set("enabled", Value::boolean(options_.auth.localEnabled)); loc.set("users_file", Value::str(options_.auth.usersFile)); cfg.set("local", loc);
        // ldap
        Value ldap = Value::object();
        ldap.set("enabled", Value::boolean(options_.auth.ldap.enabled));
        ldap.set("url", Value::str(options_.auth.ldap.url));
        ldap.set("bind_dn", Value::str(options_.auth.ldap.bindDn));
        ldap.set("bind_password", Value::str(options_.auth.ldap.bindPassword));
        ldap.set("user_search_base", Value::str(options_.auth.ldap.userSearchBase));
        ldap.set("user_filter", Value::str(options_.auth.ldap.userFilter));
        ldap.set("group_search_base", Value::str(options_.auth.ldap.groupSearchBase));
        ldap.set("group_filter", Value::str(options_.auth.ldap.groupFilter));
        ldap.set("attr_uid", Value::str(options_.auth.ldap.attrUid));
        ldap.set("attr_mail", Value::str(options_.auth.ldap.attrMail));
        ldap.set("attr_display_name", Value::str(options_.auth.ldap.attrDisplayName));
        std::ostringstream gm; bool first=true; for (auto& [k,v] : options_.auth.ldap.groupRoleMap){ if(!first) gm<<";"; first=false; gm<<k<<"="<<v; }
        ldap.set("group_role_map", Value::str(gm.str()));
        cfg.set("ldap", ldap);
        Value kc = Value::object();
        kc.set("enabled", Value::boolean(options_.auth.keycloak.enabled));
        kc.set("issuer", Value::str(options_.auth.keycloak.issuer));
        kc.set("client_id", Value::str(options_.auth.keycloak.clientId));
        kc.set("client_secret", Value::str(options_.auth.keycloak.clientSecret));
        kc.set("realm_roles_map", Value::str(options_.auth.keycloak.realmRolesMap));
        kc.set("use_introspection", Value::boolean(options_.auth.keycloak.useIntrospection));
        cfg.set("keycloak", kc);
        if (fs::writeFileAtomic(cfgPath, cfg.toJson(2)))
            LOG_NOTICE(who(), "auth config: persisted to ", cfgPath);
        else
            LOG_ERROR(who(), "auth config: failed to write ", cfgPath, ": ", std::strerror(errno),
                      " (changes are active but will be lost on restart)");
        res.json(Value::object().set("ok", Value::boolean(true)));
    });
    router_.add("GET", "/auth/providers", [this](const RestRequest&, RestResponse& res) {
        Value arr = Value::array();
        Value p = Value::object(); p.set("name", Value::str("local")); p.set("enabled", Value::boolean(local_ && local_->enabled())); arr.push(p);
        p = Value::object(); p.set("name", Value::str("ldap")); p.set("enabled", Value::boolean(ldap_ && ldap_->enabled())); arr.push(p);
        p = Value::object(); p.set("name", Value::str("keycloak")); p.set("enabled", Value::boolean(keycloak_ && keycloak_->enabled())); arr.push(p);
        res.json(arr);
    });
    // wscluster endpoints
    router_.add("GET", "/wscluster/status", [this](const RestRequest&, RestResponse& res) {
        if (!cluster_) { res.status=503; res.json(Value::object().set("error",Value::str("unavailable"))); return; }
        res.json(cluster_->getStatus());
    });
    router_.add("POST", "/wscluster/init", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body, &pe);
        if (pe.size()||!body.isObject()){res.status=400;res.json(Value::object().set("error",Value::str("bad request")));return;}
        std::string username = body.find("username") && body.find("username")->isString() ? body.find("username")->asString() : "";
        std::string password = body.find("password") && body.find("password")->isString() ? body.find("password")->asString() : "";
        if (options_.auth.enabled && local_ && local_->enabled() && !username.empty()) {
            auto ar = local_->authenticate(username, password);
            if (!ar.ok) {
                LOG_WARN(who(), "wscluster init: authentication of '", username, "' failed: ", ar.error);
                res.status=401; res.json(Value::object().set("error",Value::str("unauthorized"))); return;
            }
            bool okPerm = false;
            if (rbac_) { okPerm = rbac_->hasPermission(ar.user, "s3mmws:manage") || rbac_->hasPermission(ar.user, "s3mmws:write"); }
            if (!okPerm) {
                LOG_WARN(who(), "wscluster init: '", username, "' lacks s3mmws:manage/s3mmws:write");
                res.status=403; res.json(Value::object().set("error",Value::str("forbidden"))); return;
            }
        } else {
            LOG_WARN(who(), "wscluster init: proceeding without credential check (auth ",
                     options_.auth.enabled ? "enabled" : "disabled", ", username ", username.empty() ? "empty" : "given", ")");
        }
        if (!cluster_) { res.status=503; res.json(Value::object().set("error",Value::str("unavailable"))); return; }
        res.json(cluster_->initFromLogin(username, password));
    });
    router_.add("GET", "/wscluster/peers", [this](const RestRequest&, RestResponse& res) {
        if (!cluster_) { res.status=503; res.json(Value::object().set("error",Value::str("unavailable"))); return; }
        res.json(cluster_->listPeers());
    });
    router_.add("POST", "/wscluster/peers", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body, &pe);
        if (pe.size()||!body.isObject()){res.status=400;res.json(Value::object().set("error",Value::str("bad request")));return;}
        std::string address = body.find("address") && body.find("address")->isString() ? body.find("address")->asString() : "";
        if (address.empty()) { res.status=400; res.json(Value::object().set("error",Value::str("address required"))); return; }
        if (!cluster_) { res.status=503; res.json(Value::object().set("error",Value::str("unavailable"))); return; }
        std::string nodeId;
        LOG_INFO(who(), "wscluster: adding peer ", address, ", probing its status");
        std::string st = httpGetJson(address, "/wscluster/status");
        std::string serr; Value sv = Value::parseJson(st, &serr);
        if (serr.empty() && sv.isObject() && sv.find("node_id") && sv.find("node_id")->isString()) nodeId = sv.find("node_id")->asString();
        if (nodeId.empty())
            LOG_WARN(who(), "wscluster: peer ", address, " did not report a node id (",
                     serr.empty() ? "no node_id in reply" : serr, "); adding it anyway");
        else
            LOG_INFO(who(), "wscluster: peer ", address, " is node ", nodeId);
        bool ok = cluster_->addPeer(address, nodeId);
        res.json(Value::object().set("ok", Value::boolean(ok)));
    });
    router_.add("DELETE", "/wscluster/peers", [this](const RestRequest& req, RestResponse& res) {
        std::string address = req.query.count("address") ? req.query.at("address") : "";
        if (address.empty()) { res.status=400; res.json(Value::object().set("error",Value::str("address required"))); return; }
        if (!cluster_) { res.status=503; res.json(Value::object().set("error",Value::str("unavailable"))); return; }
        LOG_INFO(who(), "wscluster: removing peer ", address);
        bool ok = cluster_->removePeer(address);
        res.json(Value::object().set("ok", Value::boolean(ok)));
    });
    router_.add("POST", "/wscluster/replicate", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body, &pe);
        if (pe.size()||!body.isObject()){res.status=400;res.json(Value::object().set("error",Value::str("bad request")));return;}
        auto gs = [&](const std::string& k){ return body.find(k) && body.find(k)->isString() ? body.find(k)->asString() : std::string(); };
        std::string srcAddr = gs("source");
        std::string dstAddr = gs("dest");
        bool srcLocal = srcAddr.empty() || srcAddr=="local";
        bool dstLocal = dstAddr.empty() || dstAddr=="local";
        if (srcLocal) srcAddr = "http://127.0.0.1:" + std::to_string(options_.port);
        if (dstLocal) dstAddr = "http://127.0.0.1:" + std::to_string(options_.port);
        std::string srcCluster = gs("sourceCluster");
        std::string srcBucket = gs("sourceBucket");
        std::string dstCluster = gs("destCluster");
        std::string dstBucket = gs("destBucket");
        std::string prefix = gs("prefix");
        std::string secret = cluster_ ? cluster_->config().clusterSecret : "";
        log::Stopwatch replSw;
        LOG_INFO(who(), "replicate: ", srcLocal ? "local" : srcAddr, " ", srcCluster, "/", srcBucket, " -> ",
                 dstLocal ? "local" : dstAddr, " ", dstCluster, "/", dstBucket, " prefix '", prefix, "'");

        // List source objects
        std::vector<std::pair<std::string,std::string>> objects; // key, b64 content placeholder
        // We'll collect keys first
        std::vector<std::string> keys;
        if (srcLocal) {
            auto client = makeClient(srcCluster);
            if (!client) { res.status=404; res.json(Value::object().set("error",Value::str("source cluster not found"))); return; }
            auto page = client->listObjects(srcBucket, prefix);
            if (!page) {
                LOG_ERROR(who(), "replicate: listing ", srcCluster, "/", srcBucket, " failed: ", page.error());
                res.status=502; res.json(Value::object().set("error",Value::str(page.error()))); return;
            }
            for (auto& o : page.value().objects) keys.push_back(o.key);
        } else {
            std::string url = "/browse/objects?cluster=" + srcCluster + "&bucket=" + srcBucket;
            if (!prefix.empty()) url += "&prefix=" + prefix;
            std::string listResp = httpGetJson(srcAddr, url, secret);
            std::string lerr; Value lv = Value::parseJson(listResp, &lerr);
            if (lerr.size() || !lv.isObject()) {
                LOG_ERROR(who(), "replicate: source list from ", srcAddr, " unreadable: ", lerr.empty() ? log::clip(listResp) : lerr);
                res.status=502; res.json(Value::object().set("error",Value::str("source list failed"))); return;
            }
            const Value* objs = lv.find("objects");
            if (!objs || !objs->isArray()) {
                LOG_ERROR(who(), "replicate: source list from ", srcAddr, " has no 'objects' array");
                res.status=502; res.json(Value::object().set("error",Value::str("no objects"))); return;
            }
            for (auto& o : objs->items()) {
                std::string key = o.find("key") && o.find("key")->isString() ? o.find("key")->asString() : std::string();
                if (!key.empty()) keys.push_back(key);
            }
        }

        LOG_INFO(who(), "replicate: ", keys.size(), " objects to copy");
        int copied = 0, failed = 0;
        for (auto& key : keys) {
            std::string b64, ct = "application/octet-stream";
            // fetch content
            if (srcLocal) {
                auto client = makeClient(srcCluster);
                auto meta = client->headObject(srcBucket, key);
                uint64_t fetchSize = meta && meta.value().exists ? meta.value().size : 0;
                if (!meta) LOG_WARN(who(), "replicate: head ", srcBucket, "/", key, " failed: ", meta.error());
                if (fetchSize > 0) {
                    auto range = client->getObjectRange(srcBucket, key, 0, fetchSize);
                    if (range) b64 = crypto::base64Encode(range.value());
                    else LOG_WARN(who(), "replicate: read ", srcBucket, "/", key, " failed: ", range.error(), "; copying empty content");
                }
                if (meta && meta.value().exists) ct = meta.value().contentType;
            } else {
                std::string contentUrl = "/browse/object-content?cluster=" + srcCluster + "&bucket=" + srcBucket + "&key=" + key;
                std::string cResp = httpGetJson(srcAddr, contentUrl, secret);
                std::string cerr; Value cv = Value::parseJson(cResp, &cerr);
                if (cerr.empty() && cv.isObject()) {
                    b64 = cv.find("content_base64") && cv.find("content_base64")->isString() ? cv.find("content_base64")->asString() : "";
                    ct = cv.find("content_type") && cv.find("content_type")->isString() ? cv.find("content_type")->asString() : ct;
                } else {
                    LOG_ERROR(who(), "replicate: fetching ", key, " from ", srcAddr, " failed: ", cerr.empty() ? log::clip(cResp) : cerr);
                    failed++;
                    continue;
                }
            }
            Value putBody = Value::object();
            putBody.set("content_base64", Value::str(b64));
            putBody.set("content_type", Value::str(ct));
            // dest
            if (dstLocal) {
                auto client = makeClient(dstCluster);
                if (!client) { failed++; continue; }
                s3::ObjectMeta meta; meta.contentType = ct;
                std::string content = crypto::base64Decode(b64).value_or("");
                auto put = client->putObject(dstBucket, key, content, meta);
                if (put) {
                    copied++;
                    LOG_DEBUG(who(), "replicate: copied ", key, " (", content.size(), " B) to ", dstCluster, "/", dstBucket);
                } else {
                    failed++;
                    LOG_ERROR(who(), "replicate: put ", dstCluster, "/", dstBucket, "/", key, " failed: ", put.error());
                }
            } else {
                std::string putUrl = "/browse/object?cluster=" + dstCluster + "&bucket=" + dstBucket + "&key=" + key;
                std::string putResp = httpPutJson(dstAddr, putUrl, putBody.toJson(0), secret);
                std::string perr; Value pv = Value::parseJson(putResp, &perr);
                if (perr.empty() && pv.isObject() && pv.find("ok") && pv.find("ok")->asBool(false)) {
                    copied++;
                    LOG_DEBUG(who(), "replicate: copied ", key, " to ", dstAddr, " ", dstCluster, "/", dstBucket);
                } else {
                    failed++;
                    LOG_ERROR(who(), "replicate: put of ", key, " to ", dstAddr, " failed: ", log::clip(putResp));
                }
            }
        }
        S3MM_LOG_AT(failed ? log::Level::Warning : log::Level::Info, who(), "replicate: finished, ", copied,
                    " copied, ", failed, " failed, ", replSw.ms(), " ms");
        Value out = Value::object();
        out.set("copied", Value::number((int64_t)copied));
        out.set("failed", Value::number((int64_t)failed));
        res.json(out);
    });
    router_.add("POST", "/auth/login", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body, &pe);
        if (pe.size() || !body.isObject()) { res.status=400; res.json(Value::object().set("error",Value::str("bad request"))); return; }
        std::string provider = body.getString("provider", "local");
        std::string username = body.getString("username");
        std::string password = body.getString("password");
        LOG_DEBUG(requestTag(), "login: attempt by '", username, "' via ", provider);
        AuthResult ar;
        if (provider == "local" && local_) ar = local_->authenticate(username, password);
        else if (provider == "ldap" && ldap_) ar = ldap_->authenticate(username, password);
        else if (provider == "keycloak" && keycloak_) ar = keycloak_->authenticate(username, password);
        else {
            LOG_WARN(requestTag(), "login: '", username, "' requested unknown or unavailable provider '", provider, "'");
            res.status=400; res.json(Value::object().set("error",Value::str("unknown provider"))); return;
        }
        if (!ar.ok) {
            LOG_WARN(requestTag(), "login: '", username, "' via ", provider, " failed: ", ar.error);
            res.status=401; res.json(Value::object().set("error",Value::str(ar.error))); return;
        }
        LOG_NOTICE(requestTag(), "login: '", ar.user.id, "' logged in via ", provider, ", roles [", str::join(ar.user.roles, ","), "]");
        std::string token = sessions_->create(ar.user);
        // upsert rbac user shadow
        RbacUser ru; ru.id=ar.user.id; ru.username=ar.user.username; ru.displayName=ar.user.displayName; ru.provider=ar.user.provider;
        ru.roleIds = ar.user.roles;
        rbac_->upsertUser(ru);
        Value out = Value::object();
        out.set("token", Value::str(token));
        out.set("user", Value::object());
        Value u = Value::object();
        u.set("id", Value::str(ar.user.id));
        u.set("username", Value::str(ar.user.username));
        u.set("display_name", Value::str(ar.user.displayName));
        u.set("email", Value::str(ar.user.email));
        u.set("provider", Value::str(ar.user.provider));
        Value roles = Value::array(); for (auto&r:ar.user.roles) roles.push(Value::str(r)); u.set("roles", roles);
        out.set("user", u);
        res.json(out);
    });
    router_.add("POST", "/auth/logout", [this](const RestRequest& req, RestResponse& res) {
        std::string tok;
        auto it = req.headers.find("Authorization");
        if (it != req.headers.end()) {
            std::string v = it->second;
            if (v.rfind("Bearer ",0)==0) tok = v.substr(7);
        }
        if (tok.empty() && req.headers.count("X-Auth-Token")) tok = req.headers.at("X-Auth-Token");
        LOG_INFO(requestTag(), "logout: revoking session ", log::redact(tok));
        sessions_->revoke(tok);
        res.json(Value::object().set("ok", Value::boolean(true)));
    });
    router_.add("GET", "/auth/me", [this](const RestRequest& req, RestResponse& res) {
        std::string tok;
        auto it = req.headers.find("Authorization");
        if (it != req.headers.end()) {
            std::string v = it->second;
            if (v.rfind("Bearer ",0)==0) tok = v.substr(7);
        }
        if (tok.empty() && req.headers.count("X-Auth-Token")) tok = req.headers.at("X-Auth-Token");
        auto u = sessions_->resolve(tok);
        if (!u) { res.status=401; res.json(Value::object().set("error",Value::str("unauthorized"))); return; }
        Value out = Value::object();
        out.set("id", Value::str(u->id));
        out.set("username", Value::str(u->username));
        out.set("display_name", Value::str(u->displayName));
        out.set("email", Value::str(u->email));
        out.set("provider", Value::str(u->provider));
        Value roles = Value::array(); for (auto&r:u->roles) roles.push(Value::str(r)); out.set("roles", roles);
        // effective permissions
        Value perms = Value::array();
        for (auto&p: rbac_->effectivePermissions(*u)) perms.push(Value::str(p));
        out.set("permissions", perms);
        res.json(out);
    });

    // ---- RBAC endpoints ----
    router_.add("GET", "/rbac/permissions", [this](const RestRequest&, RestResponse& res) {
        Value arr = Value::array();
        for (auto& p : rbac_->listPermissions()) {
            Value v = Value::object(); v.set("id",Value::str(p.id)); v.set("name",Value::str(p.name)); v.set("description",Value::str(p.description)); arr.push(v);
        }
        res.json(arr);
    });
    router_.add("GET", "/rbac/roles", [this](const RestRequest&, RestResponse& res) {
        Value arr = Value::array();
        for (auto& r : rbac_->listRoles()) {
            Value v = Value::object(); v.set("id",Value::str(r.id)); v.set("name",Value::str(r.name)); v.set("description",Value::str(r.description));
            Value ps = Value::array(); for (auto&p:r.permissionIds) ps.push(Value::str(p)); v.set("permission_ids",ps);
            arr.push(v);
        }
        res.json(arr);
    });
    router_.add("POST", "/rbac/roles", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body,&pe);
        if (pe.size()||!body.isObject()){res.status=400;res.json(Value::object().set("error",Value::str("bad request")));return;}
        RbacRole r; r.id=body.getString("id"); r.name=body.getString("name"); r.description=body.getString("description");
        if (const Value* ps=body.find("permission_ids")) if(ps&&ps->isArray()) for(auto&x:ps->items()) r.permissionIds.push_back(x.asString());
        if (r.id.empty()) r.id = body.getString("name");
        LOG_INFO(who(), "rbac: create role '", r.id, "' with permissions [", str::join(r.permissionIds, ","), "]");
        if (!rbac_->addRole(r)) { res.status=409; res.json(Value::object().set("error",Value::str("role exists"))); return; }
        res.json(Value::object().set("ok",Value::boolean(true)));
    });
    router_.add("PUT", "/rbac/roles", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body,&pe);
        if (pe.size()||!body.isObject()){res.status=400;res.json(Value::object().set("error",Value::str("bad request")));return;}
        RbacRole r; r.id=body.getString("id"); r.name=body.getString("name"); r.description=body.getString("description");
        if (const Value* ps=body.find("permission_ids")) if(ps&&ps->isArray()) for(auto&x:ps->items()) r.permissionIds.push_back(x.asString());
        LOG_INFO(who(), "rbac: update role '", r.id, "' with permissions [", str::join(r.permissionIds, ","), "]");
        if (!rbac_->updateRole(r)) { res.status=404; res.json(Value::object().set("error",Value::str("not found"))); return; }
        res.json(Value::object().set("ok",Value::boolean(true)));
    });
    router_.add("DELETE", "/rbac/roles", [this](const RestRequest& req, RestResponse& res) {
        std::string id = req.query.count("id")?req.query.at("id"):"";
        if (id.empty()) { std::string pe; Value body=Value::parseJson(req.body,&pe); if(!pe.size()&&body.isObject()) id=body.getString("id"); }
        LOG_INFO(who(), "rbac: delete role '", id, "'");
        if (!rbac_->deleteRole(id)) { res.status=404; res.json(Value::object().set("error",Value::str("not found"))); return; }
        res.json(Value::object().set("ok",Value::boolean(true)));
    });
    router_.add("GET", "/rbac/users", [this](const RestRequest&, RestResponse& res) {
        Value arr = Value::array();
        for (auto& u : rbac_->listUsers()) {
            Value v = Value::object(); v.set("id",Value::str(u.id)); v.set("username",Value::str(u.username)); v.set("display_name",Value::str(u.displayName)); v.set("provider",Value::str(u.provider));
            Value rs = Value::array(); for (auto&r:u.roleIds) rs.push(Value::str(r)); v.set("role_ids",rs);
            Value ps = Value::array(); for (auto&p:u.permissionIds) ps.push(Value::str(p)); v.set("permission_ids",ps);
            arr.push(v);
        }
        res.json(arr);
    });
    router_.add("POST", "/rbac/users", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body,&pe);
        if (pe.size()||!body.isObject()){res.status=400;res.json(Value::object().set("error",Value::str("bad request")));return;}
        // create local user if provider local
        std::string username = body.getString("username");
        std::string password = body.getString("password");
        std::string provider = body.getString("provider","local");
        LOG_INFO(who(), "rbac: create user '", username, "' (provider ", provider, ")");
        if (provider=="local" && password.empty())
            LOG_WARN(who(), "rbac: no password given for local user '", username, "', using the default one");
        if (provider=="local" && local_) {
            LocalUserRecord rec; rec.username=username; rec.displayName=body.getString("display_name",username); rec.email=body.getString("email");
            if (const Value* rs=body.find("role_ids")) if(rs&&rs->isArray()) for(auto&x:rs->items()) rec.roles.push_back(x.asString());
            if (rec.roles.empty()) rec.roles.push_back("viewer");
            if (!local_->addUser(rec, password.empty()?"changeme":password)) { res.status=409; res.json(Value::object().set("error",Value::str("user exists"))); return; }
        }
        RbacUser ru; ru.id=provider+":"+username; ru.username=username; ru.displayName=body.getString("display_name",username); ru.provider=provider;
        if (const Value* rs=body.find("role_ids")) if(rs&&rs->isArray()) for(auto&x:rs->items()) ru.roleIds.push_back(x.asString());
        if (const Value* ps=body.find("permission_ids")) if(ps&&ps->isArray()) for(auto&x:ps->items()) ru.permissionIds.push_back(x.asString());
        rbac_->upsertUser(ru);
        res.json(Value::object().set("ok",Value::boolean(true)));
    });
    router_.add("DELETE", "/rbac/users", [this](const RestRequest& req, RestResponse& res) {
        std::string id = req.query.count("id")?req.query.at("id"):"";
        if (id.empty()) { std::string pe; Value body=Value::parseJson(req.body,&pe); if(!pe.size()&&body.isObject()) id=body.getString("id"); }
        LOG_INFO(who(), "rbac: delete user '", id, "'");
        // remove local user if local:
        if (id.rfind("local:",0)==0 && local_) local_->removeUser(id.substr(6));
        rbac_->deleteUser(id);
        res.json(Value::object().set("ok",Value::boolean(true)));
    });
    router_.add("GET", "/rbac/bindings", [this](const RestRequest&, RestResponse& res) {
        Value arr = Value::array();
        for (auto& b : rbac_->listBindings()) {
            Value v = Value::object(); v.set("id",Value::str(b.id)); v.set("subject",Value::str(b.subject)); v.set("subject_type",Value::str(b.subjectType)); v.set("role_id",Value::str(b.roleId)); v.set("scope",Value::str(b.scope));
            arr.push(v);
        }
        res.json(arr);
    });
    router_.add("POST", "/rbac/bindings", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body,&pe);
        if (pe.size()||!body.isObject()){res.status=400;res.json(Value::object().set("error",Value::str("bad request")));return;}
        RbacBinding b; b.id=body.getString("id"); if(b.id.empty()) b.id = std::to_string((long long)std::chrono::system_clock::now().time_since_epoch().count());
        b.subject=body.getString("subject"); b.subjectType=body.getString("subject_type","user"); b.roleId=body.getString("role_id"); b.scope=body.getString("scope");
        LOG_INFO(who(), "rbac: bind ", b.subjectType, " '", b.subject, "' to role '", b.roleId, "'");
        rbac_->addBinding(b);
        res.json(Value::object().set("ok",Value::boolean(true)));
    });
    router_.add("DELETE", "/rbac/bindings", [this](const RestRequest& req, RestResponse& res) {
        std::string id = req.query.count("id")?req.query.at("id"):"";
        if (id.empty()) { std::string pe; Value body=Value::parseJson(req.body,&pe); if(!pe.size()&&body.isObject()) id=body.getString("id"); }
        LOG_INFO(who(), "rbac: delete binding '", id, "'");
        rbac_->deleteBinding(id);
        res.json(Value::object().set("ok",Value::boolean(true)));
    });
    // ACL
    router_.add("GET", "/acl", [this](const RestRequest& req, RestResponse& res) {
        std::string rt = req.query.count("resource_type")?req.query.at("resource_type"):"";
        std::string rid = req.query.count("resource_id")?req.query.at("resource_id"):"";
        Value arr = Value::array();
        for (auto& a : rbac_->listAcl(rt, rid)) {
            Value v = Value::object(); v.set("id",Value::str(a.id)); v.set("subject",Value::str(a.subject)); v.set("subject_type",Value::str(a.subjectType)); v.set("effect",Value::str(a.effect)); v.set("resource_type",Value::str(a.resourceType)); v.set("resource_id",Value::str(a.resourceId));
            Value ac = Value::array(); for (auto&x:a.actions) ac.push(Value::str(x)); v.set("actions",ac);
            arr.push(v);
        }
        res.json(arr);
    });
    router_.add("POST", "/acl", [this](const RestRequest& req, RestResponse& res) {
        std::string pe; Value body = Value::parseJson(req.body,&pe);
        if (pe.size()||!body.isObject()){res.status=400;res.json(Value::object().set("error",Value::str("bad request")));return;}
        AclEntry e; e.id=body.getString("id"); if(e.id.empty()) e.id=std::to_string((long long)std::chrono::system_clock::now().time_since_epoch().count());
        e.subject=body.getString("subject"); e.subjectType=body.getString("subject_type","user"); e.effect=body.getString("effect","allow"); e.resourceType=body.getString("resource_type"); e.resourceId=body.getString("resource_id");
        if (const Value* ac=body.find("actions")) if(ac&&ac->isArray()) for(auto&x:ac->items()) e.actions.push_back(x.asString());
        LOG_INFO(who(), "acl: set entry '", e.id, "'");
        rbac_->setAclEntry(e);
        res.json(Value::object().set("ok",Value::boolean(true)));
    });
    router_.add("DELETE", "/acl", [this](const RestRequest& req, RestResponse& res) {
        std::string id = req.query.count("id")?req.query.at("id"):"";
        if (id.empty()) { std::string pe; Value body=Value::parseJson(req.body,&pe); if(!pe.size()&&body.isObject()) id=body.getString("id"); }
        LOG_INFO(who(), "acl: delete entry '", id, "'");
        rbac_->deleteAclEntry(id);
        res.json(Value::object().set("ok",Value::boolean(true)));
    });
    router_.add("GET", "/replications", [this](const RestRequest&, RestResponse& res) {
        Value req = Value::object();
        req.set("cmd", Value::str("list"));
        req.set("kind", Value::str("replication"));
        try {
            res.json(daemonClient_.call(req));
        } catch (const std::exception& e) {
            LOG_ERROR(who(), "replications: s3mmd unavailable: ", e.what());
            res.status = 502;
            res.json(Value::object().set("error", Value::str(e.what())));
        }
    });    router_.add("GET", "/browse/buckets", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        LOG_DEBUG(who(), "browse: list buckets of cluster '", cluster, "'");
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto buckets = client->listBuckets();
        if (!buckets) {
            LOG_ERROR(who(), "GET /browse/buckets: list buckets failed: ", buckets.error());
            res.status = 502; res.json(Value::object().set("error", Value::str(buckets.error()))); return;
        }
        Value arr = Value::array();
        for (const auto& b : buckets.value()) {
            Value v = Value::object();
            v.set("name", Value::str(b.name));
            v.set("created", Value::str(tm::toIso8601(b.created)));
            arr.push(v);
        }
        res.json(arr);
    });
    router_.add("GET", "/browse/objects", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string prefix = req.query.count("prefix") ? req.query.at("prefix") : "";
        LOG_DEBUG(who(), "browse: list ", cluster, "/", bucket, " prefix '", prefix, "'");
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto page = client->listObjects(bucket, prefix, "", "", 1000);
        if (!page) {
            LOG_ERROR(who(), "GET /browse/objects: list objects failed: ", page.error());
            res.status = 502; res.json(Value::object().set("error", Value::str(page.error()))); return;
        }
        Value arr = Value::array();
        for (const auto& o : page.value().objects) {
            Value v = Value::object();
            v.set("key", Value::str(o.key));
            v.set("size", Value::number((int64_t)o.size));
            v.set("last_modified", Value::str(tm::toIso8601(o.lastModified)));
            v.set("etag", Value::str(o.etag));
            v.set("storage_class", Value::str(o.storageClass));
            arr.push(v);
        }
        Value prefixes = Value::array();
        for (const auto& pfx : page.value().commonPrefixes) prefixes.push(Value::str(pfx));
        Value out = Value::object();
        out.set("objects", arr);
        out.set("prefixes", prefixes);
        out.set("truncated", Value::boolean(page.value().truncated));
        out.set("next_token", Value::str(page.value().nextToken));
        res.json(out);
    });
    router_.add("GET", "/browse/object", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        LOG_DEBUG(who(), "browse: head ", cluster, "/", bucket, "/", key);
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto meta = client->headObject(bucket, key);
        if (!meta) {
            LOG_ERROR(who(), "GET /browse/object: head object failed: ", meta.error());
            res.status = 404; res.json(Value::object().set("error", Value::str(meta.error()))); return;
        }
        Value v = Value::object();
        v.set("exists", Value::boolean(meta.value().exists));
        v.set("size", Value::number((int64_t)meta.value().size));
        v.set("etag", Value::str(meta.value().etag));
        v.set("last_modified", Value::str(tm::toIso8601(meta.value().lastModified)));
        v.set("content_type", Value::str(meta.value().contentType));
        v.set("content_encoding", Value::str(meta.value().contentEncoding));
        v.set("content_language", Value::str(meta.value().contentLanguage));
        v.set("content_disposition", Value::str(meta.value().contentDisposition));
        v.set("cache_control", Value::str(meta.value().cacheControl));
        v.set("expires", Value::str(meta.value().expires));
        v.set("storage_class", Value::str(meta.value().storageClass));
        Value tags = Value::object();
        for (const auto& [k, val] : meta.value().tags) tags.set(k, Value::str(val));
        v.set("tags", tags);
        Value userMeta = Value::object();
        for (const auto& [k, val] : meta.value().userMeta) userMeta.set(k, Value::str(val));
        v.set("user_meta", userMeta);
        res.json(v);
    });
    router_.add("PUT", "/browse/object", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        LOG_INFO(who(), "browse: put ", cluster, "/", bucket, "/", key, " (request body ", req.body.size(), " B)");
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        std::string parseError;
        Value body = Value::parseJson(req.body, &parseError);
        if (parseError.empty() == false || !body.isObject()) { res.status = 400; res.json(Value::object().set("error", Value::str("bad request"))); return; }
        s3::ObjectMeta meta;
        meta.contentType = body.getString("content_type", "application/octet-stream");
        meta.contentEncoding = body.getString("content_encoding");
        meta.contentLanguage = body.getString("content_language");
        meta.contentDisposition = body.getString("content_disposition");
        meta.cacheControl = body.getString("cache_control");
        meta.expires = body.getString("expires");
        meta.storageClass = body.getString("storage_class");
        if (const Value* m = body.find("metadata")) if (m && m->isObject()) for (const auto& [k, v] : m->members()) meta.userMeta[k] = v.asString();
        if (const Value* t = body.find("tags")) if (t && t->isObject()) for (const auto& [k, v] : t->members()) meta.tags[k] = v.asString();
        std::string content;
        bool hasContent = body.find("content") != nullptr;
        bool hasBase64 = body.find("content_base64") != nullptr;
        if (hasBase64) {
            auto decoded = crypto::base64Decode(body.getString("content_base64"));
            if (!decoded) { res.status = 400; res.json(Value::object().set("error", Value::str("invalid base64 content"))); return; }
            content = decoded.value();
        } else if (hasContent) content = body.getString("content");
        else {
            auto head = client->headObject(bucket, key);
            if (head && head.value().exists && head.value().size > 0) {
                auto range = client->getObjectRange(bucket, key, 0, head.value().size);
                if (!range) {
                    LOG_ERROR(who(), "PUT /browse/object: read object failed: ", range.error());
                    res.status = 502; res.json(Value::object().set("error", Value::str(range.error()))); return;
                }
                content = range.value();
            }
        }
        auto put = client->putObject(bucket, key, content, meta);
        if (!put) {
            LOG_ERROR(who(), "PUT /browse/object: put object failed: ", put.error());
            res.status = 502; res.json(Value::object().set("error", Value::str(put.error()))); return;
        }
        if (const Value* t = body.find("tags")) if (t && t->isObject()) {
            s3::BucketTagging tagging;
            for (const auto& [k, v] : t->members()) tagging.tags[k] = v.asString();
            auto tagged = client->putObjectTagging(bucket, key, tagging);
            if (!tagged) LOG_WARN(who(), "browse: object stored but tagging ", bucket, "/", key, " failed: ", tagged.error());
            else LOG_DEBUG(who(), "browse: tagged ", bucket, "/", key, " with ", tagging.tags.size(), " tags");
        }
        LOG_INFO(who(), "browse: stored ", cluster, "/", bucket, "/", key, " (", content.size(), " B, ", meta.contentType, ")");
        res.json(Value::object().set("ok", Value::boolean(true)));
    });
    router_.add("DELETE", "/browse/object", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        LOG_INFO(who(), "browse: delete ", cluster, "/", bucket, "/", key);
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto del = client->deleteObject(bucket, key);
        if (!del) {
            LOG_ERROR(who(), "DELETE /browse/object: delete failed: ", del.error());
            res.status = 502; res.json(Value::object().set("error", Value::str(del.error()))); return;
        }
        res.json(Value::object().set("ok", Value::boolean(true)));
    });
    router_.add("GET", "/browse/object-acl", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        LOG_DEBUG(who(), "browse: get ACL of ", cluster, "/", bucket, "/", key);
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        http::Request r;
        r.method = "GET";
        r.url = client->primaryEndpoint() + "/" + bucket + "/" + key;
        r.query["acl"] = "";
        auto resp = client->raw(r);
        if (!resp.ok()) {
            LOG_ERROR(who(), "browse: get ACL of ", bucket, "/", key, " failed: HTTP ", resp.status, ": ", log::clip(resp.body));
            res.status = resp.status; res.text(resp.body); return;
        }
        res.text(resp.body, "application/xml");
    });
    router_.add("PUT", "/browse/object-acl", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        std::string acl = req.query.count("acl") ? req.query.at("acl") : "private";
        LOG_INFO(who(), "browse: set ACL '", acl, "' on ", cluster, "/", bucket, "/", key);
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        http::Request r;
        r.method = "PUT";
        r.url = client->primaryEndpoint() + "/" + bucket + "/" + key;
        r.query["acl"] = "";
        r.headers["x-amz-acl"] = acl;
        auto resp = client->raw(r);
        if (!resp.ok()) {
            LOG_ERROR(who(), "browse: set ACL on ", bucket, "/", key, " failed: HTTP ", resp.status, ": ", log::clip(resp.body));
            res.status = resp.status; res.text(resp.body); return;
        }
        LOG_INFO(who(), "browse: ACL of ", cluster, "/", bucket, "/", key, " set to '", acl, "'");
        res.json(Value::object().set("ok", Value::boolean(true)));
    });

    router_.add("POST", "/browse/rename", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string parseError;
        Value body = Value::parseJson(req.body, &parseError);
        if (parseError.empty() == false || !body.isObject()) { res.status = 400; res.json(Value::object().set("error", Value::str("bad request"))); return; }
        std::string source = body.getString("source");
        std::string target = body.getString("target");
        if (source.empty() || target.empty()) { res.status = 400; res.json(Value::object().set("error", Value::str("source and target required"))); return; }
        LOG_INFO(who(), "browse: rename ", cluster, "/", bucket, "/", source, " -> ", target);
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto copied = client->copyObject(bucket, source, bucket, target);
        if (!copied) {
            LOG_ERROR(who(), "POST /browse/rename: copy object failed: ", copied.error());
            res.status = 502; res.json(Value::object().set("error", Value::str(copied.error()))); return;
        }
        LOG_DEBUG(who(), "browse: copied ", source, " -> ", target, ", deleting source");
        auto deleted = client->deleteObject(bucket, source);
        if (!deleted) {
            LOG_ERROR(who(), "POST /browse/rename: delete failed: ", deleted.error());
            res.status = 502; res.json(Value::object().set("error", Value::str(deleted.error()))); return;
        }
        res.json(Value::object().set("ok", Value::boolean(true)));
    });


    router_.add("POST", "/browse/buckets", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        if (bucket.empty()) { res.status = 400; res.json(Value::object().set("error", Value::str("bucket required"))); return; }
        LOG_INFO(who(), "browse: create bucket ", cluster, "/", bucket);
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto created = client->createBucket(bucket);
        if (!created) {
            LOG_ERROR(who(), "POST /browse/buckets: create bucket failed: ", created.error());
            res.status = 502; res.json(Value::object().set("error", Value::str(created.error()))); return;
        }
        res.json(Value::object().set("ok", Value::boolean(true)));
    });
    router_.add("DELETE", "/browse/buckets", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        if (bucket.empty()) { res.status = 400; res.json(Value::object().set("error", Value::str("bucket required"))); return; }
        LOG_INFO(who(), "browse: delete bucket ", cluster, "/", bucket);
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto deleted = client->deleteBucket(bucket);
        if (!deleted) {
            LOG_ERROR(who(), "DELETE /browse/buckets: delete failed: ", deleted.error());
            res.status = 502; res.json(Value::object().set("error", Value::str(deleted.error()))); return;
        }
        res.json(Value::object().set("ok", Value::boolean(true)));
    });
    router_.add("GET", "/browse/object-content", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        LOG_DEBUG(who(), "browse: read content of ", cluster, "/", bucket, "/", key);
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto meta = client->headObject(bucket, key);
        if (!meta || !meta.value().exists) {
            LOG_WARN(who(), "browse: ", bucket, "/", key, " not found", meta ? std::string() : ": " + meta.error());
            res.status = 404; res.json(Value::object().set("error", Value::str("object not found"))); return;
        }
        uint64_t limit = 1024 * 1024;
        if (req.query.count("limit")) {
            auto parsed = units::tryParseSize(req.query.at("limit"));
            if (parsed) limit = *parsed;
            else LOG_WARN(who(), "browse: invalid limit '", req.query.at("limit"), "', using 1M");
        }
        uint64_t fetchSize = std::min<uint64_t>(meta.value().size, limit);
        std::string content;
        if (fetchSize > 0) {
            auto range = client->getObjectRange(bucket, key, 0, fetchSize);
            if (!range) {
                LOG_ERROR(who(), "browse: reading ", fetchSize, " B of ", bucket, "/", key, " failed: ", range.error());
                res.status = 502;
                Value err = Value::object();
                err.set("error", Value::str(range.error()));
                err.set("curl_error", Value::str("S3 transport/HTTP error while reading object content"));
                res.json(err);
                return;
            }
            content = range.value();
        }
        LOG_DEBUG(who(), "browse: fetched ", fetchSize, " of ", meta.value().size, " B of ", bucket, "/", key);
        Value v = Value::object();
        v.set("content_type", Value::str(meta.value().contentType));
        v.set("size", Value::number((int64_t)meta.value().size));
        v.set("fetched", Value::number((int64_t)fetchSize));
        v.set("truncated", Value::boolean(fetchSize < meta.value().size));
        v.set("content_base64", Value::str(crypto::base64Encode(content)));
        res.json(v);
    });

}

int RestDaemon::run() {
    log::Options bootstrap;
    bootstrap.ident = "s3mmws";
    log::init(bootstrap);
    LOG_NOTICE("s3mmws ", S3MM_VERSION, " starting (pid ", ::getpid(), "): config '", options_.config, "', listen ",
               options_.listen, ":", options_.port, ", socket '", options_.socket, "', modules dir '",
               options_.modulesDir, "', daemonize ", options_.daemonize ? "yes" : "no", ", validate-only ",
               options_.validateOnly ? "yes" : "no");

    // Load config (optional) for socket/modules defaults.
    std::string secretsDir;
    std::string cacheDir;
    if (options_.config.empty()) LOG_WARN("config: no configuration file given, running on built-in defaults");
    if (!options_.config.empty()) {
        LOG_INFO("config: loading ", options_.config);
        log::Stopwatch cfgSw;
        auto cfg = config::Config::load(options_.config);
        if (cfg) {
            LOG_INFO("config: parsed ", options_.config, " (", cfg.value().roots().size(), " top-level nodes, ",
                     cfg.value().s3mm() ? "with" : "without", " s3mm { } wrapper) in ", cfgSw.ms(), " ms");
            for (const auto& r : cfg.value().roots())
                LOG_DEBUG("config: top-level '", r.str(), "'", r.block ? " { ... }" : "", " from ", r.file, ":", r.line);
            if (options_.validateOnly) {
                LOG_NOTICE("config: ", options_.config, " is valid (validate-only mode), exiting");
                return 0;
            }
            LOG_DEBUG("config: building registry");
            auto reg = registry::Registry::fromConfig(cfg.value());
            if (reg) {
                const auto& st = reg.value().settings();
                if (options_.socket.empty()) options_.socket = st.socket;
                if (options_.modulesDir.empty()) options_.modulesDir = st.modulesDir;
                secretsDir = st.secretsDir;
                cacheDir = st.cacheDir;
                LOG_INFO("config: registry loaded: ", reg.value().clusters().size(), " clusters, ",
                         reg.value().credentials().size(), " credentials; socket '", options_.socket,
                         "', modules dir '", options_.modulesDir, "', secrets dir '", secretsDir, "', cache dir '",
                         cacheDir, "'");
                for (const auto& c : reg.value().clusters())
                    LOG_DEBUG("config: cluster '", c.name, "' endpoints [", str::join(c.endpoints, ","), "]");

                log::Options tuned = bootstrap;
                try {
                    tuned.level = log::levelFromString(st.logLevel);
                } catch (const std::exception& e) {
                    LOG_WARN("config: ", e.what(), ", keeping log level info");
                }
                if (!log::facilityFromString(st.logFacility, tuned.facility))
                    LOG_WARN("config: unknown log facility '", st.logFacility, "', using daemon");
                tuned.socketPath = st.logSocket;
                LOG_DEBUG("config: switching logging to level ", log::levelName(tuned.level), ", facility ",
                          log::facilityName(tuned.facility), ", socket ", tuned.socketPath);
                log::init(tuned);
                LOG_INFO("logging: level ", log::levelName(tuned.level), ", facility ", log::facilityName(tuned.facility),
                         ", socket ", tuned.socketPath);
                registry_ = std::make_unique<registry::Registry>(std::move(reg.value()));
            } else {
                LOG_ERROR("config: registry could not be built from ", options_.config, ": ", reg.error(),
                          "; S3 browsing and proxying are unavailable");
            }
            // `module <name> { ... }` blocks: top level or inside s3mmws { }
            for (const auto& r : cfg.value().roots())
                if (r.name == "module") options_.modules.push_back(r);
            if (const config::Node* s3mmRoot = cfg.value().s3mm())
                for (const auto* m : s3mmRoot->findAll("module")) options_.modules.push_back(*m);
            for (const auto& r : cfg.value().roots())
                if (r.name == "s3mmws" && r.block)
                    for (const auto* m : r.findAll("module")) options_.modules.push_back(*m);
            for (const auto& m : options_.modules)
                LOG_INFO("config: module '", m.argOr(0), "' configured at ", m.file, ":", m.line);
            // parse s3mmws auth block
            const config::Node* s3mm = cfg.value().s3mm();
            const config::Node* ws = nullptr;
            if (s3mm) ws = s3mm->find("s3mmws");
            if (!ws) for (const auto& r : cfg.value().roots()) if (r.name == "s3mmws") { ws = &r; break; }
            if (!ws || !ws->block) LOG_WARN("config: no s3mmws { } block found, authentication settings stay at defaults");
            if (ws && ws->block) {
                LOG_DEBUG("config: parsing s3mmws block at ", ws->file, ":", ws->line);
                options_.auth.enabled = ws->boolValue("auth_enabled", options_.auth.enabled);
                options_.auth.sessionTtl = (int)ws->int64Value("session_ttl", options_.auth.sessionTtl);
                if (ws->value("rbac_store").size()) options_.auth.rbacStorePath = ws->value("rbac_store");
                if (ws->value("users_file").size()) options_.auth.usersFile = ws->value("users_file");
                LOG_INFO("config: s3mmws auth ", options_.auth.enabled ? "enabled" : "DISABLED (anonymous admin access)",
                         ", session ttl ", options_.auth.sessionTtl, " s, rbac store '", options_.auth.rbacStorePath,
                         "', users file '", options_.auth.usersFile, "'");
                const config::Node* authn = ws->find("auth");
                if (!authn || !authn->block) LOG_DEBUG("config: no auth { } block, providers keep defaults");
                if (authn && authn->block) {
                    const config::Node* loc = authn->find("local");
                    if (loc && loc->block) {
                        options_.auth.localEnabled = loc->boolValue("enabled", true);
                        if (loc->value("users_file").size()) options_.auth.usersFile = loc->value("users_file");
                        LOG_INFO("config: auth.local ", options_.auth.localEnabled ? "enabled" : "disabled",
                                 ", users file '", options_.auth.usersFile, "'");
                    }
                    const config::Node* ldap = authn->find("ldap");
                    if (ldap && ldap->block) {
                        options_.auth.ldap.enabled = ldap->boolValue("enabled", false);
                        options_.auth.ldap.url = ldap->value("url");
                        options_.auth.ldap.bindDn = ldap->value("bind_dn");
                        std::string bp = ldap->value("bind_password");
                        std::string bpf = ldap->value("bind_password_file");
                        if (!bpf.empty()) {
                            auto c = fs::readFile(bpf);
                            if (c) {
                                options_.auth.ldap.bindPassword = *c;
                                LOG_DEBUG("config: auth.ldap bind password read from ", bpf, " (", log::redact(*c), ")");
                            } else {
                                LOG_ERROR("config: auth.ldap bind_password_file ", bpf, " is unreadable: ", std::strerror(errno));
                            }
                        }
                        else options_.auth.ldap.bindPassword = bp;
                        options_.auth.ldap.userSearchBase = ldap->value("user_search_base");
                        if (ldap->value("user_filter").size()) options_.auth.ldap.userFilter = ldap->value("user_filter");
                        options_.auth.ldap.groupSearchBase = ldap->value("group_search_base");
                        if (ldap->value("group_filter").size()) options_.auth.ldap.groupFilter = ldap->value("group_filter");
                        if (ldap->value("attr_uid").size()) options_.auth.ldap.attrUid = ldap->value("attr_uid");
                        if (ldap->value("attr_mail").size()) options_.auth.ldap.attrMail = ldap->value("attr_mail");
                        if (ldap->value("attr_display_name").size()) options_.auth.ldap.attrDisplayName = ldap->value("attr_display_name");
                        // group_role_map "a=b;c=d"
                        std::string gm = ldap->value("group_role_map");
                        if (!gm.empty()) {
                            std::istringstream iss(gm); std::string tok;
                            while (std::getline(iss, tok, ';')) {
                                size_t eq = tok.find('=');
                                if (eq != std::string::npos) {
                                    auto trim=[&](std::string x){size_t a=x.find_first_not_of(" 	");size_t b=x.find_last_not_of(" 	"); if(a==std::string::npos)return std::string(); return x.substr(a,b-a+1);};
                                    options_.auth.ldap.groupRoleMap[trim(tok.substr(0,eq))]=trim(tok.substr(eq+1));
                                } else {
                                    LOG_WARN("config: auth.ldap group_role_map entry '", tok, "' has no '=', ignored");
                                }
                            }
                        }
                        LOG_INFO("config: auth.ldap ", options_.auth.ldap.enabled ? "enabled" : "disabled", ", url '",
                                 options_.auth.ldap.url, "', bind_dn '", options_.auth.ldap.bindDn, "', password ",
                                 log::redact(options_.auth.ldap.bindPassword), ", user base '",
                                 options_.auth.ldap.userSearchBase, "', ", options_.auth.ldap.groupRoleMap.size(),
                                 " group mappings");
                        if (options_.auth.ldap.enabled && options_.auth.ldap.url.empty())
                            LOG_WARN("config: auth.ldap is enabled but url is empty");
                    }
                    const config::Node* kc = authn->find("keycloak");
                    if (kc && kc->block) {
                        options_.auth.keycloak.enabled = kc->boolValue("enabled", false);
                        options_.auth.keycloak.issuer = kc->value("issuer");
                        options_.auth.keycloak.clientId = kc->value("client_id");
                        std::string csf = kc->value("client_secret_file");
                        if (!csf.empty()) {
                            auto c = fs::readFile(csf);
                            if (c) {
                                options_.auth.keycloak.clientSecret = *c;
                                LOG_DEBUG("config: auth.keycloak client secret read from ", csf, " (", log::redact(*c), ")");
                            } else {
                                LOG_ERROR("config: auth.keycloak client_secret_file ", csf, " is unreadable: ", std::strerror(errno));
                            }
                        }
                        else options_.auth.keycloak.clientSecret = kc->value("client_secret");
                        options_.auth.keycloak.realmRolesMap = kc->value("realm_roles_map");
                        options_.auth.keycloak.useIntrospection = kc->boolValue("use_introspection", true);
                        LOG_INFO("config: auth.keycloak ", options_.auth.keycloak.enabled ? "enabled" : "disabled",
                                 ", issuer '", options_.auth.keycloak.issuer, "', client_id '",
                                 options_.auth.keycloak.clientId, "', client secret ",
                                 log::redact(options_.auth.keycloak.clientSecret), ", introspection ",
                                 options_.auth.keycloak.useIntrospection ? "on" : "off");
                    }
                }
            }
        } else {
            LOG_ERROR("config: failed to load ", options_.config, ": ", cfg.error());
            if (options_.validateOnly) return 1;
            LOG_WARN("config: continuing with built-in defaults");
        }
    }
    if (options_.validateOnly) {
        LOG_NOTICE("validate-only mode, exiting");
        return 0;
    }

    if (options_.socket.empty()) {
        options_.socket = "/run/s3mm/s3mm.sock";
        LOG_DEBUG("config: socket not set, using default ", options_.socket);
    }
    if (options_.auth.rbacStorePath.empty()) {
        std::string base = secretsDir.empty() ? (cacheDir.empty() ? "/tmp/opencode" : cacheDir) : secretsDir;
        options_.auth.rbacStorePath = base + "/s3mmws_rbac.json";
        LOG_DEBUG("config: rbac_store not set, using ", options_.auth.rbacStorePath);
    }
    if (options_.auth.usersFile.empty()) {
        std::string base = secretsDir.empty() ? (cacheDir.empty() ? "/tmp/opencode" : cacheDir) : secretsDir;
        options_.auth.usersFile = base + "/s3mmws_users.json";
        LOG_DEBUG("config: users_file not set, using ", options_.auth.usersFile);
    }
    // init auth
    LOG_DEBUG("startup: initializing session manager, RBAC store and auth providers");
    sessions_ = std::make_unique<SessionManager>(options_.auth.sessionTtl);
    rbac_ = std::make_unique<RbacStore>(options_.auth.rbacStorePath);
    if (options_.auth.localEnabled) {
        local_ = std::make_unique<LocalAuthProvider>(options_.auth.usersFile);
        local_->setEnabled(true);
    } else {
        local_ = std::make_unique<LocalAuthProvider>(options_.auth.usersFile);
        local_->setEnabled(false);
    }
    ldap_ = std::make_unique<LdapAuthProvider>(options_.auth.ldap);
    keycloak_ = std::make_unique<KeycloakAuthProvider>(options_.auth.keycloak);
    // load persisted auth config if present
    {
        std::string dir = options_.auth.rbacStorePath;
        size_t slash = dir.find_last_of("/\\");
        std::string cfgPath = (slash==std::string::npos ? std::string(".") : dir.substr(0,slash)) + "/auth_config.json";
        auto content = fs::readFile(cfgPath);
        if (!content) LOG_DEBUG("config: no persisted auth overrides at ", cfgPath);
        if (content) {
            LOG_INFO("config: applying persisted auth overrides from ", cfgPath, " (they take precedence over the config file)");
            std::string err; Value v = Value::parseJson(*content, &err);
            if (!err.empty() || !v.isObject())
                LOG_ERROR("config: ", cfgPath, " is not a JSON object", err.empty() ? std::string() : ": " + err, ", ignored");
            if (err.empty() && v.isObject()) {
                if (const Value* loc = v.find("local")) if (loc && loc->isObject()) {
                    if (loc->find("enabled")) options_.auth.localEnabled = loc->find("enabled")->asBool(options_.auth.localEnabled);
                    if (auto x=loc->find("users_file")) if (x && x->isString()) options_.auth.usersFile = x->asString();
                    if (local_) local_->setEnabled(options_.auth.localEnabled);
                }
                if (const Value* l = v.find("ldap")) if (l && l->isObject()) {
                    if (l->find("enabled")) options_.auth.ldap.enabled = l->find("enabled")->asBool(options_.auth.ldap.enabled);
                    if (auto x=l->find("url")) if (x&&x->isString()) options_.auth.ldap.url=x->asString();
                    if (auto x=l->find("bind_dn")) if (x&&x->isString()) options_.auth.ldap.bindDn=x->asString();
                    if (auto x=l->find("bind_password")) if (x&&x->isString()) options_.auth.ldap.bindPassword=x->asString();
                    if (auto x=l->find("user_search_base")) if (x&&x->isString()) options_.auth.ldap.userSearchBase=x->asString();
                    if (auto x=l->find("user_filter")) if (x&&x->isString()) options_.auth.ldap.userFilter=x->asString();
                    if (auto x=l->find("group_search_base")) if (x&&x->isString()) options_.auth.ldap.groupSearchBase=x->asString();
                    if (auto x=l->find("group_filter")) if (x&&x->isString()) options_.auth.ldap.groupFilter=x->asString();
                    if (auto x=l->find("attr_uid")) if (x&&x->isString()) options_.auth.ldap.attrUid=x->asString();
                    if (auto x=l->find("attr_mail")) if (x&&x->isString()) options_.auth.ldap.attrMail=x->asString();
                    if (auto x=l->find("attr_display_name")) if (x&&x->isString()) options_.auth.ldap.attrDisplayName=x->asString();
                    if (auto x=l->find("group_role_map")) if (x&&x->isString()) {
                        std::map<std::string,std::string> m; std::string s=x->asString(); size_t start=0;
                        while(true){ size_t semi=s.find(';',start); std::string part=(semi==std::string::npos)?s.substr(start):s.substr(start,semi-start); size_t eq=part.find('='); if(eq!=std::string::npos){ auto trim=[](std::string x){size_t a=x.find_first_not_of(" \t");size_t b=x.find_last_not_of(" \t"); if(a==std::string::npos)return std::string(); return x.substr(a,b-a+1);}; m[trim(part.substr(0,eq))]=trim(part.substr(eq+1)); } if(semi==std::string::npos) break; start=semi+1; }
                        options_.auth.ldap.groupRoleMap=m;
                    }
                    if (ldap_) ldap_->setConfig(options_.auth.ldap);
                }
                if (const Value* k = v.find("keycloak")) if (k && k->isObject()) {
                    if (k->find("enabled")) options_.auth.keycloak.enabled = k->find("enabled")->asBool(options_.auth.keycloak.enabled);
                    if (auto x=k->find("issuer")) if (x&&x->isString()) options_.auth.keycloak.issuer=x->asString();
                    if (auto x=k->find("client_id")) if (x&&x->isString()) options_.auth.keycloak.clientId=x->asString();
                    if (auto x=k->find("client_secret")) if (x&&x->isString()) options_.auth.keycloak.clientSecret=x->asString();
                    if (auto x=k->find("realm_roles_map")) if (x&&x->isString()) options_.auth.keycloak.realmRolesMap=x->asString();
                    if (k->find("use_introspection")) options_.auth.keycloak.useIntrospection = k->find("use_introspection")->asBool(options_.auth.keycloak.useIntrospection);
                    if (keycloak_) keycloak_->setConfig(options_.auth.keycloak);
                }
                LOG_INFO("config: auth overrides applied: local ", options_.auth.localEnabled ? "on" : "off", ", ldap ",
                         options_.auth.ldap.enabled ? "on" : "off", ", keycloak ",
                         options_.auth.keycloak.enabled ? "on" : "off");
            }
        }
    }
    // parse wscluster config
    if (!options_.config.empty()) {
        LOG_DEBUG("config: re-reading ", options_.config, " for the wscluster block");
        auto cfg2 = config::Config::load(options_.config);
        if (!cfg2) LOG_ERROR("config: re-reading ", options_.config, " failed: ", cfg2.error());
        if (cfg2) {
            const config::Node* s3mm2 = cfg2.value().s3mm();
            const config::Node* wc = nullptr;
            if (s3mm2) wc = s3mm2->find("wscluster");
            if (!wc) for (const auto& r : cfg2.value().roots()) if (r.name == "wscluster") { wc = &r; break; }
            if (wc && wc->block) {
                options_.wscluster.enabled = wc->boolValue("enabled", false);
                options_.wscluster.bind = wc->value("bind", options_.wscluster.bind);
                options_.wscluster.port = (int)wc->int64Value("port", options_.wscluster.port);
                options_.wscluster.certsDir = wc->value("certs_dir");
                options_.wscluster.useMtls = wc->boolValue("use_mtls", options_.wscluster.useMtls);
                options_.wscluster.clusterSecret = wc->value("cluster_secret");
                LOG_INFO("config: wscluster ", options_.wscluster.enabled ? "enabled" : "disabled", ", bind ",
                         options_.wscluster.bind, ":", options_.wscluster.port, ", mTLS ",
                         options_.wscluster.useMtls ? "on" : "off", ", certs dir '", options_.wscluster.certsDir,
                         "', cluster secret ", log::redact(options_.wscluster.clusterSecret));
            } else {
                LOG_DEBUG("config: no wscluster block, mesh disabled");
            }
        }
    }
    cluster_ = std::make_unique<ClusterManager>();
    ClusterConfig cc;
    cc.nodeId = cluster_->nodeId();
    cc.enabled = options_.wscluster.enabled;
    cc.bind = options_.wscluster.bind;
    cc.port = options_.wscluster.port;
    cc.certsDir = options_.wscluster.certsDir;
    cc.useMtls = options_.wscluster.useMtls;
    cc.clusterSecret = options_.wscluster.clusterSecret;
    cluster_->setConfig(cc);
    LOG_INFO("wscluster: node ", cc.nodeId, ", ", cluster_->peers().size(), " known peers");
    daemonClient_ = cli::Client(options_.socket);
    LOG_INFO("control: s3mmd control socket is ", options_.socket);
    if (::access(options_.socket.c_str(), F_OK) != 0)
        LOG_WARN("control: ", options_.socket, " does not exist yet (", std::strerror(errno),
                 "); requests to s3mmd will fail until it is started");
    if (options_.modulesDir.empty()) {
        options_.modulesDir = "./modules";
        LOG_DEBUG("config: modules dir not set, using ", options_.modulesDir);
    }

    RestContext ctx(daemonClient_, options_.modulesDir);
    for (const auto& block : options_.modules) {
        const std::string name = block.argOr(0);
        if (name.empty()) {
            LOG_ERROR("rest modules: 'module' at ", block.file, ":", block.line, " has no name, ignored");
            continue;
        }
        auto loaded = loader_.loadModule(name, block.value("path"), options_.modulesDir);
        if (!loaded) {
            LOG_ERROR("rest modules: ", loaded.error(), "; the module stays disabled");
            continue;
        }
        IRestModule* m = loaded.value();
        if (auto configured = m->configure(block); !configured) {
            LOG_ERROR("rest modules: module '", name, "' rejected its configuration (", block.file, ":", block.line,
                      "): ", configured.error(), "; the module stays disabled");
            continue;
        }
        LOG_DEBUG("rest modules: initializing '", name, "'");
        m->onLoad(ctx);
        m->registerRoutes(router_);
        modules_.push_back(m);
        LOG_NOTICE("rest modules: module '", name, "' active", m->uiExtension().isNull() ? "" : " (with web UI page)");
    }
    LOG_INFO("rest modules: ", modules_.size(), " of ", options_.modules.size(), " configured module(s) active");

    registerDefaults();
    LOG_DEBUG("startup: built-in routes registered");

    auto listened = http_.listen(options_.listen, options_.port);
    if (!listened) {
        LOG_CRITICAL("rest http: cannot listen on ", options_.listen, ":", options_.port, ": ", listened.error());
        return 1;
    }
    LOG_INFO("rest http on http://", options_.listen, ":", options_.port);

    if (options_.daemonize) {
        // Simple daemonize.
        LOG_DEBUG("startup: daemonizing");
        pid_t pid = fork();
        if (pid < 0) {
            LOG_CRITICAL("startup: fork failed: ", std::strerror(errno));
            return 1;
        }
        if (pid > 0) return 0;
        if (setsid() < 0) LOG_WARN("startup: setsid failed: ", std::strerror(errno));
        LOG_INFO("startup: running in background as pid ", ::getpid());
    }

    std::signal(SIGTERM, onSignal);
    std::signal(SIGINT, onSignal);
    std::signal(SIGHUP, onReloadSignal);
    std::signal(SIGPIPE, SIG_IGN);
    LOG_DEBUG("startup: signal handlers installed (TERM, INT, HUP; PIPE ignored)");
    LOG_NOTICE("s3mmws started (pid ", ::getpid(), "), auth ", options_.auth.enabled ? "enabled" : "disabled",
               ", serving http://", options_.listen, ":", options_.port);

    while (!gStop) {
        if (gHup) {
            gHup = 0;
            LOG_NOTICE("SIGHUP received: s3mmws has no live reload, restart the service to apply configuration changes");
        }
        pollfd pfd{http_.fd(), POLLIN, 0};
        int rc = ::poll(&pfd, 1, 500);
        if (rc < 0) {
            if (errno == EINTR) continue;
            LOG_CRITICAL("main loop: poll failed: ", std::strerror(errno), ", stopping");
            break;
        }
        if (rc > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
            LOG_ERROR("main loop: listening socket reported revents 0x", std::hex, pfd.revents);
        if (rc > 0 && (pfd.revents & POLLIN)) {
            http_.acceptOne([this](const RestRequest& req, RestResponse& res) {
                gUser = "-";
                // Authentication chain (modules).
                for (auto* m : modules_) {
                    if (!m->authenticate(req, res)) {
                        LOG_WARN(requestTag(), "auth: module '", m->info().name, "' rejected ", req.method, " ", req.path,
                                 " with ", res.status);
                        return;
                    }
                }
                // Built-in auth (only s3mmws level).
                AuthUser currentUser;
                bool haveUser = false;
                bool isPublic = (req.path == "/health") || (req.path.rfind("/auth/",0)==0 && req.path != "/auth/me") || (req.path == "/wscluster/init") || (req.path == "/wscluster/status"); 
                // Actually /auth/me requires auth; handle below.
                if (req.path == "/auth/me") isPublic = false;
                bool clusterAuth = false;
                if (options_.auth.enabled && !isPublic) {
                    auto csit = req.headers.find("X-Cluster-Secret");
                    if (csit != req.headers.end() && cluster_ && !cluster_->config().clusterSecret.empty() && csit->second == cluster_->config().clusterSecret) {
                        currentUser.id = "cluster"; currentUser.username = "cluster"; currentUser.roles = {"admin"};
                        haveUser = true; clusterAuth = true;
                        LOG_DEBUG(requestTag(), "auth: authenticated by cluster secret");
                    } else {
                        if (csit != req.headers.end())
                            LOG_WARN(requestTag(), "auth: X-Cluster-Secret presented for ", req.method, " ", req.path,
                                     " does not match (", log::redact(csit->second), "), falling back to session auth");
                        std::string tok;
                        auto it = req.headers.find("Authorization");
                        if (it != req.headers.end()) {
                            std::string v = it->second;
                            if (v.rfind("Bearer ",0)==0) tok = v.substr(7);
                        }
                        if (tok.empty() && req.headers.count("X-Auth-Token")) tok = req.headers.at("X-Auth-Token");
                        auto u = sessions_->resolve(tok);
                        if (!u) {
                            LOG_WARN(requestTag(), "auth: ", req.method, " ", req.path, " rejected with 401: ",
                                     tok.empty() ? "no session token" : "invalid or expired session token");
                            res.status = 401; res.json(Value::object().set("error", Value::str("unauthorized"))); return;
                        }
                        currentUser = *u; haveUser = true;
                        // permission check
                        std::string resource = "explorer";
                        if (req.path.rfind("/clusters",0)==0) resource="clusters";
                        else if (req.path.rfind("/credentials",0)==0) resource="credentials";
                        else if (req.path.rfind("/replications",0)==0) resource="replications";
                        else if (req.path.rfind("/targets",0)==0) resource="targets";
                        else if (req.path.rfind("/policies",0)==0) resource="policies";
                        else if (req.path.rfind("/rbac",0)==0) resource="rbac";
                        else if (req.path.rfind("/audit",0)==0) resource="audit";
                        else if (req.path.rfind("/browse",0)==0) resource="explorer";
                        else if (req.path.rfind("/status",0)==0) resource="clusters";
                        else if (req.path.rfind("/modules",0)==0) resource="clusters";
                        else if (req.path.rfind("/ui/",0)==0) resource="clusters";
                        else if (req.path.rfind("/ext/",0)==0) resource="s3mmws";
                        bool write = (req.method != "GET");
                        std::string perm = resource + ":" + (write ? "write" : "read");
                        // admin-ish manage for rbac writes
                        if (resource=="rbac" && write) perm = "rbac:manage";
                        if (!rbac_->hasPermission(currentUser, perm)) {
                            LOG_WARN(requestTag(), "auth: '", currentUser.id, "' denied ", req.method, " ", req.path,
                                     ": missing permission ", perm);
                            res.status = 403;
                            res.json(Value::object().set("error", Value::str("forbidden")));
                            return;
                        }
                        LOG_DEBUG(requestTag(), "auth: '", currentUser.id, "' allowed ", perm, " for ", req.method, " ", req.path);
                    }
                } else if (!options_.auth.enabled) {
                    // anonymous admin
                    currentUser.id = "anonymous";
                    currentUser.username = "anonymous";
                    currentUser.roles = {"admin"};
                    haveUser = true;
                } else {
                    LOG_DEBUG(requestTag(), "auth: ", req.path, " is public");
                }
                if (haveUser) gUser = currentUser.id;
                (void)clusterAuth;
                // S3 proxy gateway for cross-segment access.
                if (req.path.rfind("/s3proxy/", 0) == 0) {
                    // path: /s3proxy/{cluster}/{bucket}/{key...}
                    std::string rest = req.path.substr(9);
                    size_t slash = rest.find('/');
                    std::string cluster = (slash == std::string::npos) ? rest : rest.substr(0, slash);
                    std::string remainder = (slash == std::string::npos) ? "" : rest.substr(slash + 1);
                    size_t slash2 = remainder.find('/');
                    std::string bucket = (slash2 == std::string::npos) ? remainder : remainder.substr(0, slash2);
                    std::string key = (slash2 == std::string::npos) ? "" : remainder.substr(slash2 + 1);
                    LOG_INFO(who(), "s3proxy: ", req.method, " cluster '", cluster, "' bucket '", bucket, "' key '", key, "'");
                    auto client = makeClient(cluster);
                    if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
                    if (bucket.empty()) {
                        // ListBuckets not cluster-specific; return simple list
                        res.status = 200; res.headers["Content-Type"] = "application/xml";
                        res.body = "<ListAllMyBucketsResult><Buckets></Buckets></ListAllMyBucketsResult>";
                        return;
                    }
                    if (key.empty()) {
                        if (req.method == "GET") {
                            auto page = client->listObjects(bucket, req.query.count("prefix") ? req.query.at("prefix") : "");
                            if (!page) {
                                LOG_ERROR(who(), "s3proxy: list objects failed: ", page.error());
                                res.status = 502; res.json(Value::object().set("error", Value::str(page.error()))); return;
                            }
                            std::ostringstream xml;
                            xml << "<ListBucketResult><Name>" << bucket << "</Name><Contents>";
                            for (auto& o : page.value().objects) {
                                xml << "<Contents><Key>" << o.key << "</Key><Size>" << o.size << "</Size><LastModified>" << tm::toIso8601(o.lastModified) << "</LastModified><ETag>" << o.etag << "</ETag></Contents>";
                            }
                            xml << "</Contents></ListBucketResult>";
                            res.status = 200; res.headers["Content-Type"] = "application/xml"; res.body = xml.str();
                            return;
                        }
                        if (req.method == "PUT") {
                            auto created = client->createBucket(bucket);
                            if (!created) {
                                LOG_ERROR(who(), "s3proxy: create bucket failed: ", created.error());
                                res.status = 502; res.json(Value::object().set("error", Value::str(created.error()))); return;
                            }
                            res.status = 200; res.body = "";
                            return;
                        }
                        if (req.method == "DELETE") {
                            auto del = client->deleteBucket(bucket);
                            if (!del) {
                                LOG_ERROR(who(), "s3proxy: delete bucket failed: ", del.error());
                                res.status = 502; res.json(Value::object().set("error", Value::str(del.error()))); return;
                            }
                            res.status = 204; res.body = "";
                            return;
                        }
                    } else {
                        if (req.method == "GET") {
                            auto meta = client->headObject(bucket, key);
                            if (!meta || !meta.value().exists) {
                                LOG_WARN(who(), "s3proxy: ", bucket, "/", key, " not found", meta ? std::string() : ": " + meta.error());
                                res.status = 404; res.body = ""; return;
                            }
                            uint64_t sz = meta.value().size;
                            std::string content;
                            if (sz > 0) {
                                auto range = client->getObjectRange(bucket, key, 0, sz);
                                if (range) content = range.value();
                                else LOG_ERROR(who(), "s3proxy: reading ", bucket, "/", key, " failed: ", range.error(),
                                               "; answering 200 with an empty body");
                            }
                            res.status = 200;
                            res.headers["Content-Type"] = meta.value().contentType.empty() ? "application/octet-stream" : meta.value().contentType;
                            res.body = content;
                            return;
                        }
                        if (req.method == "HEAD") {
                            auto meta = client->headObject(bucket, key);
                            if (!meta || !meta.value().exists) {
                                LOG_DEBUG(who(), "s3proxy: HEAD ", bucket, "/", key, " -> not found");
                                res.status = 404; return;
                            }
                            res.status = 200;
                            res.headers["Content-Type"] = meta.value().contentType.empty() ? "application/octet-stream" : meta.value().contentType;
                            res.headers["Content-Length"] = std::to_string(meta.value().size);
                            res.body = "";
                            return;
                        }
                        if (req.method == "PUT") {
                            s3::ObjectMeta meta;
                            meta.contentType = req.headers.count("Content-Type") ? req.headers.at("Content-Type") : "application/octet-stream";
                            auto put = client->putObject(bucket, key, req.body, meta);
                            if (!put) {
                                LOG_ERROR(who(), "s3proxy: put object failed: ", put.error());
                                res.status = 502; res.json(Value::object().set("error", Value::str(put.error()))); return;
                            }
                            res.status = 200; res.body = "";
                            return;
                        }
                        if (req.method == "DELETE") {
                            auto del = client->deleteObject(bucket, key);
                            if (!del) {
                                LOG_ERROR(who(), "s3proxy: delete object failed: ", del.error());
                                res.status = 502; res.json(Value::object().set("error", Value::str(del.error()))); return;
                            }
                            res.status = 204; res.body = "";
                            return;
                        }
                    }
                    LOG_WARN(who(), "s3proxy: method ", req.method, " not supported for ", key.empty() ? "bucket" : "object");
                    res.status = 405; res.body = "";
                    return;
                }
                // Request processing chain.
                for (auto* m : modules_) {
                    if (m->process(req, res)) {
                        LOG_DEBUG(requestTag(), "rest modules: '", m->info().name, "' handled ", req.method, " ", req.path);
                        return;
                    }
                }
                if (!router_.route(req, res)) {
                    res.status = 404;
                    res.json(Value::object().set("error", Value::str("not found")));
                }
            });
        }
    }
    LOG_NOTICE("s3mmws stopping", gSignal ? " on signal " + std::to_string((int)gSignal) : std::string());
    http_.close();
    LOG_NOTICE("s3mmws stopped");
    return 0;
}

} // namespace s3mm::rest
