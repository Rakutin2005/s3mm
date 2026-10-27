#include "s3mm/rest/auth.hpp"

#include <argon2.h>
#include <ldap.h>
#include <curl/curl.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>

#include "s3mm/common/crypto.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::rest {
namespace fs = s3mm::fs;

// ---------------- SessionManager ----------------
std::string SessionManager::create(const AuthUser& user) {
    std::string token = crypto::randomHex(32);
    std::lock_guard<std::mutex> lk(m_);
    s_[token].u = user; s_[token].e = std::chrono::steady_clock::now() + std::chrono::seconds(ttl_);
    LOG_INFO("sessions: created session for '", user.id, "' (provider ", user.provider, ", ttl ", ttl_, " s, token ",
             log::redact(token), "), ", s_.size(), " active");
    return token;
}
std::optional<AuthUser> SessionManager::resolve(const std::string& token) {
    if (token.empty()) {
        LOG_DEBUG("sessions: no session token presented");
        return std::nullopt;
    }
    std::lock_guard<std::mutex> lk(m_);
    auto it = s_.find(token);
    if (it == s_.end()) {
        LOG_DEBUG("sessions: unknown session token ", log::redact(token));
        return std::nullopt;
    }
    if (std::chrono::steady_clock::now() > it->second.e) {
        LOG_INFO("sessions: session of '", it->second.u.id, "' expired, removing");
        s_.erase(it);
        return std::nullopt;
    }
    LOG_DEBUG("sessions: token resolved to '", it->second.u.id, "'");
    return it->second.u;
}
void SessionManager::revoke(const std::string& token) {
    std::lock_guard<std::mutex> lk(m_);
    auto it = s_.find(token);
    if (it == s_.end()) {
        LOG_DEBUG("sessions: revoke of unknown token ", log::redact(token));
        return;
    }
    LOG_INFO("sessions: revoked session of '", it->second.u.id, "'");
    s_.erase(it);
}
void SessionManager::sweep() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(m_);
    size_t removed = 0;
    for (auto it = s_.begin(); it != s_.end();) {
        if (now > it->second.e) { it = s_.erase(it); ++removed; } else ++it;
    }
    LOG_DEBUG("sessions: sweep removed ", removed, " expired sessions, ", s_.size(), " active");
}

// ---------------- LocalAuthProvider ----------------
static std::string b64(const std::string& s) { return crypto::base64Encode(s); }
static std::string unb64(const std::string& s) { auto d = crypto::base64Decode(s); return d ? *d : std::string(); }

LocalAuthProvider::LocalAuthProvider(const std::string& usersFile, int argonIters, int argonMem, int argonPar)
    : usersFile_(usersFile), iters_(argonIters), mem_(argonMem), par_(argonPar) {
    LOG_DEBUG("auth/local: initializing from ", usersFile_, " (argon2id t=", iters_, " m=", mem_, " KiB p=", par_, ")");
    load();
    if (users_.empty()) {
        LocalUserRecord rec; rec.username = "admin"; rec.displayName = "Administrator"; rec.roles = {"admin"};
        addUser(rec, "admin");
        LOG_WARN("auth: no local users found; created default user 'admin' with password 'admin' (change immediately)");
    }
}

void LocalAuthProvider::load() {
    std::lock_guard<std::mutex> lk(mtx_);
    users_.clear();
    auto content = fs::readFile(usersFile_);
    if (!content) {
        LOG_WARN("auth/local: users file ", usersFile_, " is missing or unreadable");
        return;
    }
    std::string err;
    Value v = Value::parseJson(*content, &err);
    if (!err.empty() || !v.isArray()) {
        LOG_ERROR("auth/local: users file ", usersFile_, " is not a JSON array",
                  err.empty() ? std::string() : ": " + err, "; ignoring its content");
        return;
    }
    for (const auto& u : v.items()) {
        if (!u.isObject()) continue;
        LocalUserRecord r;
        r.username = u.getString("username");
        r.displayName = u.getString("display_name");
        r.email = u.getString("email");
        r.salt = u.getString("salt");
        r.hash = u.getString("hash");
        if (const Value* rr = u.find("roles")) if (rr && rr->isArray()) for (const auto& x : rr->items()) r.roles.push_back(x.asString());
        if (r.username.empty()) {
            LOG_WARN("auth/local: skipping user record without username in ", usersFile_);
            continue;
        }
        users_.push_back(r);
        LOG_DEBUG("auth/local: loaded user '", r.username, "' (", r.roles.size(), " roles)");
    }
    LOG_INFO("auth/local: loaded ", users_.size(), " users from ", usersFile_);
}

void LocalAuthProvider::save() const {
    Value arr = Value::array();
    for (const auto& u : users_) {
        Value v = Value::object();
        v.set("username", Value::str(u.username));
        v.set("display_name", Value::str(u.displayName));
        v.set("email", Value::str(u.email));
        v.set("salt", Value::str(u.salt));
        v.set("hash", Value::str(u.hash));
        Value roles = Value::array();
        for (const auto& r : u.roles) roles.push(Value::str(r));
        v.set("roles", roles);
        arr.push(v);
    }
    if (fs::writeFileAtomic(usersFile_, arr.toJson(2)))
        LOG_DEBUG("auth/local: saved ", users_.size(), " users to ", usersFile_);
    else
        LOG_ERROR("auth/local: failed to write users file ", usersFile_, ": ", std::strerror(errno));
}

std::string LocalAuthProvider::hashPw(const std::string& password, const std::string& salt) const {
    std::string saltBytes = unb64(salt);
    if (saltBytes.empty()) saltBytes = crypto::randomBytes(16);
    size_t hashLen = 32;
    std::string out(hashLen, '\0');
    int rc = argon2id_hash_raw(iters_, (uint32_t)mem_, (uint32_t)par_,
                               password.data(), password.size(),
                               saltBytes.data(), saltBytes.size(),
                               out.data(), out.size());
    if (rc != ARGON2_OK) {
        LOG_WARN("auth/local: argon2id failed (", argon2_error_message(rc), "), falling back to PBKDF2");
        auto d = crypto::pbkdf2(password, saltBytes, 100000, hashLen);
        out.assign(reinterpret_cast<const char*>(d.data()), d.size());
    }
    return b64(out);
}

bool LocalAuthProvider::addUser(const LocalUserRecord& rec, const std::string& password) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& u : users_) if (u.username == rec.username) {
        LOG_WARN("auth/local: cannot add user '", rec.username, "': already exists");
        return false;
    }
    LocalUserRecord r = rec;
    std::string salt = crypto::randomBytes(16);
    r.salt = b64(salt);
    // need hash with salt; temporarily set iters via hashPw uses salt param
    r.hash = hashPw(password, r.salt);
    users_.push_back(r);
    save();
    LOG_INFO("auth/local: added user '", r.username, "' with roles [", str::join(r.roles, ","), "]");
    return true;
}

bool LocalAuthProvider::removeUser(const std::string& username) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = std::remove_if(users_.begin(), users_.end(), [&](const LocalUserRecord& u){ return u.username == username; });
    if (it == users_.end()) {
        LOG_WARN("auth/local: cannot remove user '", username, "': not found");
        return false;
    }
    users_.erase(it, users_.end());
    save();
    LOG_INFO("auth/local: removed user '", username, "'");
    return true;
}

std::vector<LocalUserRecord> LocalAuthProvider::listUsers() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return users_;
}

AuthResult LocalAuthProvider::authenticate(const std::string& username, const std::string& password) {
    AuthResult res;
    LOG_DEBUG("auth/local: authenticating '", username, "' (enabled ", enabled_ ? "yes" : "no", ")");
    std::lock_guard<std::mutex> lk(mtx_);
    for (const auto& u : users_) {
        if (u.username != username) continue;
        std::string computed = hashPw(password, u.salt);
        if (computed.size() != u.hash.size()) {
            LOG_WARN("auth/local: login failed for '", username, "': stored hash has unexpected length");
            res.error = "invalid credentials";
            return res;
        }
        bool ok = true;
        for (size_t i = 0; i < computed.size(); ++i) if (computed[i] != u.hash[i]) ok = false;
        if (!ok) {
            LOG_WARN("auth/local: login failed for '", username, "': wrong password");
            res.error = "invalid credentials";
            return res;
        }
        res.ok = true;
        res.user.id = "local:" + u.username;
        res.user.username = u.username;
        res.user.displayName = u.displayName.empty() ? u.username : u.displayName;
        res.user.email = u.email;
        res.user.provider = "local";
        res.user.roles = u.roles;
        LOG_INFO("auth/local: '", username, "' authenticated, roles [", str::join(u.roles, ","), "]");
        return res;
    }
    LOG_WARN("auth/local: login failed for '", username, "': no such user");
    res.error = "invalid credentials";
    return res;
}

// ---------------- LDAP ----------------
LdapAuthProvider::LdapAuthProvider(const LdapConfig& cfg) : cfg_(cfg) {
    LOG_DEBUG("auth/ldap: provider created (enabled ", cfg_.enabled ? "yes" : "no", ", url '", cfg_.url, "', bind_dn '",
              cfg_.bindDn, "', bind password ", log::redact(cfg_.bindPassword), ", user base '", cfg_.userSearchBase,
              "', group base '", cfg_.groupSearchBase, "', ", cfg_.groupRoleMap.size(), " group->role mappings)");
}

AuthResult LdapAuthProvider::authenticate(const std::string& username, const std::string& password) {
    AuthResult res;
    log::Stopwatch sw;
    if (!cfg_.enabled) {
        LOG_WARN("auth/ldap: login attempt for '", username, "' while LDAP is disabled");
        res.error = "ldap disabled";
        return res;
    }
    if (username.empty() || password.empty()) {
        LOG_WARN("auth/ldap: login rejected: empty ", username.empty() ? "username" : "password");
        res.error = "invalid credentials";
        return res;
    }

    LOG_DEBUG("auth/ldap: initializing connection to ", cfg_.url, " for '", username, "'");
    LDAP* ld = nullptr;
    int rc = ldap_initialize(&ld, cfg_.url.c_str());
    if (rc != LDAP_SUCCESS || !ld) {
        LOG_ERROR("auth/ldap: ldap_initialize(", cfg_.url, ") failed: ", ldap_err2string(rc));
        res.error = "ldap init failed";
        return res;
    }
    int ver = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);

    if (!cfg_.bindDn.empty()) {
        LOG_DEBUG("auth/ldap: service bind as '", cfg_.bindDn, "' to ", cfg_.url);
        berval cred; cred.bv_val = (char*)cfg_.bindPassword.c_str(); cred.bv_len = cfg_.bindPassword.size();
        rc = ldap_sasl_bind_s(ld, cfg_.bindDn.c_str(), LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, nullptr);
        if (rc != LDAP_SUCCESS) {
            LOG_ERROR("auth/ldap: service bind as '", cfg_.bindDn, "' to ", cfg_.url, " failed: ", ldap_err2string(rc),
                      " (", rc, ")");
            res.error = "ldap service bind failed";
            ldap_unbind_ext_s(ld, nullptr, nullptr);
            return res;
        }
        LOG_INFO("auth/ldap: connected to ", cfg_.url, " and bound as '", cfg_.bindDn, "'");
    } else {
        LOG_DEBUG("auth/ldap: no bind_dn configured, searching anonymously");
    }

    std::string filter = cfg_.userFilter;
    size_t pos = filter.find("%s");
    if (pos != std::string::npos) filter.replace(pos, 2, username);
    char* attrs[] = { (char*)cfg_.attrUid.c_str(), (char*)cfg_.attrMail.c_str(), (char*)cfg_.attrDisplayName.c_str(), nullptr };
    LDAPMessage* msg = nullptr;
    LOG_DEBUG("auth/ldap: user search base '", cfg_.userSearchBase, "' filter '", filter, "'");
    rc = ldap_search_ext_s(ld, cfg_.userSearchBase.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(), attrs, 0, nullptr, nullptr, nullptr, 1, &msg);
    if (rc != LDAP_SUCCESS || !msg) {
        LOG_ERROR("auth/ldap: user search for '", username, "' failed: ", ldap_err2string(rc), " (", rc, ")");
        res.error = "ldap user search failed";
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return res;
    }
    LDAPMessage* entry = ldap_first_entry(ld, msg);
    if (!entry) {
        LOG_WARN("auth/ldap: login failed for '", username, "': user not found under '", cfg_.userSearchBase, "'");
        res.error = "user not found";
        ldap_msgfree(msg);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return res;
    }
    char* dn = ldap_get_dn(ld, entry);
    std::string userDn = dn ? dn : "";
    if (dn) ldap_memfree(dn);
    LOG_DEBUG("auth/ldap: '", username, "' resolved to DN '", userDn, "'");

    auto getAttr = [&](const std::string& a) -> std::string {
        struct berval** vals = ldap_get_values_len(ld, entry, a.c_str());
        std::string out;
        if (vals && vals[0]) out.assign(vals[0]->bv_val, vals[0]->bv_len);
        if (vals) ldap_value_free_len(vals);
        return out;
    };
    std::string uid = getAttr(cfg_.attrUid);
    std::string mail = getAttr(cfg_.attrMail);
    std::string disp = getAttr(cfg_.attrDisplayName);
    if (uid.empty()) uid = username;

    berval ucred; ucred.bv_val = (char*)password.c_str(); ucred.bv_len = password.size();
    rc = ldap_sasl_bind_s(ld, userDn.c_str(), LDAP_SASL_SIMPLE, &ucred, nullptr, nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
        LOG_WARN("auth/ldap: login failed for '", username, "': bind as '", userDn, "' rejected: ", ldap_err2string(rc));
        res.error = "invalid credentials";
        ldap_msgfree(msg);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return res;
    }
    LOG_DEBUG("auth/ldap: user bind as '", userDn, "' succeeded");

    std::vector<std::string> groups;
    if (!cfg_.groupSearchBase.empty()) {
        std::string gfilter = cfg_.groupFilter;
        size_t p = gfilter.find("%s");
        if (p != std::string::npos) gfilter.replace(p, 2, userDn);
        LDAPMessage* gmsg = nullptr;
        char* gattrs[] = { (char*)"cn", nullptr };
        LOG_DEBUG("auth/ldap: group search base '", cfg_.groupSearchBase, "' filter '", gfilter, "'");
        rc = ldap_search_ext_s(ld, cfg_.groupSearchBase.c_str(), LDAP_SCOPE_SUBTREE, gfilter.c_str(), gattrs, 0, nullptr, nullptr, nullptr, 1000, &gmsg);
        if (rc != LDAP_SUCCESS)
            LOG_WARN("auth/ldap: group search for '", userDn, "' failed: ", ldap_err2string(rc), " (", rc, "); continuing without groups");
        if (rc == LDAP_SUCCESS && gmsg) {
            for (LDAPMessage* ge = ldap_first_entry(ld, gmsg); ge; ge = ldap_next_entry(ld, ge)) {
                struct berval** cns = ldap_get_values_len(ld, ge, "cn");
                if (cns && cns[0]) groups.push_back(std::string(cns[0]->bv_val, cns[0]->bv_len));
                if (cns) ldap_value_free_len(cns);
                char* gdn = ldap_get_dn(ld, ge);
                if (gdn) { groups.push_back(gdn); ldap_memfree(gdn); }
            }
            ldap_msgfree(gmsg);
        }
    }

    ldap_msgfree(msg);
    ldap_unbind_ext_s(ld, nullptr, nullptr);

    std::vector<std::string> roles;
    for (const auto& g : groups) {
        auto it = cfg_.groupRoleMap.find(g);
        if (it != cfg_.groupRoleMap.end()) roles.push_back(it->second);
        size_t eq = g.find("cn=");
        if (eq != std::string::npos) {
            std::string cn = g.substr(eq + 3);
            size_t comma = cn.find(',');
            if (comma != std::string::npos) cn = cn.substr(0, comma);
            auto it2 = cfg_.groupRoleMap.find(cn);
            if (it2 != cfg_.groupRoleMap.end()) roles.push_back(it2->second);
        }
    }
    std::sort(roles.begin(), roles.end());
    roles.erase(std::unique(roles.begin(), roles.end()), roles.end());
    LOG_DEBUG("auth/ldap: '", username, "' groups [", str::join(groups, "; "), "]");
    if (roles.empty()) {
        LOG_DEBUG("auth/ldap: no group of '", username, "' is mapped to a role, defaulting to 'viewer'");
        roles.push_back("viewer");
    }

    LOG_INFO("auth/ldap: '", username, "' authenticated as uid '", uid, "', ", groups.size(), " groups, roles [",
             str::join(roles, ","), "] in ", sw.ms(), " ms");
    res.ok = true;
    res.user.id = "ldap:" + uid;
    res.user.username = uid;
    res.user.displayName = disp.empty() ? uid : disp;
    res.user.email = mail;
    res.user.provider = "ldap";
    res.user.roles = roles;
    res.user.groups = groups;
    return res;
}

// ---------------- Keycloak ----------------
static size_t curlWriteCb(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

static void logCurlResult(const char* method, const std::string& url, CURL* curl, CURLcode rc, const char* errbuf,
                          size_t respSize, const log::Stopwatch& sw) {
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc != CURLE_OK) {
        LOG_ERROR("auth/keycloak: ", method, " ", url, " failed: ", curl_easy_strerror(rc),
                  errbuf[0] ? std::string(" (") + errbuf + ")" : std::string(), " after ", sw.ms(), " ms");
        return;
    }
    if (status >= 400)
        LOG_WARN("auth/keycloak: ", method, " ", url, " -> HTTP ", status, ", ", respSize, " bytes, ", sw.ms(), " ms");
    else
        LOG_DEBUG("auth/keycloak: ", method, " ", url, " -> HTTP ", status, ", ", respSize, " bytes, ", sw.ms(), " ms");
}

static std::string curlPost(const std::string& url, const std::string& body, const std::string& bearer = "") {
    CURL* curl = curl_easy_init();
    std::string resp;
    if (!curl) {
        LOG_ERROR("auth/keycloak: curl_easy_init failed for POST ", url);
        return "";
    }
    log::Stopwatch sw;
    char errbuf[CURL_ERROR_SIZE] = "";
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    LOG_DEBUG("auth/keycloak: POST ", url, " (", body.size(), " bytes", bearer.empty() ? "" : ", bearer token", ")");
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    if (!bearer.empty()) {
        std::string h = "Authorization: Bearer " + bearer;
        headers = curl_slist_append(headers, h.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    // allow self-signed? keep verify on by default
    CURLcode rc = curl_easy_perform(curl);
    logCurlResult("POST", url, curl, rc, errbuf, resp.size(), sw);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}

static std::string curlGet(const std::string& url, const std::string& bearer = "") {
    CURL* curl = curl_easy_init();
    std::string resp;
    if (!curl) {
        LOG_ERROR("auth/keycloak: curl_easy_init failed for GET ", url);
        return "";
    }
    log::Stopwatch sw;
    char errbuf[CURL_ERROR_SIZE] = "";
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    LOG_DEBUG("auth/keycloak: GET ", url, bearer.empty() ? "" : " (bearer token)");
    struct curl_slist* headers = nullptr;
    if (!bearer.empty()) {
        std::string h = "Authorization: Bearer " + bearer;
        headers = curl_slist_append(headers, h.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    CURLcode rc = curl_easy_perform(curl);
    logCurlResult("GET", url, curl, rc, errbuf, resp.size(), sw);
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}

KeycloakAuthProvider::KeycloakAuthProvider(const KeycloakConfig& cfg) : cfg_(cfg) {
    discover();
}

void KeycloakAuthProvider::discover() {
    if (cfg_.issuer.empty()) {
        LOG_DEBUG("auth/keycloak: no issuer configured (enabled ", cfg_.enabled ? "yes" : "no", ")");
        if (cfg_.enabled) LOG_WARN("auth/keycloak: enabled but issuer is empty; logins will fail");
        return;
    }
    std::string base = cfg_.issuer;
    if (!base.empty() && base.back() == '/') base.pop_back();
    tokenEndpoint_ = base + "/protocol/openid-connect/token";
    userinfoEndpoint_ = base + "/protocol/openid-connect/userinfo";
    introspectionEndpoint_ = base + "/protocol/openid-connect/token/introspect";
    LOG_DEBUG("auth/keycloak: issuer ", base, ", client_id '", cfg_.clientId, "', client secret ",
              log::redact(cfg_.clientSecret), ", introspection ", cfg_.useIntrospection ? "on" : "off",
              ", token endpoint ", tokenEndpoint_);
}

std::map<std::string, std::string> KeycloakAuthProvider::parseRoleMap() const {
    std::map<std::string, std::string> out;
    std::string s = cfg_.realmRolesMap;
    size_t start = 0;
    while (true) {
        size_t semi = s.find(';', start);
        std::string part = (semi == std::string::npos) ? s.substr(start) : s.substr(start, semi - start);
        size_t eq = part.find('=');
        if (eq != std::string::npos) {
            auto trim = [](std::string x){ size_t a=x.find_first_not_of(" \t"); size_t b=x.find_last_not_of(" \t"); if(a==std::string::npos) return std::string(); return x.substr(a,b-a+1); };
            out[trim(part.substr(0,eq))] = trim(part.substr(eq+1));
        }
        if (semi == std::string::npos) break;
        start = semi + 1;
    }
    return out;
}

AuthResult KeycloakAuthProvider::authenticate(const std::string& username, const std::string& password) {
    AuthResult res;
    log::Stopwatch sw;
    if (!cfg_.enabled) {
        LOG_WARN("auth/keycloak: login attempt for '", username, "' while Keycloak is disabled");
        res.error = "keycloak disabled";
        return res;
    }
    if (username.empty() || password.empty()) {
        LOG_WARN("auth/keycloak: login rejected: empty ", username.empty() ? "username" : "password");
        res.error = "invalid credentials";
        return res;
    }
    LOG_DEBUG("auth/keycloak: password grant for '", username, "' at ", tokenEndpoint_);

    std::ostringstream body;
    body << "grant_type=password"
         << "&client_id=" << cfg_.clientId
         << "&username=" << username
         << "&password=" << password;
    if (!cfg_.clientSecret.empty()) body << "&client_secret=" << cfg_.clientSecret;

    std::string resp = curlPost(tokenEndpoint_, body.str());
    std::string err;
    Value v = Value::parseJson(resp, &err);
    if (err.size() || !v.isObject()) {
        LOG_ERROR("auth/keycloak: token request for '", username, "' failed: unreadable response (",
                  err.empty() ? "not an object" : err, "): ", log::clip(resp));
        res.error = "keycloak token request failed";
        return res;
    }
    std::string accessToken = v.getString("access_token");
    if (accessToken.empty()) {
        LOG_WARN("auth/keycloak: login failed for '", username, "': ", v.getString("error", "no access_token"), ": ",
                 v.getString("error_description"));
        res.error = v.getString("error_description", "invalid credentials");
        return res;
    }
    LOG_DEBUG("auth/keycloak: got access token ", log::redact(accessToken), " for '", username, "'");

    // userinfo
    std::string ui = curlGet(userinfoEndpoint_, accessToken);
    std::string uerr;
    Value uv = Value::parseJson(ui, &uerr);
    std::string sub, email, name;
    std::vector<std::string> kcRoles;
    if (uerr.empty() && uv.isObject()) {
        sub = uv.getString("sub");
        email = uv.getString("email");
        name = uv.getString("preferred_username", username);
        if (const Value* ra = uv.find("realm_access")) if (ra && ra->isObject()) if (const Value* r = ra->find("roles")) if (r && r->isArray()) for (auto& x : r->items()) kcRoles.push_back(x.asString());
        LOG_DEBUG("auth/keycloak: userinfo for '", username, "': sub '", sub, "', realm roles [", str::join(kcRoles, ","), "]");
    } else {
        LOG_WARN("auth/keycloak: userinfo for '", username, "' unreadable (", uerr.empty() ? "not an object" : uerr,
                 "), using defaults");
    }
    if (sub.empty()) sub = username;
    if (name.empty()) name = username;

    auto roleMap = parseRoleMap();
    std::vector<std::string> roles;
    for (auto& r : kcRoles) {
        auto it = roleMap.find(r);
        if (it != roleMap.end()) roles.push_back(it->second);
    }
    if (roles.empty()) {
        LOG_DEBUG("auth/keycloak: no realm role of '", username, "' is mapped, defaulting to 'viewer'");
        roles.push_back("viewer");
    }
    std::sort(roles.begin(), roles.end());
    roles.erase(std::unique(roles.begin(), roles.end()), roles.end());

    LOG_INFO("auth/keycloak: '", username, "' authenticated as '", sub, "', roles [", str::join(roles, ","), "] in ",
             sw.ms(), " ms");
    res.ok = true;
    res.user.id = "keycloak:" + sub;
    res.user.username = name;
    res.user.displayName = name;
    res.user.email = email;
    res.user.provider = "keycloak";
    res.user.roles = roles;
    res.user.groups = kcRoles;
    return res;
}

std::optional<AuthUser> KeycloakAuthProvider::resolveToken(const std::string& token) {
    if (token.empty() || !cfg_.enabled) {
        LOG_DEBUG("auth/keycloak: token resolution skipped (", token.empty() ? "empty token" : "keycloak disabled", ")");
        return std::nullopt;
    }
    LOG_DEBUG("auth/keycloak: introspecting token ", log::redact(token));
    // introspect
    std::ostringstream body;
    body << "token=" << token << "&client_id=" << cfg_.clientId;
    if (!cfg_.clientSecret.empty()) body << "&client_secret=" << cfg_.clientSecret;
    std::string resp = curlPost(introspectionEndpoint_, body.str());
    std::string err;
    Value v = Value::parseJson(resp, &err);
    if (err.size() || !v.isObject()) {
        LOG_ERROR("auth/keycloak: introspection response unreadable: ", err.empty() ? log::clip(resp) : err);
        return std::nullopt;
    }
    if (!(v.find("active") && v.find("active")->asBool(false))) {
        LOG_INFO("auth/keycloak: introspected token is not active");
        return std::nullopt;
    }
    AuthUser u;
    u.id = "keycloak:" + v.getString("sub");
    u.username = v.getString("preferred_username", v.getString("username"));
    u.provider = "keycloak";
    // roles from token? skip; default viewer
    u.roles = {"viewer"};
    LOG_DEBUG("auth/keycloak: token belongs to '", u.id, "' (", u.username, ")");
    return u;
}

} // namespace s3mm::rest
