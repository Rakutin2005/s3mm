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
    return token;
}
std::optional<AuthUser> SessionManager::resolve(const std::string& token) {
    if (token.empty()) return std::nullopt;
    std::lock_guard<std::mutex> lk(m_);
    auto it = s_.find(token);
    if (it == s_.end()) return std::nullopt;
    if (std::chrono::steady_clock::now() > it->second.e) { s_.erase(it); return std::nullopt; }
    return it->second.u;
}
void SessionManager::revoke(const std::string& token) {
    std::lock_guard<std::mutex> lk(m_);
    s_.erase(token);
}
void SessionManager::sweep() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(m_);
    for (auto it = s_.begin(); it != s_.end();) {
        if (now > it->second.e) it = s_.erase(it); else ++it;
    }
}

// ---------------- LocalAuthProvider ----------------
static std::string b64(const std::string& s) { return crypto::base64Encode(s); }
static std::string unb64(const std::string& s) { auto d = crypto::base64Decode(s); return d ? *d : std::string(); }

LocalAuthProvider::LocalAuthProvider(const std::string& usersFile, int argonIters, int argonMem, int argonPar)
    : usersFile_(usersFile), iters_(argonIters), mem_(argonMem), par_(argonPar) {
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
    if (!content) return;
    std::string err;
    Value v = Value::parseJson(*content, &err);
    if (!err.empty() || !v.isArray()) return;
    for (const auto& u : v.items()) {
        if (!u.isObject()) continue;
        LocalUserRecord r;
        r.username = u.getString("username");
        r.displayName = u.getString("display_name");
        r.email = u.getString("email");
        r.salt = u.getString("salt");
        r.hash = u.getString("hash");
        if (const Value* rr = u.find("roles")) if (rr && rr->isArray()) for (const auto& x : rr->items()) r.roles.push_back(x.asString());
        if (!r.username.empty()) users_.push_back(r);
    }
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
    fs::writeFileAtomic(usersFile_, arr.toJson(2));
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
        auto d = crypto::pbkdf2(password, saltBytes, 100000, hashLen);
        out.assign(reinterpret_cast<const char*>(d.data()), d.size());
    }
    return b64(out);
}

bool LocalAuthProvider::addUser(const LocalUserRecord& rec, const std::string& password) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& u : users_) if (u.username == rec.username) return false;
    LocalUserRecord r = rec;
    std::string salt = crypto::randomBytes(16);
    r.salt = b64(salt);
    // need hash with salt; temporarily set iters via hashPw uses salt param
    r.hash = hashPw(password, r.salt);
    users_.push_back(r);
    save();
    return true;
}

bool LocalAuthProvider::removeUser(const std::string& username) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = std::remove_if(users_.begin(), users_.end(), [&](const LocalUserRecord& u){ return u.username == username; });
    if (it == users_.end()) return false;
    users_.erase(it, users_.end());
    save();
    return true;
}

std::vector<LocalUserRecord> LocalAuthProvider::listUsers() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return users_;
}

AuthResult LocalAuthProvider::authenticate(const std::string& username, const std::string& password) {
    AuthResult res;
    std::lock_guard<std::mutex> lk(mtx_);
    for (const auto& u : users_) {
        if (u.username != username) continue;
        std::string computed = hashPw(password, u.salt);
        if (computed.size() != u.hash.size()) { res.error = "invalid credentials"; return res; }
        bool ok = true;
        for (size_t i = 0; i < computed.size(); ++i) if (computed[i] != u.hash[i]) ok = false;
        if (!ok) { res.error = "invalid credentials"; return res; }
        res.ok = true;
        res.user.id = "local:" + u.username;
        res.user.username = u.username;
        res.user.displayName = u.displayName.empty() ? u.username : u.displayName;
        res.user.email = u.email;
        res.user.provider = "local";
        res.user.roles = u.roles;
        return res;
    }
    res.error = "invalid credentials";
    return res;
}

// ---------------- LDAP ----------------
LdapAuthProvider::LdapAuthProvider(const LdapConfig& cfg) : cfg_(cfg) {}

AuthResult LdapAuthProvider::authenticate(const std::string& username, const std::string& password) {
    AuthResult res;
    if (!cfg_.enabled) { res.error = "ldap disabled"; return res; }
    if (username.empty() || password.empty()) { res.error = "invalid credentials"; return res; }

    LDAP* ld = nullptr;
    int rc = ldap_initialize(&ld, cfg_.url.c_str());
    if (rc != LDAP_SUCCESS || !ld) { res.error = "ldap init failed"; return res; }
    int ver = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ver);

    if (!cfg_.bindDn.empty()) {
        berval cred; cred.bv_val = (char*)cfg_.bindPassword.c_str(); cred.bv_len = cfg_.bindPassword.size();
        rc = ldap_sasl_bind_s(ld, cfg_.bindDn.c_str(), LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, nullptr);
        if (rc != LDAP_SUCCESS) { res.error = "ldap service bind failed"; ldap_unbind_ext_s(ld, nullptr, nullptr); return res; }
    }

    std::string filter = cfg_.userFilter;
    size_t pos = filter.find("%s");
    if (pos != std::string::npos) filter.replace(pos, 2, username);
    char* attrs[] = { (char*)cfg_.attrUid.c_str(), (char*)cfg_.attrMail.c_str(), (char*)cfg_.attrDisplayName.c_str(), nullptr };
    LDAPMessage* msg = nullptr;
    rc = ldap_search_ext_s(ld, cfg_.userSearchBase.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(), attrs, 0, nullptr, nullptr, nullptr, 1, &msg);
    if (rc != LDAP_SUCCESS || !msg) { res.error = "ldap user search failed"; ldap_unbind_ext_s(ld, nullptr, nullptr); return res; }
    LDAPMessage* entry = ldap_first_entry(ld, msg);
    if (!entry) { res.error = "user not found"; ldap_msgfree(msg); ldap_unbind_ext_s(ld, nullptr, nullptr); return res; }
    char* dn = ldap_get_dn(ld, entry);
    std::string userDn = dn ? dn : "";
    if (dn) ldap_memfree(dn);

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
    if (rc != LDAP_SUCCESS) { res.error = "invalid credentials"; ldap_msgfree(msg); ldap_unbind_ext_s(ld, nullptr, nullptr); return res; }

    std::vector<std::string> groups;
    if (!cfg_.groupSearchBase.empty()) {
        std::string gfilter = cfg_.groupFilter;
        size_t p = gfilter.find("%s");
        if (p != std::string::npos) gfilter.replace(p, 2, userDn);
        LDAPMessage* gmsg = nullptr;
        char* gattrs[] = { (char*)"cn", nullptr };
        rc = ldap_search_ext_s(ld, cfg_.groupSearchBase.c_str(), LDAP_SCOPE_SUBTREE, gfilter.c_str(), gattrs, 0, nullptr, nullptr, nullptr, 1000, &gmsg);
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
    if (roles.empty()) roles.push_back("viewer");

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

static std::string curlPost(const std::string& url, const std::string& body, const std::string& bearer = "") {
    CURL* curl = curl_easy_init();
    std::string resp;
    if (!curl) return "";
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
    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}

static std::string curlGet(const std::string& url, const std::string& bearer = "") {
    CURL* curl = curl_easy_init();
    std::string resp;
    if (!curl) return "";
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
    curl_easy_perform(curl);
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return resp;
}

KeycloakAuthProvider::KeycloakAuthProvider(const KeycloakConfig& cfg) : cfg_(cfg) {
    discover();
}

void KeycloakAuthProvider::discover() {
    if (cfg_.issuer.empty()) return;
    std::string base = cfg_.issuer;
    if (!base.empty() && base.back() == '/') base.pop_back();
    tokenEndpoint_ = base + "/protocol/openid-connect/token";
    userinfoEndpoint_ = base + "/protocol/openid-connect/userinfo";
    introspectionEndpoint_ = base + "/protocol/openid-connect/token/introspect";
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
    if (!cfg_.enabled) { res.error = "keycloak disabled"; return res; }
    if (username.empty() || password.empty()) { res.error = "invalid credentials"; return res; }

    std::ostringstream body;
    body << "grant_type=password"
         << "&client_id=" << cfg_.clientId
         << "&username=" << username
         << "&password=" << password;
    if (!cfg_.clientSecret.empty()) body << "&client_secret=" << cfg_.clientSecret;

    std::string resp = curlPost(tokenEndpoint_, body.str());
    std::string err;
    Value v = Value::parseJson(resp, &err);
    if (err.size() || !v.isObject()) { res.error = "keycloak token request failed"; return res; }
    std::string accessToken = v.getString("access_token");
    if (accessToken.empty()) {
        res.error = v.getString("error_description", "invalid credentials");
        return res;
    }

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
    }
    if (sub.empty()) sub = username;
    if (name.empty()) name = username;

    auto roleMap = parseRoleMap();
    std::vector<std::string> roles;
    for (auto& r : kcRoles) {
        auto it = roleMap.find(r);
        if (it != roleMap.end()) roles.push_back(it->second);
    }
    if (roles.empty()) roles.push_back("viewer");
    std::sort(roles.begin(), roles.end());
    roles.erase(std::unique(roles.begin(), roles.end()), roles.end());

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
    if (token.empty() || !cfg_.enabled) return std::nullopt;
    // introspect
    std::ostringstream body;
    body << "token=" << token << "&client_id=" << cfg_.clientId;
    if (!cfg_.clientSecret.empty()) body << "&client_secret=" << cfg_.clientSecret;
    std::string resp = curlPost(introspectionEndpoint_, body.str());
    std::string err;
    Value v = Value::parseJson(resp, &err);
    if (err.size() || !v.isObject()) return std::nullopt;
    if (!(v.find("active") && v.find("active")->asBool(false))) return std::nullopt;
    AuthUser u;
    u.id = "keycloak:" + v.getString("sub");
    u.username = v.getString("preferred_username", v.getString("username"));
    u.provider = "keycloak";
    // roles from token? skip; default viewer
    u.roles = {"viewer"};
    return u;
}

} // namespace s3mm::rest
