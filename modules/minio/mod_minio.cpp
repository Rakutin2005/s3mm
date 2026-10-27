// MinIO vendor module: full account CRUD against the MinIO Admin API v3.
//
// Signing matches madmin-go exactly: AWS SigV4 with service "s3" and an empty
// region (`<date>//s3/aws4_request`) — that is what the official admin client
// sends, and the data plane keeps the cluster's own region.
//
// Endpoints used (relative to /minio/admin/v3):
//   GET    /list-users
//   PUT    /add-user?accessKey=K            body: raw secret key
//   DELETE /remove-user?accessKey=K
//   PUT    /set-user-status?accessKey=K     body: on|off
//   PUT    /add-canned-policy?name=N        body: policy JSON
//   DELETE /remove-canned-policy?name=N
//   GET    /info-canned-policy?name=N
//   PUT    /set-policy?user=K&policy=N
//   DELETE /remove-policy?user=K&policy=N
#include "s3mm/module/module.hpp"
#include "s3mm/module/iam_export.hpp"

#include <algorithm>
#include <random>
#include <set>
#include <cstring>
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::module {
namespace {

constexpr const char* kAdminPrefix = "/minio/admin/v3";
constexpr const char* kGrantPrefix = "s3mm-grant-"; // per-user canned policy

std::string randomSecret() {
    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, (int)sizeof(kAlphabet) - 2);
    std::string out;
    out.reserve(40);
    for (int i = 0; i < 40; ++i) out += kAlphabet[dist(rd)];
    return out;
}

/// Permission list ("READ,WRITE" | "FULL_CONTROL" | raw s3: actions) → actions.
std::vector<std::string> permissionActions(const std::string& perms) {
    static const std::vector<std::string> kRead = {
        "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging",
        "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketLocation"};
    static const std::vector<std::string> kWrite = {
        "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion",
        "s3:AbortMultipartUpload", "s3:PutObjectTagging"};
    std::vector<std::string> out;
    auto add = [&out](const std::vector<std::string>& v) {
        for (const auto& s : v)
            if (std::find(out.begin(), out.end(), s) == out.end()) out.push_back(s);
    };
    for (const auto& raw : str::splitList(perms)) {
        const std::string t = str::trim(raw);
        if (t.empty()) continue;
        if (t == "READ") add(kRead);
        else if (t == "WRITE") add(kWrite);
        else if (t == "READWRITE" || t == "FULL_CONTROL" || t == "*") {
            add(kRead);
            add(kWrite);
        } else if (str::startsWith(t, "s3:")) {
            if (std::find(out.begin(), out.end(), t) == out.end()) out.push_back(t);
        }
    }
    if (out.empty()) add(kRead);
    return out;
}


static std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

static std::string madminEncrypt(const std::string& password, const std::string& data) {
    unsigned char salt[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1) throw std::runtime_error("rand failed");
    unsigned char key[32];
    if (argon2id_hash_raw(1, 64 * 1024, 4, password.data(), password.size(),
                          salt, sizeof(salt), key, sizeof(key)) != ARGON2_OK)
        throw std::runtime_error("argon2 failed");

    unsigned char nonce8[8];
    if (RAND_bytes(nonce8, sizeof(nonce8)) != 1) throw std::runtime_error("rand failed");

    std::string out;
    out.append((const char*)salt, sizeof(salt));
    out.push_back(0x00);
    out.append((const char*)nonce8, sizeof(nonce8));

    // secure-io/sio-go: one AES-GCM seal, final block (associated data 0x80).
    unsigned char iv[12];
    std::memcpy(iv, nonce8, 8);
    iv[8] = 1; iv[9] = iv[10] = iv[11] = 0;

    // Compute the synthetic associated data: 0x80 followed by the AES-GCM tag
    // of an empty plaintext sealed with seq=0 (secure-io EncWriter constructor).
    unsigned char iv0[12];
    std::memcpy(iv0, nonce8, 8);
    iv0[8] = iv0[9] = iv0[10] = iv0[11] = 0;
    unsigned char ad[17];
    ad[0] = 0x80;
    {
        EVP_CIPHER_CTX* c0 = EVP_CIPHER_CTX_new();
        if (!c0) throw std::runtime_error("cipher ctx");
        if (EVP_EncryptInit_ex(c0, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(c0, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
            EVP_EncryptInit_ex(c0, nullptr, nullptr, key, iv0) != 1) {
            EVP_CIPHER_CTX_free(c0); throw std::runtime_error("init0");
        }
        int l = 0;
        if (EVP_EncryptUpdate(c0, nullptr, &l, nullptr, 0) != 1 ||
            EVP_EncryptFinal_ex(c0, nullptr, &l) != 1) {
            EVP_CIPHER_CTX_free(c0); throw std::runtime_error("fin0");
        }
        if (EVP_CIPHER_CTX_ctrl(c0, EVP_CTRL_GCM_GET_TAG, 16, ad + 1) != 1) {
            EVP_CIPHER_CTX_free(c0); throw std::runtime_error("tag0");
        }
        EVP_CIPHER_CTX_free(c0);
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("cipher ctx");
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("init");
    }
    int len = 0;
    if (EVP_EncryptUpdate(ctx, nullptr, &len, ad, 17) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("aad");
    }
    std::string ciphertext;
    ciphertext.resize(data.size());
    if (!data.empty() && EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext.data(), &len,
                                          (const unsigned char*)data.data(), (int)data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("enc");
    }
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data() + len, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("final");
    }
    ciphertext.resize(len + finalLen);
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("tag");
    }
    EVP_CIPHER_CTX_free(ctx);

    out += ciphertext;
    out.append((const char*)tag, sizeof(tag));
    return out;
}


class MinioAdmin : public IAdminProvider {
public:
    MinioAdmin(const s3::ClientOptions& options, const sigv4::Credentials& credentials)
        : client_(options, credentials), credentials_(credentials) {}

    const char* vendorName() const override { return "minio"; }

    FeatureSet features() const override {
        FeatureSet f;
        f.credentials = true;
        f.acl = true;
        f.bucketPolicy = true;
        f.versioning = true;
        f.tagging = true;
        f.inventory = false;
        f.iamPolicy = true;
        f.policyDetach = true;
        f.groups = true;
        return f;
    }

    Result<std::vector<Account>> listAccounts() override {
        // The admin list-users body is encrypted by madmin. export-iam returns a
        // plaintext ZIP with users (including secrets) and policy mappings, so
        // use it as the primary source and keep list-users for older servers.
        http::Response exported = call("GET", "/export-iam");
        std::string exportError;
        if (exported.ok() && exported.body.size() >= 2 && exported.body.compare(0, 2, "PK") == 0) {
            auto accounts = parseIamExport(exported.body, "minio");
            if (accounts) {
                LOG_DEBUG("minio listAccounts: ", accounts.value().size(), " account(s) from export-iam");
                return accounts;
            }
            exportError = accounts.error();
            LOG_WARN(accounts.error());
        } else if (exported.ok()) {
            exportError = "unexpected response (not a ZIP)";
            LOG_WARN("minio export-iam: ", exportError);
        } else {
            exportError = fail("export-iam", exported);
            LOG_WARN(exportError, "; falling back to list-users");
        }

        http::Response r = call("GET", "/list-users");
        if (!r.ok()) {
            std::string err = fail("list-users", r);
            LOG_ERROR(err);
            return Result<std::vector<Account>>::failure(err);
        }
        // madmin encrypts the list-users response body. Recognise the SIO
        // header instead of trying to JSON-parse binary data and returning a
        // misleading "unexpected token at offset 0".
        if (r.body.size() > 32 && (unsigned char)r.body[32] <= 2) {
            LOG_ERROR("minio list-users response is encrypted; a working export-iam endpoint is required (", exportError, ")");
            return Result<std::vector<Account>>::failure(
                "minio list-users response is encrypted; a working export-iam endpoint is required (" +
                exportError + ")");
        }
        std::string err;
        Value root = Value::parseJson(r.body, &err);
        if (!err.empty() || !root.isObject()) {
            LOG_ERROR("minio list-users: unparseable response: ", err, "; body: ", log::clip(r.body, 200));
            return Result<std::vector<Account>>::failure(
                "minio list-users: unparseable response: " + err);
        }
        std::vector<Account> out;
        for (const auto& [key, info] : root.members()) {
            Account a;
            a.accessKey = key;
            a.secretKey = info.getString("secretKey");
            a.hasSecret = !a.secretKey.empty();
            a.status = info.getString("status", "on") == "off" ? "disabled" : "enabled";
            // "policies" arrived as a comma separated string in older MinIO
            // and as a list in newer one: accept both.
            if (const Value* p = info.find("policies")) {
                if (p->isString()) a.policies = str::splitList(p->asString());
                else if (p->isArray())
                    for (const auto& it : p->items()) a.policies.push_back(it.asString());
            }
            if (const Value* g = info.find("groups"); g && g->isArray())
                for (const auto& it : g->items()) a.groups.push_back(it.asString());
            out.push_back(std::move(a));
        }
        LOG_DEBUG("minio listAccounts: ", out.size(), " account(s) from list-users");
        return Result<std::vector<Account>>(std::move(out));
    }

    Result<Account> getAccount(const std::string& accessKey) override {
        auto all = listAccounts();
        if (!all) return Result<Account>::failure(all.error());
        for (auto& a : all.value())
            if (a.accessKey == accessKey) return Result<Account>(std::move(a));
        LOG_DEBUG("minio getAccount: no account '", accessKey, "'");
        return Result<Account>::failure("minio: no account '" + accessKey + "'");
    }

    Result<void> createAccount(const Account& account) override {
        if (account.accessKey.empty()) {
            LOG_ERROR("minio createAccount: empty access key");
            return Result<void>::failure("minio createAccount: empty access key");
        }
        LOG_DEBUG("minio createAccount ", account.accessKey, " status=", account.status, " policies=", account.policies.size(),
                  " buckets=", account.buckets.size(), account.secretKey.empty() ? " (generated secret)" : "");
        std::string secret = account.secretKey.empty() ? randomSecret() : account.secretKey;
        Result<void> res = putUser(account.accessKey, secret, account.status);
        if (!res) return res;
        for (const auto& p : account.policies) {
            LOG_DEBUG("minio createAccount ", account.accessKey, ": set-policy ", p);
            http::Response r =
                call("PUT", "/set-policy", {{"user", account.accessKey}, {"policy", p}});
            if (!r.ok()) {
                std::string err = fail("set-policy", r);
                LOG_ERROR(err);
                return Result<void>::failure(err);
            }
        }
        LOG_INFO("minio: account ", account.accessKey, " created");
        if (!account.buckets.empty()) return setBucketAccess(account.accessKey, account.buckets);
        return Result<void>::success();
    }

    Result<void> setSecret(const std::string& accessKey, const std::string& secretKey) override {
        if (secretKey.empty()) {
            LOG_ERROR("minio setSecret ", accessKey, ": empty secret");
            return Result<void>::failure("minio setSecret: empty secret");
        }
        LOG_INFO("minio: rotating secret of ", accessKey, " (new secret ", log::redact(secretKey), ")");
        // add-user overwrites the secret but may reset the account state:
        // remember the status first and restore it afterwards.
        std::string status = "enabled";
        if (auto cur = getAccount(accessKey)) status = cur.value().status;
        return putUser(accessKey, secretKey, status);
    }

    Result<void> setStatus(const std::string& accessKey, const std::string& status) override {
        LOG_INFO("minio: setStatus ", accessKey, " -> ", status);
        if (status != "enabled" && status != "disabled") {
            LOG_ERROR("minio setStatus: expected enabled|disabled, got '", status, "'");
            return Result<void>::failure("minio setStatus: expected enabled|disabled, got '" +
                                         status + "'");
        }
        return setUserStatus(accessKey, status);
    }

    Result<void> setBucketAccess(const std::string& accessKey,
                                 const std::map<std::string, std::string>& buckets) override {
        LOG_INFO("minio: setBucketAccess ", accessKey, " -> ", buckets.size(), " bucket(s)");
        if (buckets.empty()) return dropGrants(accessKey);
        Value doc = Value::object();
        doc.set("Version", Value::str("2012-10-17"));
        Value stmts = Value::array();
        for (const auto& [bucket, perms] : buckets)
            stmts.push(bucketStatement(bucket, perms));
        doc.set("Statement", stmts);
        return putGrants(accessKey, doc);
    }

    Result<void> addBucketAccess(const std::string& accessKey, const std::string& bucket,
                                 const std::string& permissions) override {
        LOG_INFO("minio: addBucketAccess ", accessKey, " bucket=", bucket, " permissions=", permissions);
        Value doc = readGrants(accessKey);
        if (!doc.isObject()) doc = emptyPolicy();
        setStatement(doc, bucket, &permissions);
        return putGrants(accessKey, doc);
    }

    Result<void> removeBucketAccess(const std::string& accessKey,
                                    const std::string& bucket) override {
        LOG_INFO("minio: removeBucketAccess ", accessKey, " bucket=", bucket);
        Value doc = readGrants(accessKey);
        if (!doc.isObject()) {
            LOG_DEBUG("minio removeBucketAccess ", accessKey, ": no grant policy, nothing to remove");
            return Result<void>::success(); // nothing to remove
        }
        setStatement(doc, bucket, nullptr);
        const Value* stmts = doc.find("Statement");
        if (!stmts || stmts->items().empty()) return dropGrants(accessKey);
        return putGrants(accessKey, doc);
    }

    Result<void> attachPolicy(const std::string& accessKey,
                              const std::string& policyName) override {
        Value body = Value::object();
        Value arr = Value::array();
        arr.push(Value::str(policyName));
        body.set("policies", std::move(arr));
        body.set("user", Value::str(accessKey));
        LOG_INFO("minio: attach policy ", policyName, " to ", accessKey);
        http::Response r = call("POST", "/idp/builtin/policy/attach", {}, body.toJson(0));
        if (!r.ok()) {
            std::string err = fail("attach-policy", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        return Result<void>::success();
    }

    Result<void> detachPolicy(const std::string& accessKey,
                              const std::string& policyName) override {
        Value body = Value::object();
        Value arr = Value::array();
        arr.push(Value::str(policyName));
        body.set("policies", std::move(arr));
        body.set("user", Value::str(accessKey));
        LOG_INFO("minio: detach policy ", policyName, " from ", accessKey);
        http::Response r = call("POST", "/idp/builtin/policy/detach", {}, body.toJson(0));
        if (!r.ok() && r.status != 404) {
            std::string err = fail("detach-policy", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        return Result<void>::success();
    }

    Result<void> setGroups(const std::string& accessKey, const std::vector<std::string>& desired,
                           const std::vector<std::string>& current) override {
        std::set<std::string> want(desired.begin(), desired.end());
        std::set<std::string> have(current.begin(), current.end());
        LOG_DEBUG("minio setGroups ", accessKey, ": desired=", desired.size(), " current=", current.size());
        for (const auto& group : have) {
            if (want.count(group)) continue;
            auto res = updateGroup(group, accessKey, true);
            if (!res) return res;
        }
        for (const auto& group : want) {
            if (have.count(group)) continue;
            auto res = updateGroup(group, accessKey, false);
            if (!res) return res;
        }
        return Result<void>::success();
    }

    Result<void> deleteAccount(const std::string& accessKey) override {
        LOG_INFO("minio: deleting account ", accessKey);
        http::Response r = call("DELETE", "/remove-user", {{"accessKey", accessKey}});
        if (!r.ok()) {
            std::string err = fail("remove-user", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        dropGrants(accessKey); // best effort: the grant policy is orphaned otherwise
        LOG_INFO("minio: account ", accessKey, " deleted");
        return Result<void>::success();
    }

private:
    http::Response call(const std::string& method, const std::string& path,
                        const std::map<std::string, std::string>& query = {},
                        const std::string& body = {},
                        const std::map<std::string, std::string>& headers = {}) {
        http::Request req;
        req.method = method;
        req.url = client_.primaryEndpoint() + std::string(kAdminPrefix) + path;
        req.query = query;
        req.body = body;
        req.headers = headers;
        req.timeoutSec = client_.options().timeoutSec;
        req.connectTimeoutSec = client_.options().connectTimeoutSec;
        std::string q;
        for (const auto& [k, v] : query) q += (q.empty() ? "?" : "&") + k + "=" + v;
        LOG_DEBUG("minio admin: ", method, " ", path, q, " body=", body.size(), "B");
        log::Stopwatch sw;
        http::Response r = client_.raw(req);
        LOG_DEBUG("minio admin: ", method, " ", path, " -> ", r.ok() ? std::to_string(r.status) : r.errorText(), " ",
                  r.body.size(), "B in ", sw.ms(), " ms");
        return r;
    }

    static std::string fail(const char* op, const http::Response& r) {
        std::string msg = std::string("minio ") + op + ": HTTP " + std::to_string(r.status);
        if (!r.curlError.empty()) msg += " (" + r.curlError + ")";
        if (!r.body.empty()) {
            msg += ": ";
            msg += r.body.substr(0, 512);
        }
        return msg;
    }

    Result<void> updateGroup(const std::string& group, const std::string& accessKey, bool remove) {
        LOG_INFO("minio: ", remove ? "removing " : "adding ", accessKey, remove ? " from group " : " to group ", group);
        Value body = Value::object();
        body.set("group", Value::str(group));
        Value members = Value::array();
        members.push(Value::str(accessKey));
        body.set("members", std::move(members));
        body.set("groupStatus", Value::str("enabled"));
        body.set("isRemove", Value::boolean(remove));
        http::Response r = call("PUT", "/update-group-members", {}, body.toJson());
        if (!r.ok()) {
            std::string err = fail("update-group-members", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        return Result<void>::success();
    }

    Result<void> putUser(const std::string& accessKey, const std::string& secret,
                         const std::string& status) {
        std::string json = std::string("{\"secretKey\":\"") + jsonEscape(secret) +
                          std::string("\",\"status\":\"") +
                          (status == "disabled" ? std::string("disabled") : std::string("enabled")) +
                          std::string("\"}");
        std::string body;
        try { body = madminEncrypt(credentials_.secretKey, json); }
        catch (const std::exception& e) {
            LOG_ERROR("minio add-user ", accessKey, ": cannot encrypt request body: ", e.what());
            return Result<void>::failure(std::string("minio add-user: ") + e.what());
        }
        http::Response r = call("PUT", "/add-user", {{"accessKey", accessKey}}, body,
                                {{"Content-Type", "application/octet-stream"}});
        if (!r.ok()) {
            std::string err = fail("add-user", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        return setUserStatus(accessKey, status.empty() ? "enabled" : status);
    }

    Result<void> setUserStatus(const std::string& accessKey, const std::string& status) {
        const std::string st = status == "disabled" || status == "off" ? "disabled" : "enabled";
        http::Response r = call("PUT", "/set-user-status", {{"accessKey", accessKey}, {"status", st}}, "");
        if (!r.ok()) {
            std::string err = fail("set-user-status", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        return Result<void>::success();
    }

    static Value emptyPolicy() {
        Value doc = Value::object();
        doc.set("Version", Value::str("2012-10-17"));
        doc.set("Statement", Value::array());
        return doc;
    }

    static Value bucketStatement(const std::string& bucket, const std::string& perms) {
        Value st = Value::object();
        st.set("Sid", Value::str("s3mm:" + bucket));
        st.set("Effect", Value::str("Allow"));
        Value actions = Value::array();
        for (const auto& a : permissionActions(perms)) actions.push(Value::str(a));
        st.set("Action", actions);
        Value res = Value::array();
        res.push(Value::str("arn:aws:s3:::" + bucket));
        res.push(Value::str("arn:aws:s3:::" + bucket + "/*"));
        st.set("Resource", res);
        return st;
    }

    /// Insert/replace (permissions != nullptr) or drop (nullptr) the statement
    /// whose Sid is "s3mm:<bucket>".
    static void setStatement(Value& doc, const std::string& bucket,
                             const std::string* permissions) {
        const std::string sid = "s3mm:" + bucket;
        Value merged = Value::array();
        bool replaced = false;
        if (const Value* stmts = doc.find("Statement"); stmts && stmts->isArray()) {
            for (const auto& item : stmts->items()) {
                if (item.isObject() && item.getString("Sid") == sid) {
                    replaced = true;
                    if (permissions) merged.push(bucketStatement(bucket, *permissions));
                } else {
                    merged.push(item);
                }
            }
        }
        if (permissions && !replaced) merged.push(bucketStatement(bucket, *permissions));
        doc.set("Statement", merged);
    }

    Value readGrants(const std::string& accessKey) {
        http::Response r =
            call("GET", "/info-canned-policy", {{"name", std::string(kGrantPrefix) + accessKey}});
        if (!r.ok()) {
            if (r.status != 404)
                LOG_WARN("minio info-canned-policy: HTTP ", r.status, " for ", accessKey);
            return Value::null();
        }
        std::string err;
        Value v = Value::parseJson(r.body, &err);
        if (!err.empty()) {
            LOG_WARN("minio info-canned-policy: unparseable policy of ", accessKey, ": ", err);
            return Value::null();
        }
        return v;
    }

    Result<void> putGrants(const std::string& accessKey, const Value& doc) {
        const std::string name = std::string(kGrantPrefix) + accessKey;
        LOG_DEBUG("minio putGrants ", accessKey, ": policy ", name);
        http::Response r = call("PUT", "/add-canned-policy", {{"name", name}}, doc.toJson(0));
        if (!r.ok()) {
            std::string err = fail("add-canned-policy", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        http::Response r2 = call("PUT", "/set-policy", {{"user", accessKey}, {"policy", name}});
        if (!r2.ok()) {
            std::string err = fail("set-policy", r2);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        return Result<void>::success();
    }

    Result<void> dropGrants(const std::string& accessKey) {
        const std::string name = std::string(kGrantPrefix) + accessKey;
        LOG_DEBUG("minio dropGrants ", accessKey, ": policy ", name);
        http::Response r = call("DELETE", "/remove-policy", {{"user", accessKey}, {"policy", name}});
        if (!r.ok() && r.status != 404)
            LOG_WARN("minio remove-policy: HTTP ", r.status, " for ", accessKey);
        http::Response r2 = call("DELETE", "/remove-canned-policy", {{"name", name}});
        if (!r2.ok() && r2.status != 404)
            LOG_WARN("minio remove-canned-policy: HTTP ", r2.status, " for ", accessKey);
        return Result<void>::success();
    }

    s3::Client client_;
    sigv4::Credentials credentials_;
};

class MinioModule : public IModule {
public:
    ModuleInfo info() const override { return {"minio", S3MM_VERSION, "minio"}; }

    Result<std::unique_ptr<IAdminProvider>> createAdmin(
        const s3::ClientOptions& options, const sigv4::Credentials& credentials) override {
        try {
            s3::ClientOptions opts = options;
            opts.service = "s3";      // the admin plane signs as "s3" (madmin-go)
            sigv4::Credentials creds = credentials;
            creds.region.clear();     // madmin-go signs admin calls with an empty region
            LOG_INFO("minio: admin provider created for ", opts.endpoints.empty() ? std::string("<no endpoint>") : opts.endpoints.front(),
                     " (access_key=", creds.accessKey, ")");
            return Result<std::unique_ptr<IAdminProvider>>(
                std::make_unique<MinioAdmin>(opts, creds));
        } catch (const std::exception& e) {
            LOG_ERROR("minio: cannot create admin provider: ", e.what());
            return Result<std::unique_ptr<IAdminProvider>>::failure(
                std::string("minio: ") + e.what());
        }
    }

    void adjustClientOptions(s3::ClientOptions& opts) override {
        opts.service = "s3";
        LOG_DEBUG("minio: client options adjusted: service=", opts.service);
    }
};

} // namespace

S3MM_MODULE_ENTRY(MinioModule)

} // namespace s3mm::module
