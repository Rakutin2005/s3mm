// RustFS vendor module: account CRUD against the RustFS Admin API v3.
//
// Endpoints live under /rustfs/admin/v3 and are signed with AWS SigV4
// (service "s3"), like the MinIO admin plane. See:
//   https://docs.rustfs.com/en/security-compliance/iam/policies
//
//   GET    /list-users
//   PUT    /add-user?accessKey=K            body: {"secretKey":..., "status":...}
//   DELETE /remove-user?accessKey=K
//   PUT    /set-user-status?accessKey=K&status=enabled|disabled
//   GET    /info-canned-policy?name=N
//   PUT    /add-canned-policy?name=N        body: policy JSON
//   DELETE /remove-canned-policy?name=N
//   PUT    /set-user-or-group-policy?policyName=P&userOrGroup=K&isGroup=false
//   POST   /idp/builtin/policy/attach      body: {"policies":[...], "user": K}
//   POST   /idp/builtin/policy/detach      body: {"policies":[...], "user": K}
#include "s3mm/module/module.hpp"

#include <algorithm>
#include <random>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::module {
namespace {

constexpr const char* kAdminPrefix = "/rustfs/admin/v3";
constexpr const char* kGrantPrefix = "s3mm-grant-";

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

Account parseAccount(const Value& info, const std::string& keyHint) {
    Account a;
    a.accessKey = info.getString("accessKey", "");
    if (a.accessKey.empty()) a.accessKey = info.getString("access_key", "");
    if (a.accessKey.empty()) a.accessKey = info.getString("name", "");
    if (a.accessKey.empty()) a.accessKey = info.getString("access_key_id", "");
    if (a.accessKey.empty()) a.accessKey = keyHint;

    a.secretKey = info.getString("secretKey", "");
    if (a.secretKey.empty()) a.secretKey = info.getString("secret_key", "");
    a.hasSecret = !a.secretKey.empty();

    std::string st = info.getString("status", "enabled");
    a.status = (st == "disabled" || st == "off" || st == "false") ? "disabled" : "enabled";

    if (const Value* p = info.find("policies")) {
        if (p->isString()) a.policies = str::splitList(p->asString());
        else if (p->isArray())
            for (const auto& it : p->items()) a.policies.push_back(it.asString());
    }
    if (a.policies.empty()) {
        for (const char* f : {"policyName", "policy", "policy_name"}) {
            std::string pn = info.getString(f, "");
            if (!pn.empty()) { a.policies.push_back(pn); break; }
        }
    }
    if (const Value* g = info.find("groups"); g && g->isArray())
        for (const auto& it : g->items()) a.groups.push_back(it.asString());

    return a;
}

class RustfsAdmin : public IAdminProvider {
public:
    RustfsAdmin(const s3::ClientOptions& options, const sigv4::Credentials& credentials)
        : client_(options, credentials) {}

    const char* vendorName() const override { return "rustfs"; }

    FeatureSet features() const override {
        FeatureSet f;
        f.credentials = true;
        f.acl = true;
        f.bucketPolicy = true;
        f.versioning = true;
        f.tagging = true;
        f.inventory = false;
        f.iamPolicy = true;
        return f;
    }

    Result<std::vector<Account>> listAccounts() override {
        http::Response r = call("GET", "/list-users");
        if (!r.ok()) return Result<std::vector<Account>>::failure(fail("list-users", r));
        std::string err;
        Value root = Value::parseJson(r.body, &err);
        if (!err.empty())
            return Result<std::vector<Account>>::failure(
                "rustfs list-users: unparseable response: " + err);
        std::vector<Account> out;
        if (root.isObject()) {
            bool consumed = false;
            for (const auto& [key, info] : root.members()) {
                if (info.isObject() &&
                    (info.find("accessKey") || info.find("access_key") || info.find("secretKey") ||
                     info.find("secret_key") || info.find("status") || info.find("policies") ||
                     info.find("policy") || info.find("policyName"))) {
                    out.push_back(parseAccount(info, key));
                    consumed = true;
                }
            }
            if (consumed) return Result<std::vector<Account>>(std::move(out));
            for (const char* field : {"accounts", "users", "data", "items", "result"}) {
                if (const Value* arr = root.find(field); arr && arr->isArray()) {
                    for (const auto& it : arr->items())
                        if (it.isObject()) out.push_back(parseAccount(it, ""));
                    return Result<std::vector<Account>>(std::move(out));
                }
            }
            // empty result (e.g. `{}`) is valid: no users
            return Result<std::vector<Account>>(std::move(out));
        }
        if (root.isArray()) {
            for (const auto& it : root.items())
                if (it.isObject()) out.push_back(parseAccount(it, ""));
            return Result<std::vector<Account>>(std::move(out));
        }
        return Result<std::vector<Account>>::failure(
            "rustfs list-users: unexpected response shape");
    }

    Result<Account> getAccount(const std::string& accessKey) override {
        auto all = listAccounts();
        if (!all) return Result<Account>::failure(all.error());
        for (auto& a : all.value())
            if (a.accessKey == accessKey) return Result<Account>(std::move(a));
        return Result<Account>::failure("rustfs: no account '" + accessKey + "'");
    }

    Result<void> createAccount(const Account& account) override {
        if (account.accessKey.empty())
            return Result<void>::failure("rustfs createAccount: empty access key");
        std::string secret = account.secretKey.empty() ? randomSecret() : account.secretKey;
        Result<void> res = putUser(account.accessKey, secret, account.status);
        if (!res) return res;
        if (!account.policies.empty()) {
            Value body = Value::object();
            Value arr = Value::array();
            for (const auto& p : account.policies) arr.push(Value::str(p));
            body.set("policies", arr);
            body.set("user", Value::str(account.accessKey));
            http::Response r = call("POST", "/idp/builtin/policy/attach", {}, body.toJson(0));
            if (!r.ok()) return Result<void>::failure(fail("attach", r));
        }
        if (!account.buckets.empty()) return setBucketAccess(account.accessKey, account.buckets);
        return Result<void>::success();
    }

    Result<void> setSecret(const std::string& accessKey, const std::string& secretKey) override {
        if (secretKey.empty()) return Result<void>::failure("rustfs setSecret: empty secret");
        std::string status = "enabled";
        std::vector<std::string> policies;
        if (auto cur = getAccount(accessKey)) {
            status = cur.value().status;
            policies = cur.value().policies;
        }
        Result<void> res = putUser(accessKey, secretKey, status);
        if (!res) return res;
        // re-attach policies: putUser may have replaced the binding
        if (!policies.empty()) {
            Value body = Value::object();
            Value arr = Value::array();
            for (const auto& p : policies) arr.push(Value::str(p));
            body.set("policies", arr);
            body.set("user", Value::str(accessKey));
            http::Response r = call("POST", "/idp/builtin/policy/attach", {}, body.toJson(0));
            if (!r.ok()) return Result<void>::failure(fail("attach", r));
        }
        return Result<void>::success();
    }

    Result<void> setStatus(const std::string& accessKey, const std::string& status) override {
        if (status != "enabled" && status != "disabled")
            return Result<void>::failure("rustfs setStatus: expected enabled|disabled, got '" + status + "'");
        const std::string st = status == "disabled" ? "disabled" : "enabled";
        http::Response r = call("PUT", "/set-user-status", {{"accessKey", accessKey}, {"status", st}});
        if (!r.ok()) return Result<void>::failure(fail("set-user-status", r));
        return Result<void>::success();
    }

    Result<void> setBucketAccess(const std::string& accessKey,
                                  const std::map<std::string, std::string>& buckets) override {
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
        Value doc = readGrants(accessKey);
        if (!doc.isObject()) doc = emptyPolicy();
        setStatement(doc, bucket, &permissions);
        return putGrants(accessKey, doc);
    }

    Result<void> removeBucketAccess(const std::string& accessKey,
                                    const std::string& bucket) override {
        Value doc = readGrants(accessKey);
        if (!doc.isObject()) return Result<void>::success();
        setStatement(doc, bucket, nullptr);
        const Value* stmts = doc.find("Statement");
        if (!stmts || stmts->items().empty()) return dropGrants(accessKey);
        return putGrants(accessKey, doc);
    }

    Result<void> attachPolicy(const std::string& accessKey,
                              const std::string& policyName) override {
        http::Response r = call("PUT", "/set-user-or-group-policy",
                                {{"policyName", policyName}, {"userOrGroup", accessKey}, {"isGroup", "false"}});
        if (!r.ok()) return Result<void>::failure(fail("set-user-or-group-policy", r));
        return Result<void>::success();
    }

    Result<void> deleteAccount(const std::string& accessKey) override {
        http::Response r = call("DELETE", "/remove-user", {{"accessKey", accessKey}});
        if (!r.ok()) return Result<void>::failure(fail("remove-user", r));
        dropGrants(accessKey);
        return Result<void>::success();
    }

private:
    http::Response call(const std::string& method, const std::string& path,
                        const std::map<std::string, std::string>& query = {},
                        const std::string& body = {}) {
        http::Request req;
        req.method = method;
        req.url = client_.primaryEndpoint() + std::string(kAdminPrefix) + path;
        req.query = query;
        req.body = body;
        req.timeoutSec = client_.options().timeoutSec;
        req.connectTimeoutSec = client_.options().connectTimeoutSec;
        return client_.raw(req);
    }

    static std::string fail(const char* op, const http::Response& r) {
        std::string msg = std::string("rustfs ") + op + ": HTTP " + std::to_string(r.status);
        if (!r.curlError.empty()) msg += " (" + r.curlError + ")";
        if (!r.body.empty()) {
            msg += ": ";
            msg += r.body.substr(0, 512);
        }
        return msg;
    }

    Result<void> putUser(const std::string& accessKey, const std::string& secret,
                         const std::string& status) {
        Value body = Value::object();
        body.set("secretKey", Value::str(secret));
        body.set("status", Value::str(status == "disabled" ? "disabled" : "enabled"));
        http::Response r = call("PUT", "/add-user", {{"accessKey", accessKey}}, body.toJson(0));
        if (!r.ok()) return Result<void>::failure(fail("add-user", r));
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
                LOG_WARN("rustfs info-canned-policy: HTTP ", r.status, " for ", accessKey);
            return Value::null();
        }
        std::string err;
        Value v = Value::parseJson(r.body, &err);
        if (!err.empty()) {
            LOG_WARN("rustfs info-canned-policy: unparseable policy of ", accessKey);
            return Value::null();
        }
        // RustFS wraps the document: {"policy_name":..., "policy":{...}, ...}
        if (const Value* p = v.find("policy"); p && p->isObject()) return *p;
        return v;
    }

    Result<void> putGrants(const std::string& accessKey, const Value& doc) {
        const std::string name = std::string(kGrantPrefix) + accessKey;
        http::Response r = call("PUT", "/add-canned-policy", {{"name", name}}, doc.toJson(0));
        if (!r.ok()) return Result<void>::failure(fail("add-canned-policy", r));
        // attach the grant policy to the user
        Value body = Value::object();
        Value arr = Value::array();
        arr.push(Value::str(name));
        body.set("policies", arr);
        body.set("user", Value::str(accessKey));
        http::Response r2 = call("POST", "/idp/builtin/policy/attach", {}, body.toJson(0));
        if (!r2.ok()) return Result<void>::failure(fail("attach", r2));
        return Result<void>::success();
    }

    Result<void> dropGrants(const std::string& accessKey) {
        const std::string name = std::string(kGrantPrefix) + accessKey;
        Value body = Value::object();
        Value arr = Value::array();
        arr.push(Value::str(name));
        body.set("policies", arr);
        body.set("user", Value::str(accessKey));
        http::Response r = call("POST", "/idp/builtin/policy/detach", {}, body.toJson(0));
        if (!r.ok() && r.status != 404)
            LOG_WARN("rustfs detach: HTTP ", r.status, " for ", accessKey);
        http::Response r2 = call("DELETE", "/remove-canned-policy", {{"name", name}});
        if (!r2.ok() && r2.status != 404)
            LOG_WARN("rustfs remove-canned-policy: HTTP ", r2.status, " for ", accessKey);
        return Result<void>::success();
    }

    s3::Client client_;
};

class RustfsModule : public IModule {
public:
    ModuleInfo info() const override { return {"rustfs", S3MM_VERSION, "rustfs"}; }

    Result<std::unique_ptr<IAdminProvider>> createAdmin(
        const s3::ClientOptions& options, const sigv4::Credentials& credentials) override {
        try {
            s3::ClientOptions opts = options;
            opts.service = "s3";
            return Result<std::unique_ptr<IAdminProvider>>(
                std::make_unique<RustfsAdmin>(opts, credentials));
        } catch (const std::exception& e) {
            return Result<std::unique_ptr<IAdminProvider>>::failure(
                std::string("rustfs: ") + e.what());
        }
    }

    void adjustClientOptions(s3::ClientOptions& opts) override {
        opts.service = "s3";
        opts.pathStyle = true;
    }
};

} // namespace

S3MM_MODULE_ENTRY(RustfsModule)

} // namespace s3mm::module
