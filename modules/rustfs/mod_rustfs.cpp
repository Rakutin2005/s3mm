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
#include "s3mm/module/iam_export.hpp"

#include <algorithm>
#include <random>
#include <set>

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
        f.policyDetach = true;
        f.groups = true;
        return f;
    }

    Result<std::vector<Account>> listAccounts() override {
        // export-iam is the only RustFS endpoint that exposes the secret keys;
        // list-users returns metadata only, which made account sync invent
        // random secrets on the destination.
        http::Response exported = call("GET", "/export-iam");
        if (exported.ok() && exported.body.size() >= 2 && exported.body.compare(0, 2, "PK") == 0) {
            auto accounts = parseIamExport(exported.body, "rustfs");
            if (accounts) {
                LOG_DEBUG("rustfs listAccounts: ", accounts.value().size(), " account(s) from export-iam");
                return accounts;
            }
            LOG_WARN(accounts.error());
        } else if (exported.ok()) {
            LOG_WARN("rustfs export-iam: unexpected response (not a ZIP)");
        } else {
            LOG_WARN(fail("export-iam", exported), "; falling back to list-users (no secrets)");
        }

        http::Response r = call("GET", "/list-users");
        if (!r.ok()) {
            std::string err = fail("list-users", r);
            LOG_ERROR(err);
            return Result<std::vector<Account>>::failure(err);
        }
        std::string err;
        Value root = Value::parseJson(r.body, &err);
        if (!err.empty()) {
            LOG_ERROR("rustfs list-users: unparseable response: ", err, "; body: ", log::clip(r.body, 200));
            return Result<std::vector<Account>>::failure(
                "rustfs list-users: unparseable response: " + err);
        }
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
            if (consumed) {
                LOG_DEBUG("rustfs listAccounts: ", out.size(), " account(s) from list-users (keyed map)");
                return Result<std::vector<Account>>(std::move(out));
            }
            for (const char* field : {"accounts", "users", "data", "items", "result"}) {
                if (const Value* arr = root.find(field); arr && arr->isArray()) {
                    for (const auto& it : arr->items())
                        if (it.isObject()) out.push_back(parseAccount(it, ""));
                    LOG_DEBUG("rustfs listAccounts: ", out.size(), " account(s) from list-users field '", field, "'");
                    return Result<std::vector<Account>>(std::move(out));
                }
            }
            // empty result (e.g. `{}`) is valid: no users
            LOG_DEBUG("rustfs listAccounts: no users");
            return Result<std::vector<Account>>(std::move(out));
        }
        if (root.isArray()) {
            for (const auto& it : root.items())
                if (it.isObject()) out.push_back(parseAccount(it, ""));
            LOG_DEBUG("rustfs listAccounts: ", out.size(), " account(s) from list-users (array)");
            return Result<std::vector<Account>>(std::move(out));
        }
        LOG_ERROR("rustfs list-users: unexpected response shape: ", log::clip(r.body, 200));
        return Result<std::vector<Account>>::failure(
            "rustfs list-users: unexpected response shape");
    }

    Result<Account> getAccount(const std::string& accessKey) override {
        auto all = listAccounts();
        if (!all) return Result<Account>::failure(all.error());
        for (auto& a : all.value())
            if (a.accessKey == accessKey) return Result<Account>(std::move(a));
        LOG_DEBUG("rustfs getAccount: no account '", accessKey, "'");
        return Result<Account>::failure("rustfs: no account '" + accessKey + "'");
    }

    Result<void> createAccount(const Account& account) override {
        if (account.accessKey.empty()) {
            LOG_ERROR("rustfs createAccount: empty access key");
            return Result<void>::failure("rustfs createAccount: empty access key");
        }
        LOG_DEBUG("rustfs createAccount ", account.accessKey, " status=", account.status, " policies=", account.policies.size(),
                  " buckets=", account.buckets.size(), account.secretKey.empty() ? " (generated secret)" : "");
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
            if (!r.ok()) {
                std::string err = fail("attach", r);
                LOG_ERROR(err);
                return Result<void>::failure(err);
            }
        }
        LOG_INFO("rustfs: account ", account.accessKey, " created");
        if (!account.buckets.empty()) return setBucketAccess(account.accessKey, account.buckets);
        return Result<void>::success();
    }

    Result<void> setSecret(const std::string& accessKey, const std::string& secretKey) override {
        if (secretKey.empty()) {
            LOG_ERROR("rustfs setSecret ", accessKey, ": empty secret");
            return Result<void>::failure("rustfs setSecret: empty secret");
        }
        LOG_INFO("rustfs: rotating secret of ", accessKey, " (new secret ", log::redact(secretKey), ")");
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
            LOG_DEBUG("rustfs setSecret ", accessKey, ": re-attaching ", policies.size(), " policy(ies)");
            Value body = Value::object();
            Value arr = Value::array();
            for (const auto& p : policies) arr.push(Value::str(p));
            body.set("policies", arr);
            body.set("user", Value::str(accessKey));
            http::Response r = call("POST", "/idp/builtin/policy/attach", {}, body.toJson(0));
            if (!r.ok()) {
                std::string err = fail("attach", r);
                LOG_ERROR(err);
                return Result<void>::failure(err);
            }
        }
        return Result<void>::success();
    }

    Result<void> setStatus(const std::string& accessKey, const std::string& status) override {
        LOG_INFO("rustfs: setStatus ", accessKey, " -> ", status);
        if (status != "enabled" && status != "disabled") {
            LOG_ERROR("rustfs setStatus: expected enabled|disabled, got '", status, "'");
            return Result<void>::failure("rustfs setStatus: expected enabled|disabled, got '" + status + "'");
        }
        const std::string st = status == "disabled" ? "disabled" : "enabled";
        http::Response r = call("PUT", "/set-user-status", {{"accessKey", accessKey}, {"status", st}});
        if (!r.ok()) {
            std::string err = fail("set-user-status", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        return Result<void>::success();
    }

    Result<void> setBucketAccess(const std::string& accessKey,
                                  const std::map<std::string, std::string>& buckets) override {
        LOG_INFO("rustfs: setBucketAccess ", accessKey, " -> ", buckets.size(), " bucket(s)");
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
        LOG_INFO("rustfs: addBucketAccess ", accessKey, " bucket=", bucket, " permissions=", permissions);
        Value doc = readGrants(accessKey);
        if (!doc.isObject()) doc = emptyPolicy();
        setStatement(doc, bucket, &permissions);
        return putGrants(accessKey, doc);
    }

    Result<void> removeBucketAccess(const std::string& accessKey,
                                    const std::string& bucket) override {
        LOG_INFO("rustfs: removeBucketAccess ", accessKey, " bucket=", bucket);
        Value doc = readGrants(accessKey);
        if (!doc.isObject()) {
            LOG_DEBUG("rustfs removeBucketAccess ", accessKey, ": no grant policy, nothing to remove");
            return Result<void>::success();
        }
        setStatement(doc, bucket, nullptr);
        const Value* stmts = doc.find("Statement");
        if (!stmts || stmts->items().empty()) return dropGrants(accessKey);
        return putGrants(accessKey, doc);
    }

    Result<void> attachPolicy(const std::string& accessKey,
                              const std::string& policyName) override {
        LOG_INFO("rustfs: attach policy ", policyName, " to ", accessKey);
        http::Response r = call("PUT", "/set-user-or-group-policy",
                                {{"policyName", policyName}, {"userOrGroup", accessKey}, {"isGroup", "false"}});
        if (!r.ok()) {
            std::string err = fail("set-user-or-group-policy", r);
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
        LOG_INFO("rustfs: detach policy ", policyName, " from ", accessKey);
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
        LOG_DEBUG("rustfs setGroups ", accessKey, ": desired=", desired.size(), " current=", current.size());
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
        LOG_INFO("rustfs: deleting account ", accessKey);
        http::Response r = call("DELETE", "/remove-user", {{"accessKey", accessKey}});
        if (!r.ok()) {
            std::string err = fail("remove-user", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        dropGrants(accessKey);
        LOG_INFO("rustfs: account ", accessKey, " deleted");
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
        std::string q;
        for (const auto& [k, v] : query) q += (q.empty() ? "?" : "&") + k + "=" + v;
        LOG_DEBUG("rustfs admin: ", method, " ", path, q, " body=", body.size(), "B");
        log::Stopwatch sw;
        http::Response r = client_.raw(req);
        LOG_DEBUG("rustfs admin: ", method, " ", path, " -> ", r.ok() ? std::to_string(r.status) : r.errorText(), " ",
                  r.body.size(), "B in ", sw.ms(), " ms");
        return r;
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

    Result<void> updateGroup(const std::string& group, const std::string& accessKey, bool remove) {
        LOG_INFO("rustfs: ", remove ? "removing " : "adding ", accessKey, remove ? " from group " : " to group ", group);
        Value body = Value::object();
        body.set("group", Value::str(group));
        Value members = Value::array();
        members.push(Value::str(accessKey));
        body.set("members", std::move(members));
        body.set("groupStatus", Value::str("enabled"));
        body.set("isRemove", Value::boolean(remove));
        http::Response r = call("PUT", "/update-group-members", {}, body.toJson(0));
        if (!r.ok()) {
            std::string err = fail("update-group-members", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        return Result<void>::success();
    }

    Result<void> putUser(const std::string& accessKey, const std::string& secret,
                         const std::string& status) {
        Value body = Value::object();
        body.set("secretKey", Value::str(secret));
        body.set("status", Value::str(status == "disabled" ? "disabled" : "enabled"));
        http::Response r = call("PUT", "/add-user", {{"accessKey", accessKey}}, body.toJson(0));
        if (!r.ok()) {
            std::string err = fail("add-user", r);
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
            LOG_WARN("rustfs info-canned-policy: unparseable policy of ", accessKey, ": ", err);
            return Value::null();
        }
        // RustFS wraps the document: {"policy_name":..., "policy":{...}, ...}
        if (const Value* p = v.find("policy"); p && p->isObject()) return *p;
        return v;
    }

    Result<void> putGrants(const std::string& accessKey, const Value& doc) {
        const std::string name = std::string(kGrantPrefix) + accessKey;
        LOG_DEBUG("rustfs putGrants ", accessKey, ": policy ", name);
        http::Response r = call("PUT", "/add-canned-policy", {{"name", name}}, doc.toJson(0));
        if (!r.ok()) {
            std::string err = fail("add-canned-policy", r);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        // attach the grant policy to the user
        Value body = Value::object();
        Value arr = Value::array();
        arr.push(Value::str(name));
        body.set("policies", arr);
        body.set("user", Value::str(accessKey));
        http::Response r2 = call("POST", "/idp/builtin/policy/attach", {}, body.toJson(0));
        if (!r2.ok()) {
            std::string err = fail("attach", r2);
            LOG_ERROR(err);
            return Result<void>::failure(err);
        }
        return Result<void>::success();
    }

    Result<void> dropGrants(const std::string& accessKey) {
        const std::string name = std::string(kGrantPrefix) + accessKey;
        LOG_DEBUG("rustfs dropGrants ", accessKey, ": policy ", name);
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
            LOG_INFO("rustfs: admin provider created for ", opts.endpoints.empty() ? std::string("<no endpoint>") : opts.endpoints.front(),
                     " (access_key=", credentials.accessKey, ")");
            return Result<std::unique_ptr<IAdminProvider>>(
                std::make_unique<RustfsAdmin>(opts, credentials));
        } catch (const std::exception& e) {
            LOG_ERROR("rustfs: cannot create admin provider: ", e.what());
            return Result<std::unique_ptr<IAdminProvider>>::failure(
                std::string("rustfs: ") + e.what());
        }
    }

    void adjustClientOptions(s3::ClientOptions& opts) override {
        opts.service = "s3";
        opts.pathStyle = true;
        LOG_DEBUG("rustfs: client options adjusted: service=", opts.service, " path_style=", opts.pathStyle);
    }
};

} // namespace

S3MM_MODULE_ENTRY(RustfsModule)

} // namespace s3mm::module
