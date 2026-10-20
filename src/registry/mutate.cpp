#include "s3mm/registry/mutate.hpp"

#include <sstream>

#include "s3mm/common/error.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/secret.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/units.hpp"

namespace s3mm::registry {

namespace {

Value strArray(const std::vector<std::string>& v) {
    Value a = Value::array();
    for (const auto& s : v) a.push(Value::str(s));
    return a;
}

} // namespace

// ---------------------------------------------------------------- fields ----

const Value& fieldsOf(const Value& req) {
    const Value* f = req.find("fields");
    return (f && f->isObject()) ? *f : req;
}

bool has(const Value& f, const std::string& k) { return f.find(k) != nullptr; }

std::string fstr(const Value& f, const std::string& k, const std::string& def) {
    const Value* v = f.find(k);
    return v ? v->asString(def) : def;
}

bool fbool(const Value& f, const std::string& k, bool def) {
    const Value* v = f.find(k);
    if (!v) return def;
    if (v->type() == Value::Type::Bool) return v->asBool();
    if (v->type() == Value::Type::Number) return v->asInt() != 0;
    std::string s = str::toLower(v->asString());
    return s == "on" || s == "true" || s == "1" || s == "yes";
}

int64_t fint(const Value& f, const std::string& k, int64_t def) {
    const Value* v = f.find(k);
    if (!v) return def;
    if (v->type() == Value::Type::Number) return v->asInt();
    auto n = str::parseInt64(v->asString());
    return n ? *n : def;
}

double fdouble(const Value& f, const std::string& k, double def) {
    const Value* v = f.find(k);
    if (!v) return def;
    if (v->type() == Value::Type::Number) return v->asDouble();
    auto d = str::parseDouble(v->asString());
    return d ? *d : def;
}

uint64_t fsize(const Value& f, const std::string& k, uint64_t def) {
    const Value* v = f.find(k);
    if (!v) return def;
    if (v->type() == Value::Type::Number) return (uint64_t)v->asInt();
    auto s = units::tryParseSize(v->asString());
    return s ? *s : def;
}

int64_t fdur(const Value& f, const std::string& k, int64_t defSec) {
    const Value* v = f.find(k);
    if (!v) return defSec;
    if (v->type() == Value::Type::Number) return v->asInt();
    auto ms = units::tryParseDuration(v->asString());
    return ms ? (*ms + 999) / 1000 : defSec;
}

std::vector<std::string> flist(const Value& f, const std::string& k) {
    const Value* v = f.find(k);
    if (!v) return {};
    if (v->isArray()) {
        std::vector<std::string> out;
        for (const auto& it : v->items()) out.push_back(it.asString());
        return out;
    }
    if (v->isString()) return str::splitList(v->asString());
    return {};
}

std::string normKind(std::string k) {
    k = str::toLower(k);
    if (k == "clusters") return "cluster";
    if (k == "credentials") return "credential";
    if (k == "replications") return "replication";
    if (k == "targets") return "target";
    if (k == "policies" || k == "bundles") return "policy";
    if (k == "rules") return "rule";
    if (k == "settings") return "settings";
    return k;
}

policy::Action parseActionText(const std::string& text) {
    auto toks = str::splitWS(text);
    if (toks.empty()) throw UsageError("empty action");
    policy::Action a;
    a.name = toks[0];
    const policy::ActionSpec* spec = policy::findActionSpec(a.name);
    if (!spec) throw UsageError("unknown action '" + a.name + "'");
    bool positionalTaken = false;
    for (size_t i = 1; i < toks.size(); ++i) {
        auto eq = toks[i].find('=');
        if (eq == std::string::npos && spec->positional && !positionalTaken) {
            a.positional = toks[i];
            positionalTaken = true;
        } else {
            if (eq == std::string::npos)
                throw UsageError("expected key=value inside action '" + a.name + "'");
            a.params[toks[i].substr(0, eq)] = toks[i].substr(eq + 1);
        }
    }
    return a;
}

Value parseFields(const std::vector<std::string>& kv) {
    Value f = Value::object();
    for (const auto& item : kv) {
        auto eq = item.find('=');
        if (eq == std::string::npos || eq == 0)
            throw UsageError("expected key=value, got '" + item + "'");
        // Keep everything as a string: the field helpers parse lazily.
        f.set(item.substr(0, eq), Value::str(item.substr(eq + 1)));
    }
    return f;
}

// ----------------------------------------------------------- serialisation ---

Value clusterValue(const Cluster& c) {
    Value v = Value::object();
    v.set("name", Value::str(c.name));
    v.set("alias", Value::str(c.alias));
    v.set("addr", strArray(c.endpoints));
    v.set("path_style", Value::boolean(c.pathStyle));
    v.set("insecure", Value::boolean(c.insecure));
    v.set("vendor", Value::str(c.vendor));
    v.set("zone", Value::str(c.zone));
    v.set("credentials", strArray(c.credentials));
    v.set("location", Value::str(c.location));
    v.set("timeout", Value::number((int64_t)c.timeoutSec));
    v.set("connect_timeout", Value::number((int64_t)c.connectTimeoutSec));
    v.set("rate_limit", Value::number(c.rateLimitPerSec));
    v.set("parallel", Value::number((int64_t)c.parallel));
    v.set("part_size", Value::number(c.partSize));
    v.set("retries", Value::number((int64_t)c.retries));
    v.set("description", Value::str(c.description));
    return v;
}

Value credentialValue(const Credential& c) {
    Value v = Value::object();
    v.set("name", Value::str(c.name));
    v.set("cluster", Value::str(c.cluster));
    v.set("zone", Value::str(c.zone));
    v.set("access_key", Value::str(c.accessKey));
    v.set("has_secret", Value::boolean(!c.secretKey.empty()));
    v.set("secret_is_plain", Value::boolean(c.secretIsPlain));
    v.set("session_token_set", Value::boolean(!c.sessionToken.empty()));
    v.set("region", Value::str(c.region));
    v.set("read_only", Value::boolean(c.readOnly));
    return v;
}

Value replicationValue(const Replication& r) {
    Value v = Value::object();
    v.set("name", Value::str(r.name));
    v.set("source", Value::str(r.source));
    v.set("destination", Value::str(r.destination));
    v.set("buckets", strArray(r.buckets));
    v.set("accounts", strArray(r.accounts));
    v.set("policy", Value::str(r.policy));
    v.set("retention", Value::number(r.retentionSec));
    v.set("delete_propagation", Value::boolean(r.deletePropagation));
    v.set("queue_size", Value::number(r.queueSizeBytes));
    v.set("queue_time", Value::number(r.queuePeriodSec));
    v.set("min_size", Value::number(r.minSizeBytes));
    v.set("max_disk", Value::number(r.maxDiskBytes));
    v.set("scan_every", Value::number((int64_t)r.scanEverySec));
    v.set("paused", Value::boolean(r.paused));
    return v;
}

Value targetValue(const Target& t) {
    Value v = Value::object();
    v.set("name", Value::str(t.name));
    v.set("type", Value::str(t.kind));
    v.set("uri", Value::str(t.uri));
    v.set("template", Value::str(t.pathTemplate));
    v.set("description", Value::str(t.description));
    return v;
}

Value actionValue(const policy::Action& a) { return Value::str(a.toString()); }

Value ruleValue(const policy::Rule& r) {
    Value v = Value::object();
    v.set("order", Value::number((int64_t)r.order));
    v.set("name", Value::str(r.name));
    v.set("category", Value::str(policy::categoryName(r.category)));
    v.set("condition", Value::str(r.conditionText()));
    Value actions = Value::array();
    for (const auto& a : r.actions) actions.push(actionValue(a));
    v.set("actions", actions);
    v.set("line", Value::str(r.toString()));
    return v;
}

Value bundleValue(const policy::Bundle& b, bool withRules) {
    Value v = Value::object();
    v.set("name", Value::str(b.name));
    Value defaults = Value::object();
    for (const auto& [cat, action] : b.defaults)
        defaults.set(policy::categoryName(cat), actionValue(action));
    v.set("defaults", defaults);
    v.set("route_denied", Value::str(b.routes.denied));
    v.set("route_warning", Value::str(b.routes.warning));
    v.set("route_success", Value::str(b.routes.success));
    v.set("rules", Value::number((int64_t)b.rules.size()));
    if (withRules) {
        Value rules = Value::array();
        for (const auto& r : b.rules) rules.push(ruleValue(r));
        v.set("rule_list", rules);
    }
    return v;
}

Value settingsValue(const Settings& s) {
    Value v = Value::object();
    v.set("socket", Value::str(s.socket));
    v.set("pid_file", Value::str(s.pidFile));
    v.set("cache_dir", Value::str(s.cacheDir));
    v.set("secrets_dir", Value::str(s.secretsDir));
    v.set("modules_dir", Value::str(s.modulesDir));
    v.set("master_key_file", Value::str(s.masterKeyFile));
    v.set("worker_count", Value::number((int64_t)s.workerCount));
    v.set("log_level", Value::str(s.logLevel));
    v.set("log_facility", Value::str(s.logFacility));
    v.set("log_socket", Value::str(s.logSocket));
    v.set("metrics", Value::str(s.metricsListen));
    v.set("transfer_parallel", Value::number((int64_t)s.transferParallel));
    v.set("part_size", Value::number(s.partSize));
    v.set("retries", Value::number((int64_t)s.retries));
    v.set("backoff", Value::number((int64_t)s.backoffSec));
    v.set("rate_limit", Value::number(s.rateLimitPerSec));
    v.set("queue_size", Value::number(s.queueSizeBytes));
    v.set("queue_time", Value::number(s.queuePeriodSec));
    v.set("min_size", Value::number(s.minSizeBytes));
    v.set("max_disk", Value::number(s.maxDiskBytes));
    v.set("scan_every", Value::number((int64_t)s.scanEverySec));
    v.set("bucket_scan_every", Value::number((int64_t)s.bucketScanEverySec));
    v.set("permanent", Value::boolean(s.permanent));
    return v;
}

// -------------------------------------------------------------- mutations ----

Value mutateEntity(Registry& r, const std::string& cmd, const std::string& kindRaw,
                   const std::string& nameIn, const Value& fields) {
    const bool isAdd = cmd == "add", isEdit = cmd == "edit", isRm = cmd == "rm";
    if (!isAdd && !isEdit && !isRm)
        throw UsageError("mutate: unknown command '" + cmd + "'");

    std::string kind = normKind(kindRaw);
    if (kind.empty()) throw UsageError(cmd + ": 'kind' required");
    std::string name = nameIn;
    if (name.empty()) name = fstr(fields, "name");
    if (name.empty() && kind != "settings") throw UsageError(cmd + ": 'name' required");

    auto removed = [] {
        Value v = Value::object();
        v.set("removed", Value::boolean(true));
        return v;
    };

    if (kind == "settings") {
        if (isRm) throw UsageError("settings cannot be removed");
        if (isAdd && !has(fields, "socket") && !has(fields, "cache_dir"))
            throw UsageError("settings: use `edit settings` with key=value fields");
        Settings& st = r.mutableSettings();
        if (has(fields, "socket")) st.socket = fstr(fields, "socket", st.socket);
        if (has(fields, "pid_file")) st.pidFile = fstr(fields, "pid_file", st.pidFile);
        if (has(fields, "cache_dir")) st.cacheDir = fstr(fields, "cache_dir", st.cacheDir);
        if (has(fields, "secrets_dir")) st.secretsDir = fstr(fields, "secrets_dir", st.secretsDir);
        if (has(fields, "modules_dir")) st.modulesDir = fstr(fields, "modules_dir", st.modulesDir);
        if (has(fields, "master_key_file"))
            st.masterKeyFile = fstr(fields, "master_key_file", st.masterKeyFile);
        if (has(fields, "worker_count")) st.workerCount = (int)fint(fields, "worker_count", st.workerCount);
        if (has(fields, "log_level")) st.logLevel = fstr(fields, "log_level", st.logLevel);
        if (has(fields, "log_facility")) st.logFacility = fstr(fields, "log_facility", st.logFacility);
        if (has(fields, "log_socket")) st.logSocket = fstr(fields, "log_socket", st.logSocket);
        if (has(fields, "metrics")) st.metricsListen = fstr(fields, "metrics", st.metricsListen);
        if (has(fields, "transfer_parallel"))
            st.transferParallel = (int)fint(fields, "transfer_parallel", st.transferParallel);
        if (has(fields, "part_size")) st.partSize = fsize(fields, "part_size", st.partSize);
        if (has(fields, "retries")) st.retries = (int)fint(fields, "retries", st.retries);
        if (has(fields, "backoff")) st.backoffSec = (int)fdur(fields, "backoff", st.backoffSec);
        if (has(fields, "rate_limit")) st.rateLimitPerSec = fdouble(fields, "rate_limit", st.rateLimitPerSec);
        if (has(fields, "queue_size"))
            st.queueSizeBytes = (int64_t)fsize(fields, "queue_size", (uint64_t)st.queueSizeBytes);
        if (has(fields, "queue_time")) st.queuePeriodSec = fdur(fields, "queue_time", st.queuePeriodSec);
        if (has(fields, "min_size")) st.minSizeBytes = (int64_t)fsize(fields, "min_size", (uint64_t)st.minSizeBytes);
        if (has(fields, "max_disk")) st.maxDiskBytes = (int64_t)fsize(fields, "max_disk", (uint64_t)st.maxDiskBytes);
        if (has(fields, "scan_every")) st.scanEverySec = (int)fdur(fields, "scan_every", st.scanEverySec);
        if (has(fields, "bucket_scan_every"))
            st.bucketScanEverySec = (int)fdur(fields, "bucket_scan_every", st.bucketScanEverySec);
        if (has(fields, "permanent")) st.permanent = fbool(fields, "permanent", st.permanent);
        return settingsValue(st);
    }

    if (kind == "cluster") {
        if (isRm) {
            Result<void> res = r.removeCluster(name);
            if (!res) throw Error(res.error());
            return removed();
        }
        const Cluster* existing = r.cluster(name);
        if (isEdit && !existing) throw Error("no cluster '" + name + "'");
        Cluster c = existing ? *existing : Cluster();
        c.name = name;
        if (existing) {
            if (has(fields, "alias")) c.alias = fstr(fields, "alias", c.alias);
            if (has(fields, "addr") || has(fields, "endpoints"))
                c.endpoints = flist(fields, has(fields, "addr") ? "addr" : "endpoints");
        } else {
            c.alias = fstr(fields, "alias", name);
            c.endpoints = flist(fields, has(fields, "addr") ? "addr" : "endpoints");
            if (c.endpoints.empty()) throw UsageError("cluster: 'addr' required");
        }
        if (has(fields, "path_style")) c.pathStyle = fbool(fields, "path_style", c.pathStyle);
        if (has(fields, "insecure")) c.insecure = fbool(fields, "insecure", c.insecure);
        if (has(fields, "vendor")) c.vendor = fstr(fields, "vendor", c.vendor);
        if (has(fields, "zone")) c.zone = fstr(fields, "zone", c.zone);
        if (has(fields, "credentials")) c.credentials = flist(fields, "credentials");
        if (has(fields, "location")) c.location = fstr(fields, "location", c.location);
        if (has(fields, "timeout")) c.timeoutSec = (int)fdur(fields, "timeout", c.timeoutSec);
        if (has(fields, "connect_timeout"))
            c.connectTimeoutSec = (int)fdur(fields, "connect_timeout", c.connectTimeoutSec);
        if (has(fields, "rate_limit")) c.rateLimitPerSec = fdouble(fields, "rate_limit", c.rateLimitPerSec);
        if (has(fields, "parallel")) c.parallel = (int)fint(fields, "parallel", c.parallel);
        if (has(fields, "part_size")) c.partSize = fsize(fields, "part_size", c.partSize);
        if (has(fields, "retries")) c.retries = (int)fint(fields, "retries", c.retries);
        if (has(fields, "description")) c.description = fstr(fields, "description", c.description);
        Result<void> res = isAdd ? r.addCluster(c) : r.updateCluster(name, c);
        if (!res) throw Error(res.error());
        return clusterValue(c);
    }

    if (kind == "credential") {
        if (isRm) {
            Result<void> res = r.removeCredential(name);
            if (!res) throw Error(res.error());
            return removed();
        }
        const Credential* existing = r.credential(name);
        if (isEdit && !existing) throw Error("no credential '" + name + "'");
        Credential c = existing ? *existing : Credential();
        c.name = name;
        if (has(fields, "cluster")) c.cluster = fstr(fields, "cluster", c.cluster);
        if (has(fields, "zone")) c.zone = fstr(fields, "zone", c.zone);
        if (has(fields, "access_key")) c.accessKey = fstr(fields, "access_key", c.accessKey);
        if (has(fields, "session_token")) c.sessionToken = fstr(fields, "session_token", c.sessionToken);
        if (has(fields, "region")) c.region = fstr(fields, "region", c.region);
        if (has(fields, "read_only")) c.readOnly = fbool(fields, "read_only", c.readOnly);
        if (c.accessKey.empty()) throw UsageError("credential: 'access_key' required");

        // Secret materialisation: always into <secretsDir>/<name> (0400),
        // sealed with the master key when one is configured.
        auto materialize = [&](const std::string& plain) {
            const Settings& st = r.settings();
            fs::mkdirp(st.secretsDir);
            std::string path = fs::joinPath(st.secretsDir, name);
            std::string body = st.masterKey.empty() ? plain : secret::seal(plain, st.masterKey);
            if (!fs::writeFileAtomic(path, body + "\n"))
                throw Error("cannot write secret file " + path);
            fs::setPermissions(path, 0400);
            c.secretKey = plain;
            c.secretIsPlain = false;
        };
        std::string sec = fstr(fields, "secret", fstr(fields, "secret_key"));
        if (!sec.empty()) materialize(sec);
        std::string secFile = fstr(fields, "secret_file");
        if (!secFile.empty()) {
            auto content = fs::readSecretFile(secFile);
            if (!content) throw Error("secret_file: " + content.value_or("unreadable"));
            std::string plain = str::trim(*content);
            if (secret::isPemBlock(plain)) {
                if (r.settings().masterKey.empty())
                    throw Error("sealed secret_file requires a configured master_key");
                auto opened = secret::open(plain, r.settings().masterKey);
                if (!opened) throw Error("secret_file: " + opened.error());
                plain = opened.value();
            }
            materialize(plain);
        }
        if (c.secretKey.empty()) throw UsageError("credential: 'secret' or 'secret_file' required");

        Result<void> res = isAdd ? r.addCredential(c) : r.updateCredential(name, c);
        if (!res) throw Error(res.error());
        return credentialValue(c);
    }

    if (kind == "replication") {
        if (isRm) {
            Result<void> res = r.removeReplication(name);
            if (!res) throw Error(res.error());
            return removed();
        }
        const Replication* existing = r.replication(name);
        if (isEdit && !existing) throw Error("no replication '" + name + "'");
        Replication rep = existing ? *existing : Replication();
        rep.name = name;
        if (has(fields, "source")) rep.source = fstr(fields, "source", rep.source);
        if (has(fields, "destination")) rep.destination = fstr(fields, "destination", rep.destination);
        if (isAdd) {
            if (rep.source.empty() || rep.destination.empty())
                throw UsageError("replication: 'source' and 'destination' required");
            if (rep.policy.empty()) rep.policy = "default";
        }
        if (has(fields, "buckets")) rep.buckets = flist(fields, "buckets");
        if (has(fields, "accounts")) rep.accounts = flist(fields, "accounts");
        if (has(fields, "policy")) rep.policy = fstr(fields, "policy", rep.policy);
        if (has(fields, "retention")) rep.retentionSec = fdur(fields, "retention", rep.retentionSec);
        if (has(fields, "delete_propagation"))
            rep.deletePropagation = fbool(fields, "delete_propagation", rep.deletePropagation);
        if (has(fields, "queue_size"))
            rep.queueSizeBytes = (int64_t)fsize(fields, "queue_size", (uint64_t)rep.queueSizeBytes);
        if (has(fields, "queue_time")) rep.queuePeriodSec = fdur(fields, "queue_time", rep.queuePeriodSec);
        if (has(fields, "min_size")) rep.minSizeBytes = (int64_t)fsize(fields, "min_size", (uint64_t)rep.minSizeBytes);
        if (has(fields, "max_disk")) rep.maxDiskBytes = (int64_t)fsize(fields, "max_disk", (uint64_t)rep.maxDiskBytes);
        if (has(fields, "scan_every")) rep.scanEverySec = (int)fdur(fields, "scan_every", rep.scanEverySec);
        if (has(fields, "paused")) rep.paused = fbool(fields, "paused", rep.paused);
        Result<void> res = isAdd ? r.addReplication(rep) : r.updateReplication(name, rep);
        if (!res) throw Error(res.error());
        return replicationValue(rep);
    }

    if (kind == "target") {
        if (isRm) {
            Result<void> res = r.removeTarget(name);
            if (!res) throw Error(res.error());
            return removed();
        }
        const Target* existing = r.target(name);
        if (isEdit && !existing) throw Error("no target '" + name + "'");
        Target t = existing ? *existing : Target();
        t.name = name;
        if (has(fields, "type") || has(fields, "kind"))
            t.kind = fstr(fields, has(fields, "type") ? "type" : "kind", t.kind);
        if (has(fields, "uri")) t.uri = fstr(fields, "uri", t.uri);
        if (has(fields, "template")) t.pathTemplate = fstr(fields, "template", t.pathTemplate);
        if (has(fields, "description")) t.description = fstr(fields, "description", t.description);
        if (isAdd && t.kind.empty()) throw UsageError("target: 'type' required");
        Result<void> res = isAdd ? r.addTarget(t) : r.updateTarget(name, t);
        if (!res) throw Error(res.error());
        return targetValue(t);
    }

    if (kind == "policy") {
        if (isRm) {
            Result<void> res = r.removeBundle(name);
            if (!res) throw Error(res.error());
            return removed();
        }
        auto it = r.bundles().find(name);
        if (isEdit && it == r.bundles().end()) throw Error("no policy bundle '" + name + "'");
        policy::Bundle b = it != r.bundles().end() ? it->second : policy::Bundle();
        b.name = name;
        if (has(fields, "default_access"))
            b.defaults[policy::Category::Access] = parseActionText(fstr(fields, "default_access"));
        if (has(fields, "default_bucket"))
            b.defaults[policy::Category::Bucket] = parseActionText(fstr(fields, "default_bucket"));
        if (has(fields, "default_object"))
            b.defaults[policy::Category::Object] = parseActionText(fstr(fields, "default_object"));
        if (has(fields, "route_denied")) b.routes.denied = fstr(fields, "route_denied", b.routes.denied);
        if (has(fields, "route_warning")) b.routes.warning = fstr(fields, "route_warning", b.routes.warning);
        if (has(fields, "route_success")) b.routes.success = fstr(fields, "route_success", b.routes.success);
        Result<void> res = isAdd ? r.addBundle(b) : r.updateBundle(name, b);
        if (!res) throw Error(res.error());
        return bundleValue(b, true);
    }

    throw UsageError(cmd + ": unknown kind '" + kind + "'");
}

Value applyRule(Registry& r, const std::string& action, const std::string& bundleName,
                const std::string& ref, const std::string& line, const std::string& before,
                const std::string& after) {
    if (bundleName.empty()) throw UsageError("rule: 'policy' bundle name required");
    auto it = r.bundles().find(bundleName);
    if (it == r.bundles().end()) throw Error("no policy bundle '" + bundleName + "'");

    if (action == "list") {
        Value arr = Value::array();
        for (const auto& rl : it->second.rules) arr.push(ruleValue(rl));
        return arr;
    }

    auto ack = [&](const std::string& a) {
        Value v = Value::object();
        v.set("bundle", Value::str(bundleName));
        v.set("action", Value::str(a));
        return v;
    };

    if (action == "add") {
        if (line.empty()) throw UsageError("rule add: 'line' required");
        auto parsed = policy::Rule::parseLine(line);
        if (!parsed) throw Error("rule: " + parsed.error());
        Result<void> res = r.addRule(bundleName, parsed.value(), before, after);
        if (!res) throw Error(res.error());
        return ack("add");
    }
    if (action == "edit") {
        if (ref.empty()) throw UsageError("rule edit: 'ref' (name or number) required");
        if (line.empty()) throw UsageError("rule edit: 'line' required");
        auto parsed = policy::Rule::parseLine(line);
        if (!parsed) throw Error("rule: " + parsed.error());
        Result<void> res = r.replaceRule(bundleName, ref, parsed.value());
        if (!res) throw Error(res.error());
        return ack("edit");
    }
    if (action == "rm" || action == "remove") {
        if (ref.empty()) throw UsageError("rule rm: 'ref' (name or number) required");
        Result<void> res = r.removeRule(bundleName, ref);
        if (!res) throw Error(res.error());
        Value v = Value::object();
        v.set("removed", Value::boolean(true));
        return v;
    }
    throw UsageError("rule: unknown action '" + action + "'");
}

} // namespace s3mm::registry
