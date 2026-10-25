#include "s3mm/registry/registry.hpp"
#include <cstdio>

#include <algorithm>
#include <sstream>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/secret.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/units.hpp"

namespace s3mm::registry {

using config::Node;

static std::string loc(const Node& n) { return n.file + ":" + std::to_string(n.line); }

static std::vector<std::string> argList(const Node& n) {
    std::vector<std::string> out;
    for (const auto& a : n.args)
        for (auto& part : str::splitList(a)) out.push_back(part);
    return out;
}

// ---------------------------------------------------------------- settings --

Result<void> Registry::parseQueueBlock(const Node& node) {
    for (const auto& c : node.children) {
        if (c.name == "size") settings_.queueSizeBytes = (int64_t)units::parseSize(c.argOr(0, "1G"));
        else if (c.name == "time" || c.name == "period") settings_.queuePeriodSec = units::parseDurationSeconds(c.argOr(0, "5m"));
        else if (c.name == "min_size") settings_.minSizeBytes = (int64_t)units::parseSize(c.argOr(0, "0"));
        else if (c.name == "max_disk") settings_.maxDiskBytes = (int64_t)units::parseSize(c.argOr(0, "10G"));
        else return Result<void>::failure(loc(c) + ": unknown queue directive '" + c.name + "'");
    }
    return Result<void>::success();
}

Result<void> Registry::parseTransferBlock(const Node& node) {
    for (const auto& c : node.children) {
        if (c.name == "parallel") settings_.transferParallel = (int)c.int64Value("parallel", 4);
        else if (c.name == "part_size") settings_.partSize = units::parseSize(c.argOr(0, "16M"));
        else if (c.name == "retries") settings_.retries = (int)c.int64Value("retries", 5);
        else if (c.name == "backoff") settings_.backoffSec = units::parseDurationSeconds(c.argOr(0, "5s"));
        else if (c.name == "rate_limit") settings_.rateLimitPerSec = str::parseDouble(c.argOr(0, "0")).value_or(0);
        else return Result<void>::failure(loc(c) + ": unknown transfer directive '" + c.name + "'");
    }
    return Result<void>::success();
}

Result<void> Registry::parseSettings(const Node& node) {
    for (const auto& c : node.children) {
        try {
            if (c.name == "socket") settings_.socket = c.argRequired(0);
            else if (c.name == "pid_file") settings_.pidFile = c.argRequired(0);
            else if (c.name == "cache_dir") settings_.cacheDir = c.argRequired(0);
            else if (c.name == "secrets_dir") settings_.secretsDir = c.argRequired(0);
            else if (c.name == "modules_dir") settings_.modulesDir = c.argRequired(0);
            else if (c.name == "master_key") settings_.masterKey = c.argRequired(0);
            else if (c.name == "master_key_file") settings_.masterKeyFile = c.argRequired(0);
            else if (c.name == "worker_count") settings_.workerCount = (int)c.int64Value("worker_count", 0);
            else if (c.name == "metrics") settings_.metricsListen = c.argRequired(0);
            else if (c.name == "permanent") settings_.permanent = c.boolFlag(false);
            else if (c.name == "queue") {
                auto r = parseQueueBlock(c);
                if (!r) return r;
            } else if (c.name == "transfer") {
                auto r = parseTransferBlock(c);
                if (!r) return r;
            } else if (c.name == "log") {
                settings_.logLevel = c.value("level", settings_.logLevel);
                settings_.logFacility = c.value("facility", settings_.logFacility);
                settings_.logSocket = c.value("socket", settings_.logSocket);
            } else if (c.name == "scan") {
                settings_.scanEverySec = units::parseDurationSeconds(c.value("every", "5m"));
                settings_.bucketScanEverySec = units::parseDurationSeconds(c.value("bucket_every", "0"));
            } else if (c.name == "include" || c.name == "cluster" || c.name == "credential" || c.name == "policy" ||
                       c.name == "replication" || c.name == "target" || c.name == "s3mmws" || c.name == "wscluster" ||
                       c.name == "peer" || c.name == "peers" || c.name == "mtls") {
                continue; // handled elsewhere
            } else {
                return Result<void>::failure(loc(c) + ": unknown directive '" + c.name + "' in s3mm block");
            }
        } catch (const Error& e) {
            return Result<void>::failure(loc(c) + ": " + e.what());
        }
    }
    if (!settings_.masterKeyFile.empty()) {
        auto content = fs::readSecretFile(settings_.masterKeyFile);
        if (!content) return Result<void>::failure(loc(node) + ": master_key_file: " + content.value_or("unreadable"));
        settings_.masterKey = str::trim(*content);
    }
    return Result<void>::success();
}

// ---------------------------------------------------------------- cluster --

Result<void> Registry::parseCluster(const Node& node) {
    Cluster c;
    c.name = node.argOr(0);
    if (c.name.empty()) return Result<void>::failure(loc(node) + ": cluster requires a name");
    for (const auto& d : node.children) {
        try {
            if (d.name == "addr" || d.name == "endpoint") c.endpoints.push_back(d.argRequired(0));
            else if (d.name == "alias") c.alias = d.argRequired(0);
            else if (d.name == "path_style") c.pathStyle = d.boolFlag(true);
            else if (d.name == "insecure") c.insecure = d.boolFlag(false);
            else if (d.name == "vendor") c.vendor = d.argRequired(0);
            else if (d.name == "zone") c.zone = d.argRequired(0);
            else if (d.name == "credential" || d.name == "credentials") {
                for (const auto& a : argList(d)) c.credentials.push_back(a);
            } else if (d.name == "location" || d.name == "region") c.location = d.argRequired(0);
            else if (d.name == "timeout") c.timeoutSec = units::parseDurationSeconds(d.argOr(0, "120s"));
            else if (d.name == "connect_timeout") c.connectTimeoutSec = units::parseDurationSeconds(d.argOr(0, "10s"));
            else if (d.name == "rate_limit") c.rateLimitPerSec = str::parseDouble(d.argOr(0, "0")).value_or(0);
            else if (d.name == "parallel") c.parallel = (int)d.int64Value("parallel", 4);
            else if (d.name == "part_size") c.partSize = units::parseSize(d.argOr(0, "16M"));
            else if (d.name == "retries") c.retries = (int)d.int64Value("retries", 5);
            else if (d.name == "description") c.description = d.argOr(0);
            else if (d.name == "managed") c.managed = d.boolFlag(true);
            else return Result<void>::failure(loc(d) + ": unknown directive '" + d.name + "' in cluster '" + c.name + "'");
        } catch (const Error& e) {
            return Result<void>::failure(loc(d) + ": " + e.what());
        }
    }
    if (c.endpoints.empty()) return Result<void>::failure(loc(node) + ": cluster '" + c.name + "' has no addr");
    if (c.alias.empty()) c.alias = c.name;
    return addCluster(std::move(c));
}

// -------------------------------------------------------------- credential --

Result<void> Registry::parseCredential(const Node& node) {
    Credential c;
    c.name = node.argOr(0);
    if (c.name.empty()) return Result<void>::failure(loc(node) + ": credential requires a name");
    for (const auto& d : node.children) {
        try {
            if (d.name == "cluster") c.cluster = d.argRequired(0);
            else if (d.name == "zone") c.zone = d.argRequired(0);
            else if (d.name == "access_key") c.accessKey = d.argRequired(0);
            else if (d.name == "secret_key") { c.secretKey = d.argRequired(0); c.secretIsPlain = true; }
            else if (d.name == "secret_key_file") {
                auto content = fs::readSecretFile(d.argRequired(0));
                if (!content) throw Error("secret_key_file: " + content.value_or("unreadable"));
                c.secretKey = str::trim(*content);
                c.secretIsPlain = false;
            } else if (d.name == "session_token") c.sessionToken = d.argRequired(0);
            else if (d.name == "region") c.region = d.argRequired(0);
            else if (d.name == "read_only") c.readOnly = d.boolFlag(false);
            else return Result<void>::failure(loc(d) + ": unknown directive '" + d.name + "' in credential '" + c.name + "'");
        } catch (const Error& e) {
            return Result<void>::failure(loc(d) + ": " + e.what());
        }
    }
    if (c.accessKey.empty()) return Result<void>::failure(loc(node) + ": credential '" + c.name + "' has no access_key");
    if (c.secretKey.empty()) return Result<void>::failure(loc(node) + ": credential '" + c.name + "' has no secret_key");
    if (!c.secretIsPlain && secret::isPemBlock(c.secretKey)) {
        if (settings_.masterKey.empty())
            return Result<void>::failure(loc(node) + ": credential '" + c.name + "' uses a sealed secret but no master_key is configured");
        auto opened = secret::open(c.secretKey, settings_.masterKey);
        if (!opened) return Result<void>::failure(loc(node) + ": credential '" + c.name + "': " + opened.error());
        c.secretKey = opened.value();
    }
    return addCredential(std::move(c));
}

// ------------------------------------------------------------- replication --

Result<void> Registry::parseReplication(const Node& node) {
    Replication r;
    r.name = node.argOr(0);
    if (r.name.empty()) return Result<void>::failure(loc(node) + ": replication requires a name");
    for (const auto& d : node.children) {
        try {
            if (d.name == "source") r.source = d.argRequired(0);
            else if (d.name == "destination") r.destination = d.argRequired(0);
            else if (d.name == "buckets") r.buckets = argList(d);
            else if (d.name == "accounts" || d.name == "account") r.accounts = argList(d);
            else if (d.name == "policy") r.policy = d.argRequired(0);
            else if (d.name == "retention") { r.retentionSec = units::parseDurationSeconds(d.argOr(0, "0")); r.deletePropagation = r.retentionSec > 0; }
            else if (d.name == "delete_propagation") r.deletePropagation = d.boolFlag(false);
            else if (d.name == "scan_every") r.scanEverySec = units::parseDurationSeconds(d.argOr(0, "5m"));
            else if (d.name == "metadata_every") r.metadataEverySec = units::parseDurationSeconds(d.argOr(0, "5m"));
            else if (d.name == "paused") r.paused = d.boolFlag(false);
            else if (d.name == "queue") {
                for (const auto& q : d.children) {
                    if (q.name == "size") r.queueSizeBytes = (int64_t)units::parseSize(q.argOr(0, "1G"));
                    else if (q.name == "time" || q.name == "period") r.queuePeriodSec = units::parseDurationSeconds(q.argOr(0, "5m"));
                    else if (q.name == "min_size") r.minSizeBytes = (int64_t)units::parseSize(q.argOr(0, "0"));
                    else if (q.name == "max_disk") r.maxDiskBytes = (int64_t)units::parseSize(q.argOr(0, "10G"));
                    else return Result<void>::failure(loc(q) + ": unknown queue directive '" + q.name + "'");
                }
            } else {
                return Result<void>::failure(loc(d) + ": unknown directive '" + d.name + "' in replication '" + r.name + "'");
            }
        } catch (const Error& e) {
            return Result<void>::failure(loc(d) + ": " + e.what());
        }
    }
    if (r.source.empty()) return Result<void>::failure(loc(node) + ": replication '" + r.name + "' has no source");
    if (r.destination.empty()) return Result<void>::failure(loc(node) + ": replication '" + r.name + "' has no destination");
    if (r.buckets.empty()) r.buckets = {"*"};
    if (r.accounts.empty()) r.accounts = {"*"};
    if (r.policy.empty()) r.policy = "default";
    return addReplication(std::move(r));
}

// ------------------------------------------------------------------ target --

Result<void> Registry::parseTarget(const Node& node) {
    Target t;
    t.name = node.argOr(0);
    if (t.name.empty()) return Result<void>::failure(loc(node) + ": target requires a name");
    for (const auto& d : node.children) {
        if (d.name == "type" || d.name == "kind") t.kind = d.argRequired(0);
        else if (d.name == "uri" || d.name == "url") t.uri = d.argRequired(0);
        else if (d.name == "template") t.pathTemplate = d.argOr(0);
        else if (d.name == "description") t.description = d.argOr(0);
        else return Result<void>::failure(loc(d) + ": unknown directive '" + d.name + "' in target '" + t.name + "'");
    }
    if (t.kind.empty()) {
        // infer from uri
        if (str::startsWith(t.uri, "s3://")) t.kind = "s3";
        else if (str::startsWith(t.uri, "http://") || str::startsWith(t.uri, "https://")) t.kind = "http";
        else if (str::startsWith(t.uri, "file:")) t.kind = "file";
        else if (t.uri.empty()) t.kind = "null";
        else t.kind = "file";
    }
    if (t.kind == "s3" && !str::startsWith(t.uri, "s3://"))
        return Result<void>::failure(loc(node) + ": s3 target uri must look like s3://cluster/bucket/prefix");
    return addTarget(std::move(t));
}

// ------------------------------------------------------------------ policy --

Result<void> Registry::parsePolicy(const Node& node) {
    auto bundle = policy::Bundle::fromNode(node);
    if (!bundle) return Result<void>::failure(bundle.error());
    // A config block may override a built-in bundle ("default", "drop-all");
    // fromConfig() pre-inserts the built-ins, and dump() writes them back out.
    const std::string name = bundle.value().name;
    if ((name == "default" || name == "drop-all") && bundles_.count(name))
        return updateBundle(name, bundle.value());
    return addBundle(bundle.value());
}

// ---------------------------------------------------------------- registry --

Result<Registry> Registry::fromConfig(const config::Config& cfg) {
    Registry registry;
    if (!cfg.s3mm()) return Result<Registry>::failure("config has no 's3mm' block");
    const Node& root = *cfg.s3mm();

    auto settingsRes = registry.parseSettings(root);
    if (!settingsRes) return Result<Registry>::failure(settingsRes.error());

    // built-in bundles always exist
    registry.bundles_["drop-all"] = policy::Bundle::builtin("drop-all");
    registry.bundles_["default"] = policy::Bundle::builtin("default");

    // Credentials must be available before clusters (addCluster validates them),
    // so parse credential blocks first regardless of their order in the file.
    std::vector<const Node*> credNodes, otherNodes;
    for (const auto& c : root.children) {
        if (c.name == "credential" && c.block) credNodes.push_back(&c);
        else otherNodes.push_back(&c);
    }
    for (const Node* np : credNodes) {
        const Node& c = *np;
        auto res = registry.parseCredential(c);
        if (!res) return Result<Registry>::failure(res.error());
    }
    for (const Node* np : otherNodes) {
        const Node& c = *np;
        Result<void> res = Result<void>::success();
        if (c.name == "cluster" && c.block) res = registry.parseCluster(c);
        else if (c.name == "policy" && c.block) res = registry.parsePolicy(c);
        else if (c.name == "replication" && c.block) res = registry.parseReplication(c);
        else if (c.name == "target" && c.block) res = registry.parseTarget(c);
        if (!res) return Result<Registry>::failure(res.error());
    }

    // resolve replication references
    for (const auto& r : registry.replications_) {
        if (!registry.cluster(r.source)) return Result<Registry>::failure("replication '" + r.name + "': unknown source cluster '" + r.source + "'");
        if (!registry.cluster(r.destination)) return Result<Registry>::failure("replication '" + r.name + "': unknown destination cluster '" + r.destination + "'");
        if (!registry.bundle(r.policy)) return Result<Registry>::failure("replication '" + r.name + "': unknown policy bundle '" + r.policy + "'");
    }
    for (const auto& c : registry.clusters_)
        for (const auto& credName : c.credentials)
            if (!registry.credential(credName))
                return Result<Registry>::failure("cluster '" + c.name + "': unknown credential '" + credName + "'");

    // remember the config files that were loaded (flush-config writes back to them)
    registry.sources_.push_back(cfg.path().empty() ? std::string("<memory>") : cfg.path());
    for (const auto& root : cfg.roots())
        if (!root.file.empty() && root.file != registry.sources_.front())
            registry.sources_.push_back(root.file);
    return Result<Registry>(std::move(registry));
}

const Cluster* Registry::cluster(const std::string& nameOrAlias) const {
    for (const auto& c : clusters_)
        if (c.name == nameOrAlias || c.alias == nameOrAlias) return &c;
    return nullptr;
}

const Credential* Registry::credential(const std::string& name) const {
    for (const auto& c : credentials_)
        if (c.name == name) return &c;
    return nullptr;
}

const Credential* Registry::credentialFor(const Cluster& cluster, const std::string& name) const {
    const Credential* global = nullptr;
    for (const auto& c : credentials_) {
        if (c.name != name) continue;
        if (c.cluster == cluster.name) return &c; // cluster bound wins
        if (c.cluster.empty()) global = &c;
    }
    return global;
}

const Credential* Registry::bestCredential(const Cluster& cluster) const {
    const Credential* fallback = nullptr;
    for (const auto& name : cluster.credentials) {
        const Credential* c = credentialFor(cluster, name);
        if (!c) continue;
        if (!c->readOnly) return c;
        if (!fallback) fallback = c;
    }
    // fall back: any credential bound to the cluster, then any global one
    if (!fallback)
        for (const auto& c : credentials_)
            if (c.cluster == cluster.name && !c.readOnly) return &c;
    if (!fallback)
        for (const auto& c : credentials_)
            if (c.cluster.empty() && !c.readOnly) fallback = &c;
    return fallback;
}

const Replication* Registry::replication(const std::string& name) const {
    for (const auto& r : replications_)
        if (r.name == name) return &r;
    return nullptr;
}

const Target* Registry::target(const std::string& name) const {
    for (const auto& t : targets_)
        if (t.name == name) return &t;
    return nullptr;
}

const policy::Bundle* Registry::bundle(const std::string& name) const {
    auto it = bundles_.find(name);
    return it == bundles_.end() ? nullptr : &it->second;
}

policy::Bundle Registry::bundleOrBuiltin(const std::string& name) const {
    auto it = bundles_.find(name);
    if (it != bundles_.end()) return it->second;
    return policy::Bundle::builtin(name);
}

// -------------------------------------------------------------- mutation ---

Result<void> Registry::addCluster(Cluster c) {
    if (c.name.empty()) return Result<void>::failure("cluster requires a name");
    for (const auto& existing : clusters_)
        if (existing.name == c.name || existing.alias == c.alias)
            return Result<void>::failure("cluster '" + c.name + "' (alias '" + c.alias + "') already exists");
    for (const auto& cred : c.credentials)
        if (!credential(cred)) return Result<void>::failure("cluster '" + c.name + "': unknown credential '" + cred + "'");
    clusters_.push_back(std::move(c));
    return Result<void>::success();
}

Result<void> Registry::updateCluster(const std::string& name, Cluster c) {
    for (auto& existing : clusters_) {
        if (existing.name != name) continue;
        existing = c;
        existing.name = name;
        return Result<void>::success();
    }
    return Result<void>::failure("no cluster '" + name + "'");
}

Result<void> Registry::removeCluster(const std::string& name) {
    const Cluster* c = cluster(name);
    if (!c) return Result<void>::failure("no cluster '" + name + "'");
    std::string canonical = c->name;
    for (const auto& r : replications_)
        if (r.source == canonical || r.destination == canonical)
            return Result<void>::failure("cluster '" + name + "' is used by replication '" + r.name + "'");
    clusters_.erase(std::remove_if(clusters_.begin(), clusters_.end(),
                                   [&](const Cluster& x) { return x.name == canonical; }),
                    clusters_.end());
    return Result<void>::success();
}

Result<void> Registry::addCredential(Credential c) {
    if (c.name.empty()) return Result<void>::failure("credential requires a name");
    for (const auto& existing : credentials_)
        if (existing.name == c.name && existing.cluster == c.cluster)
            return Result<void>::failure("credential '" + c.name + "'" +
                                         (c.cluster.empty() ? " (global)" : " on cluster '" + c.cluster + "'") + " already exists");
    if (!c.cluster.empty() && !cluster(c.cluster)) return Result<void>::failure("unknown cluster '" + c.cluster + "'");
    credentials_.push_back(std::move(c));
    return Result<void>::success();
}

Result<void> Registry::updateCredential(const std::string& name, Credential c) {
    for (auto& existing : credentials_) {
        if (existing.name != name) continue;
        existing = c;
        existing.name = name;
        return Result<void>::success();
    }
    return Result<void>::failure("no credential '" + name + "'");
}

Result<void> Registry::removeCredential(const std::string& name) {
    for (const auto& cl : clusters_)
        for (const auto& cred : cl.credentials)
            if (cred == name) return Result<void>::failure("credential '" + name + "' is used by cluster '" + cl.name + "'");
    auto before = credentials_.size();
    credentials_.erase(std::remove_if(credentials_.begin(), credentials_.end(),
                                      [&](const Credential& x) { return x.name == name; }),
                       credentials_.end());
    if (credentials_.size() == before) return Result<void>::failure("no credential '" + name + "'");
    return Result<void>::success();
}

Result<void> Registry::addReplication(Replication r) {
    if (r.name.empty()) return Result<void>::failure("replication requires a name");
    if (replication(r.name)) return Result<void>::failure("replication '" + r.name + "' already exists");
    if (!cluster(r.source)) return Result<void>::failure("unknown source cluster '" + r.source + "'");
    if (!cluster(r.destination)) return Result<void>::failure("unknown destination cluster '" + r.destination + "'");
    if (!bundle(r.policy)) return Result<void>::failure("unknown policy bundle '" + r.policy + "'");
    replications_.push_back(std::move(r));
    return Result<void>::success();
}

Result<void> Registry::updateReplication(const std::string& name, Replication r) {
    for (auto& existing : replications_) {
        if (existing.name != name) continue;
        existing = r;
        existing.name = name;
        return Result<void>::success();
    }
    return Result<void>::failure("no replication '" + name + "'");
}

Result<void> Registry::removeReplication(const std::string& name) {
    auto before = replications_.size();
    replications_.erase(std::remove_if(replications_.begin(), replications_.end(),
                                       [&](const Replication& x) { return x.name == name; }),
                        replications_.end());
    if (replications_.size() == before) return Result<void>::failure("no replication '" + name + "'");
    return Result<void>::success();
}

Result<void> Registry::addTarget(Target t) {
    if (t.name.empty()) return Result<void>::failure("target requires a name");
    if (target(t.name)) return Result<void>::failure("target '" + t.name + "' already exists");
    targets_.push_back(std::move(t));
    return Result<void>::success();
}

Result<void> Registry::removeTarget(const std::string& name) {
    auto before = targets_.size();
    targets_.erase(std::remove_if(targets_.begin(), targets_.end(),
                                  [&](const Target& x) { return x.name == name; }),
                   targets_.end());
    if (targets_.size() == before) return Result<void>::failure("no target '" + name + "'");
    return Result<void>::success();
}

Result<void> Registry::updateTarget(const std::string& name, Target t) {
    for (auto& x : targets_) {
        if (x.name == name) {
            t.name = name;
            x = std::move(t);
            return Result<void>::success();
        }
    }
    return Result<void>::failure("no target '" + name + "'");
}

Result<void> Registry::addBundle(policy::Bundle b) {
    if (b.name.empty()) return Result<void>::failure("policy bundle requires a name");
    if (bundles_.count(b.name)) return Result<void>::failure("policy bundle '" + b.name + "' already exists");
    bundles_[b.name] = std::move(b);
    return Result<void>::success();
}

Result<void> Registry::updateBundle(const std::string& name, policy::Bundle b) {
    if (!bundles_.count(name)) return Result<void>::failure("no policy bundle '" + name + "'");
    b.name = name;
    bundles_[name] = std::move(b);
    return Result<void>::success();
}

Result<void> Registry::removeBundle(const std::string& name) {
    if (name == "default" || name == "drop-all")
        return Result<void>::failure("built-in policy bundle '" + name + "' cannot be removed");
    if (!bundles_.count(name)) return Result<void>::failure("no policy bundle '" + name + "'");
    for (const auto& r : replications_)
        if (r.policy == name) return Result<void>::failure("policy bundle '" + name + "' is used by replication '" + r.name + "'");
    bundles_.erase(name);
    return Result<void>::success();
}

Result<void> Registry::addRule(const std::string& bundleName, policy::Rule rule, const std::string& before,
                               const std::string& after) {
    auto it = bundles_.find(bundleName);
    if (it == bundles_.end()) return Result<void>::failure("no policy bundle '" + bundleName + "'");
    return it->second.addRule(std::move(rule), before, after);
}

Result<void> Registry::removeRule(const std::string& bundleName, const std::string& nameOrNumber) {
    auto it = bundles_.find(bundleName);
    if (it == bundles_.end()) return Result<void>::failure("no policy bundle '" + bundleName + "'");
    return it->second.removeRule(nameOrNumber);
}

Result<void> Registry::replaceRule(const std::string& bundleName, const std::string& nameOrNumber, policy::Rule rule) {
    auto it = bundles_.find(bundleName);
    if (it == bundles_.end()) return Result<void>::failure("no policy bundle '" + bundleName + "'");
    return it->second.replaceRule(nameOrNumber, std::move(rule));
}

// ------------------------------------------------------------ serialisation -

std::string Registry::dumpSettings() const {
    std::ostringstream os;
    os << "    socket " << str::quoteShell(settings_.socket) << ";\n";
    os << "    pid_file " << str::quoteShell(settings_.pidFile) << ";\n";
    os << "    cache_dir " << str::quoteShell(settings_.cacheDir) << ";\n";
    os << "    secrets_dir " << str::quoteShell(settings_.secretsDir) << ";\n";
    if (!settings_.modulesDir.empty()) os << "    modules_dir " << str::quoteShell(settings_.modulesDir) << ";\n";
    if (!settings_.masterKeyFile.empty()) os << "    master_key_file " << str::quoteShell(settings_.masterKeyFile) << ";\n";
    os << "    worker_count " << settings_.workerCount << ";\n";
    if (!settings_.metricsListen.empty()) os << "    metrics " << settings_.metricsListen << ";\n";
    os << "    log {\n";
    os << "        level " << settings_.logLevel << ";\n";
    os << "        facility " << settings_.logFacility << ";\n";
    os << "        socket " << str::quoteShell(settings_.logSocket) << ";\n";
    os << "    }\n";
    os << "    transfer {\n";
    os << "        parallel " << settings_.transferParallel << ";\n";
    os << "        part_size " << units::formatSize(settings_.partSize) << ";\n";
    os << "        retries " << settings_.retries << ";\n";
    os << "        backoff " << units::formatDuration(settings_.backoffSec * 1000) << ";\n";
    os << "        rate_limit " << settings_.rateLimitPerSec << ";\n";
    os << "    }\n";
    os << "    queue {\n";
    os << "        size " << units::formatSize((uint64_t)settings_.queueSizeBytes) << ";\n";
    os << "        time " << units::formatDuration(settings_.queuePeriodSec * 1000) << ";\n";
    os << "        min_size " << units::formatSize((uint64_t)settings_.minSizeBytes) << ";\n";
    os << "        max_disk " << units::formatSize((uint64_t)settings_.maxDiskBytes) << ";\n";
    os << "    }\n";
    os << "    scan {\n";
    os << "        every " << units::formatDuration(settings_.scanEverySec * 1000) << ";\n";
    os << "        bucket_every " << units::formatDuration(settings_.bucketScanEverySec * 1000) << ";\n";
    os << "    }\n";
    return os.str();
}

std::string Registry::dumpCluster(const Cluster& c) const {
    std::ostringstream os;
    os << "cluster " << str::quoteShell(c.name) << " {\n";
    if (c.alias != c.name) os << "    alias " << str::quoteShell(c.alias) << ";\n";
    for (const auto& e : c.endpoints) os << "    addr " << str::quoteShell(e) << ";\n";
    os << "    path_style " << (c.pathStyle ? "on" : "off") << ";\n";
    os << "    insecure " << (c.insecure ? "on" : "off") << ";\n";
    if (c.vendor != "generic") os << "    vendor " << str::quoteShell(c.vendor) << ";\n";
    if (!c.zone.empty()) os << "    zone " << str::quoteShell(c.zone) << ";\n";
    for (const auto& cred : c.credentials) os << "    credential " << str::quoteShell(cred) << ";\n";
    if (!c.location.empty()) os << "    location " << str::quoteShell(c.location) << ";\n";
    if (c.rateLimitPerSec > 0) os << "    rate_limit " << c.rateLimitPerSec << ";\n";
    if (c.parallel != 4) os << "    parallel " << c.parallel << ";\n";
    os << "    part_size " << units::formatSize(c.partSize) << ";\n";
    if (c.retries != 5) os << "    retries " << c.retries << ";\n";
    if (!c.description.empty()) os << "    description " << str::quoteShell(c.description) << ";\n";
    os << "}";
    return os.str();
}

std::string Registry::dumpCredential(const Credential& c) const {
    std::ostringstream os;
    os << "credential " << str::quoteShell(c.name) << " {\n";
    if (!c.cluster.empty()) os << "    cluster " << str::quoteShell(c.cluster) << ";\n";
    if (!c.zone.empty()) os << "    zone " << str::quoteShell(c.zone) << ";\n";
    os << "    access_key " << str::quoteShell(c.accessKey) << ";\n";
    if (c.secretIsPlain) os << "    secret_key " << str::quoteShell(c.secretKey) << ";\n";
    else os << "    secret_key_file " << str::quoteShell(fs::joinPath(settings_.secretsDir, c.name)) << ";\n";
    if (!c.sessionToken.empty()) os << "    session_token " << str::quoteShell(c.sessionToken) << ";\n";
    if (c.region != "us-east-1") os << "    region " << str::quoteShell(c.region) << ";\n";
    if (c.readOnly) os << "    read_only on;\n";
    os << "}";
    return os.str();
}

std::string Registry::dumpReplication(const Replication& r) const {
    std::ostringstream os;
    os << "replication " << str::quoteShell(r.name) << " {\n";
    os << "    source " << str::quoteShell(r.source) << ";\n";
    os << "    destination " << str::quoteShell(r.destination) << ";\n";
    os << "    buckets " << str::quoteShell(str::join(r.buckets, ",")) << ";\n";
    os << "    accounts " << str::quoteShell(str::join(r.accounts, ",")) << ";\n";
    os << "    policy " << str::quoteShell(r.policy) << ";\n";
    if (r.retentionSec > 0) os << "    retention " << units::formatDuration(r.retentionSec * 1000) << ";\n";
    if (r.deletePropagation) os << "    delete_propagation on;\n";
    if (r.scanEverySec > 0) os << "    scan_every " << units::formatDuration(r.scanEverySec * 1000) << ";\n";
    if (r.metadataEverySec != 300)
        os << "    metadata_every " << units::formatDuration(r.metadataEverySec * 1000) << ";\n";
    if (r.queueSizeBytes || r.queuePeriodSec || r.minSizeBytes || r.maxDiskBytes) {
        os << "    queue {\n";
        if (r.queueSizeBytes) os << "        size " << units::formatSize((uint64_t)r.queueSizeBytes) << ";\n";
        if (r.queuePeriodSec) os << "        time " << units::formatDuration(r.queuePeriodSec * 1000) << ";\n";
        if (r.minSizeBytes) os << "        min_size " << units::formatSize((uint64_t)r.minSizeBytes) << ";\n";
        if (r.maxDiskBytes) os << "        max_disk " << units::formatSize((uint64_t)r.maxDiskBytes) << ";\n";
        os << "    }\n";
    }
    if (r.paused) os << "    paused on;\n";
    os << "}";
    return os.str();
}

std::string Registry::dumpTarget(const Target& t) const {
    std::ostringstream os;
    os << "target " << str::quoteShell(t.name) << " {\n";
    os << "    type " << str::quoteShell(t.kind) << ";\n";
    if (!t.uri.empty()) os << "    uri " << str::quoteShell(t.uri) << ";\n";
    if (!t.pathTemplate.empty()) os << "    template " << str::quoteShell(t.pathTemplate) << ";\n";
    if (!t.description.empty()) os << "    description " << str::quoteShell(t.description) << ";\n";
    os << "}";
    return os.str();
}

/// Re-indent every line by four spaces (entity blocks nested into `s3mm { }`).
static std::string indentLines(const std::string& text) {
    const std::string pad = "    ";
    std::string out;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        size_t end = nl == std::string::npos ? text.size() : nl;
        out += pad + text.substr(pos, end - pos) + "\n";
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return out;
}

std::string Registry::dump() const {
    // The parser only recognises cluster/credential/policy/replication/target
    // blocks *inside* the `s3mm` root block, so everything must be nested there.
    std::ostringstream os;
    os << "s3mm {\n";
    os << dumpSettings() << "\n";
    for (const auto& c : clusters_) os << indentLines(dumpCluster(c)) << "\n";
    for (const auto& c : credentials_) os << indentLines(dumpCredential(c)) << "\n";
    for (const auto& [name, bundle] : bundles_) os << indentLines(bundle.dump()) << "\n";
    for (const auto& t : targets_) os << indentLines(dumpTarget(t)) << "\n";
    for (const auto& r : replications_) os << indentLines(dumpReplication(r)) << "\n";
    os << "}\n";
    return os.str();
}

} // namespace s3mm::registry
