#include "s3mm/replication/access.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::repl {

// ------------------------------------------------------------ SyncReport ---

std::string SyncReport::toJson() const {
    Value v = Value::object();
    v.set("dry_run", Value::boolean(dryRun));
    v.set("source_accounts", Value::number(sourceAccounts));
    v.set("destination_accounts", Value::number(destinationAccounts));
    v.set("matched", Value::number(matched));
    v.set("created", Value::number(created));
    v.set("updated", Value::number(updated));
    v.set("deleted", Value::number(deleted));
    v.set("failed", Value::number(failed));
    Value list = Value::array();
    for (const auto& c : changes) {
        Value item = Value::object();
        item.set("access_key", Value::str(c.accessKey));
        Value actions = Value::array();
        for (const auto& a : c.actions) actions.push(Value::str(a));
        item.set("actions", std::move(actions));
        item.set("applied", Value::boolean(c.applied));
        if (!c.error.empty()) item.set("error", Value::str(c.error));
        list.push(std::move(item));
    }
    v.set("changes", std::move(list));
    if (!errors.empty()) {
        Value errs = Value::array();
        for (const auto& e : errors) errs.push(Value::str(e));
        v.set("errors", std::move(errs));
    }
    return v.toJson(0);
}

std::string SyncReport::toText() const {
    std::ostringstream os;
    if (dryRun) os << "(dry run)\n";
    os << "source accounts: " << sourceAccounts << ", destination accounts: " << destinationAccounts
        << ", identical: " << matched << "\n";
    for (const auto& c : changes) {
        std::string joined = str::join(c.actions, ", ");
        os << (c.applied ? "applied" : (dryRun ? "planned" : "failed")) << ": " << c.accessKey << " [" << joined
           << "]";
        if (!c.error.empty()) os << " error: " << c.error;
        os << "\n";
    }
    for (const auto& e : errors) os << "error: " << e << "\n";
    os << "created: " << created << ", updated: " << updated << ", deleted: " << deleted
       << ", failed: " << failed << "\n";
    return os.str();
}

// ----------------------------------------------------------- AccountSync ---

AccountSync::AccountSync(const registry::Registry& registry, module::Loader& loader)
    : registry_(registry), loader_(loader) {}

bool AccountSync::selected(const registry::Replication& replication, const std::string& accessKey) {
    if (replication.accounts.empty()) return true;
    return glob::matchFilter(replication.accounts, accessKey);
}

Result<std::unique_ptr<module::IAdminProvider>> AccountSync::adminFor(const registry::Cluster& cluster) const {
    module::IModule* mod = loader_.find(cluster.vendor);
    if (!mod) {
        const auto names = loader_.names();
        return Result<std::unique_ptr<module::IAdminProvider>>::failure(
            "cluster '" + cluster.name + "': no module '" + cluster.vendor + "' loaded (available: " +
            str::join(names, ", ") + ")");
    }
    const registry::Credential* cred = registry_.bestCredential(cluster);
    if (!cred)
        return Result<std::unique_ptr<module::IAdminProvider>>::failure("cluster '" + cluster.name + "': no usable credential");

    s3::ClientOptions options;
    options.endpoints = cluster.endpoints;
    options.pathStyle = cluster.pathStyle;
    options.insecure = cluster.insecure;
    options.timeoutSec = cluster.timeoutSec;
    options.connectTimeoutSec = cluster.connectTimeoutSec;
    options.rateLimitPerSec = cluster.rateLimitPerSec;
    options.maxRetries = cluster.retries;
    mod->adjustClientOptions(options);

    sigv4::Credentials sig{cred->accessKey, cred->secretKey, cred->sessionToken, cred->region};
    auto provider = mod->createAdmin(options, sig);
    if (!provider) return Result<std::unique_ptr<module::IAdminProvider>>::failure(provider.error());
    if (!provider.value()->features().credentials)
        return Result<std::unique_ptr<module::IAdminProvider>>::failure(
            "cluster '" + cluster.name + "': module '" + cluster.vendor + "' does not support account admin");
    return provider;
}

Result<std::shared_ptr<s3::Client>> AccountSync::clientFor(const registry::Cluster& cluster,
                                                           const std::string& credentialName) const {
    const registry::Credential* cred = credentialName.empty()
                                           ? registry_.bestCredential(cluster)
                                           : registry_.credentialFor(cluster, credentialName);
    if (!cred) return Result<std::shared_ptr<s3::Client>>::failure("cluster '" + cluster.name + "': no usable credential");

    s3::ClientOptions options;
    options.endpoints = cluster.endpoints;
    options.pathStyle = cluster.pathStyle;
    options.insecure = cluster.insecure;
    options.timeoutSec = cluster.timeoutSec;
    options.connectTimeoutSec = cluster.connectTimeoutSec;
    options.rateLimitPerSec = cluster.rateLimitPerSec;
    options.maxRetries = cluster.retries;

    if (module::IModule* mod = loader_.find(cluster.vendor)) mod->adjustClientOptions(options);

    sigv4::Credentials sig{cred->accessKey, cred->secretKey, cred->sessionToken, cred->region};
    return Result<std::shared_ptr<s3::Client>>(std::make_shared<s3::Client>(options, sig));
}

namespace {

/// Compare two account views; append the differing actions to `actions`.
std::vector<std::string> diffAccounts(const module::Account& source, const module::Account& dest,
                                      bool sourceHasSecret, const module::FeatureSet& destFeatures) {
    std::vector<std::string> actions;
    if (!source.status.empty() && source.status != dest.status) actions.emplace_back("status");
    if (sourceHasSecret && dest.hasSecret && !source.secretKey.empty() && source.secretKey != dest.secretKey)
        actions.emplace_back("secret");
    if (source.buckets != dest.buckets) actions.emplace_back("grants");
    for (const auto& p : source.policies) {
        if (std::find(dest.policies.begin(), dest.policies.end(), p) == dest.policies.end())
            actions.push_back("policy+:" + p);
    }
    if (destFeatures.policyDetach) {
        for (const auto& p : dest.policies) {
            if (std::find(source.policies.begin(), source.policies.end(), p) == source.policies.end())
                actions.push_back("policy-:" + p);
        }
    }
    if (destFeatures.groups && source.groups != dest.groups) actions.emplace_back("groups");
    return actions;
}

} // namespace

Result<SyncReport> AccountSync::sync(const registry::Replication& replication, bool dryRun, bool prune,
                                     const std::function<bool(const module::Account&)>& accept) const {
    const registry::Cluster* source = registry_.cluster(replication.source);
    const registry::Cluster* destination = registry_.cluster(replication.destination);
    if (!source) return Result<SyncReport>::failure("unknown source cluster '" + replication.source + "'");
    if (!destination) return Result<SyncReport>::failure("unknown destination cluster '" + replication.destination + "'");

    auto sourceAdmin = adminFor(*source);
    if (!sourceAdmin) return Result<SyncReport>::failure(sourceAdmin.error());
    auto destAdmin = adminFor(*destination);
    if (!destAdmin) return Result<SyncReport>::failure(destAdmin.error());
    const module::FeatureSet destFeatures = destAdmin.value()->features();

    auto sourceList = sourceAdmin.value()->listAccounts();
    if (!sourceList) return Result<SyncReport>::failure(sourceList.error());
    auto destList = destAdmin.value()->listAccounts();
    if (!destList) return Result<SyncReport>::failure(destList.error());

    SyncReport report;
    report.dryRun = dryRun;

    std::map<std::string, module::Account> destByKey;
    for (auto& a : destList.value()) {
        if (!selected(replication, a.accessKey)) continue;
        destByKey[a.accessKey] = a;
    }
    report.destinationAccounts = (int64_t)destByKey.size();

    auto apply = [&](const AccountChange& change, auto&& fn) -> bool {
        if (dryRun) return true;
        auto res = fn();
        if (!res) {
            LOG_ERROR("account sync: ", change.accessKey, ": ", res.error());
            return false;
        }
        return true;
    };

    for (auto& src : sourceList.value()) {
        if (!selected(replication, src.accessKey)) continue;
        if (accept && !accept(src)) continue; // rejected by the access policy
        report.sourceAccounts++;

        auto destIt = destByKey.find(src.accessKey);
        if (destIt == destByKey.end()) {
            AccountChange change;
            change.accessKey = src.accessKey;
            change.actions.emplace_back("create");
            if (src.hasSecret) change.actions.emplace_back("secret");
            if (!src.buckets.empty()) change.actions.emplace_back("grants");
            for (const auto& p : src.policies) change.actions.push_back("policy+:" + p);
            if (destFeatures.groups && !src.groups.empty()) change.actions.emplace_back("groups");

            bool ok = apply(change, [&] { return destAdmin.value()->createAccount(src); });
            if (ok && !src.buckets.empty() && !dryRun)
                ok = apply(change, [&] { return destAdmin.value()->setBucketAccess(src.accessKey, src.buckets); });
            if (ok && destFeatures.groups && !src.groups.empty() && !dryRun) {
                ok = apply(change, [&] { return destAdmin.value()->setGroups(src.accessKey, src.groups, {}); });
            }
            if (ok && !dryRun) {
                for (const auto& p : src.policies) {
                    auto res = destAdmin.value()->attachPolicy(src.accessKey, p);
                    if (!res) LOG_WARN("account sync: attach policy ", p, " to ", src.accessKey, ": ", res.error());
                }
            }
            change.applied = ok && !dryRun;
            if (!ok && !dryRun) {
                change.error = "create failed";
                report.failed++;
            } else {
                report.created++;
            }
            report.changes.push_back(std::move(change));
            destByKey[src.accessKey] = src;
            continue;
        }

        std::vector<std::string> actions = diffAccounts(src, destIt->second, src.hasSecret, destFeatures);
        if (actions.empty()) {
            report.matched++;
            continue;
        }
        AccountChange change;
        change.accessKey = src.accessKey;
        change.actions = actions;

        bool ok = true;
        for (const auto& action : actions) {
            if (action == "status")
                ok = ok && apply(change, [&] { return destAdmin.value()->setStatus(src.accessKey, src.status); });
            else if (action == "secret" && !dryRun)
                ok = ok && apply(change, [&] { return destAdmin.value()->setSecret(src.accessKey, src.secretKey); });
            else if (action == "grants")
                ok = ok && apply(change, [&] { return destAdmin.value()->setBucketAccess(src.accessKey, src.buckets); });
            else if (action == "groups")
                ok = ok && apply(change, [&] {
                    return destAdmin.value()->setGroups(src.accessKey, src.groups, destIt->second.groups);
                });
            else if (str::startsWith(action, "policy+:")) {
                std::string policy = action.substr(std::strlen("policy+:"));
                ok = ok && apply(change, [&] { return destAdmin.value()->attachPolicy(src.accessKey, policy); });
            } else if (str::startsWith(action, "policy-:")) {
                std::string policy = action.substr(std::strlen("policy-:"));
                ok = ok && apply(change, [&] { return destAdmin.value()->detachPolicy(src.accessKey, policy); });
            } else if (str::startsWith(action, "policy:")) {
                std::string policy = action.substr(std::strlen("policy:"));
                ok = ok && apply(change, [&] { return destAdmin.value()->attachPolicy(src.accessKey, policy); });
            }
        }
        change.applied = ok && !dryRun;
        if (ok)
            report.updated++;
        else {
            change.error = "one or more updates failed";
            report.failed++;
        }
        report.changes.push_back(std::move(change));
    }

    if (prune) {
        // destination-only accounts inside the filter are removed
        std::vector<std::string> toRemove;
        for (const auto& [key, account] : destByKey) {
            bool onSource = false;
            for (const auto& src : sourceList.value()) {
                if (src.accessKey == key && selected(replication, src.accessKey) && (!accept || accept(src))) {
                    onSource = true;
                    break;
                }
            }
            if (!onSource) toRemove.push_back(key);
        }
        for (const auto& key : toRemove) {
            AccountChange change;
            change.accessKey = key;
            change.actions.emplace_back("delete");
            bool ok = apply(change, [&] { return destAdmin.value()->deleteAccount(key); });
            change.applied = ok && !dryRun;
            if (ok)
                report.deleted++;
            else {
                change.error = "delete failed";
                report.failed++;
            }
            report.changes.push_back(std::move(change));
        }
    }

    LOG_DEBUG("account sync for replication '", replication.name, "': created=", report.created,
              " updated=", report.updated, " deleted=", report.deleted, " matched=", report.matched,
              " failed=", report.failed, dryRun ? " (dry run)" : "");
    return Result<SyncReport>(std::move(report));
}

} // namespace s3mm::repl
