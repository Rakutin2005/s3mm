#include "s3mm/module/iam_export.hpp"

#include <algorithm>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/value.hpp"
#include "s3mm/common/zip.hpp"

namespace s3mm::module {
namespace {

void addPolicyList(Account& account, const Value& value) {
    if (value.isString()) {
        for (const auto& p : str::splitList(value.asString()))
            if (std::find(account.policies.begin(), account.policies.end(), p) == account.policies.end())
                account.policies.push_back(p);
    } else if (value.isArray()) {
        for (const auto& item : value.items()) {
            std::string p = item.asString();
            if (!p.empty() && std::find(account.policies.begin(), account.policies.end(), p) == account.policies.end())
                account.policies.push_back(std::move(p));
        }
    }
}

void addGroupList(Account& account, const Value& value) {
    if (value.isString()) {
        for (const auto& g : str::splitList(value.asString()))
            if (std::find(account.groups.begin(), account.groups.end(), g) == account.groups.end())
                account.groups.push_back(g);
    } else if (value.isArray()) {
        for (const auto& item : value.items()) {
            std::string g = item.asString();
            if (!g.empty() && std::find(account.groups.begin(), account.groups.end(), g) == account.groups.end())
                account.groups.push_back(std::move(g));
        }
    }
}

} // namespace

Result<std::vector<Account>> parseIamExport(std::string_view archive, const std::string& vendor) {
    LOG_DEBUG(vendor, " export-iam: parsing archive (", archive.size(), " bytes)");
    auto usersRaw = zip::extractFile(archive, "iam-assets/users.json");
    if (!usersRaw) {
        LOG_ERROR(vendor, " export-iam: cannot extract iam-assets/users.json: ", usersRaw.error());
        return Result<std::vector<Account>>::failure(vendor + " export-iam: " + usersRaw.error());
    }
    std::string err;
    Value users = Value::parseJson(usersRaw.value(), &err);
    if (!err.empty() || !users.isObject()) {
        LOG_ERROR(vendor, " export-iam: unparseable users.json: ", err.empty() ? "not an object" : err, " (",
                  usersRaw.value().size(), " bytes)");
        return Result<std::vector<Account>>::failure(vendor + " export-iam: unparseable users.json: " + err);
    }

    Value mappings;
    if (auto mappingRaw = zip::extractFile(archive, "iam-assets/user_mappings.json")) {
        std::string mappingErr;
        mappings = Value::parseJson(mappingRaw.value(), &mappingErr);
        if (!mappingErr.empty() || !mappings.isObject()) {
            LOG_WARN(vendor, " export-iam: ignoring unparseable user_mappings.json: ",
                     mappingErr.empty() ? "not an object" : mappingErr);
            mappings = Value::null();
        }
    } else {
        LOG_DEBUG(vendor, " export-iam: no user_mappings.json in archive");
    }
    Value groups;
    if (auto groupsRaw = zip::extractFile(archive, "iam-assets/groups.json")) {
        std::string groupsErr;
        groups = Value::parseJson(groupsRaw.value(), &groupsErr);
        if (!groupsErr.empty() || !groups.isObject()) {
            LOG_WARN(vendor, " export-iam: ignoring unparseable groups.json: ",
                     groupsErr.empty() ? "not an object" : groupsErr);
            groups = Value::null();
        }
    } else {
        LOG_DEBUG(vendor, " export-iam: no groups.json in archive");
    }

    std::vector<Account> out;
    for (const auto& [key, info] : users.members()) {
        if (!info.isObject()) {
            LOG_WARN(vendor, " export-iam: user entry '", key, "' is not an object, skipped");
            continue;
        }
        Account a;
        a.accessKey = info.getString("accessKey", key);
        if (a.accessKey.empty()) a.accessKey = key;
        a.secretKey = info.getString("secretKey", info.getString("secret_key"));
        a.hasSecret = !a.secretKey.empty();
        std::string status = str::toLower(info.getString("status", "enabled"));
        a.status = (status == "disabled" || status == "off" || status == "false") ? "disabled" : "enabled";
        if (const Value* g = info.find("groups")) addGroupList(a, *g);

        if (const Value* mapping = mappings.find(key); mapping && mapping->isObject()) {
            if (const Value* p = mapping->find("policy")) addPolicyList(a, *p);
            if (const Value* p = mapping->find("policies")) addPolicyList(a, *p);
            if (const Value* g = mapping->find("groups")) addGroupList(a, *g);
        }
        LOG_DEBUG(vendor, " export-iam: account ", a.accessKey, " status=", a.status, " secret=",
                  a.hasSecret ? log::redact(a.secretKey) : std::string("none"), " policies=",
                  str::join(a.policies, ","), " groups=", str::join(a.groups, ","));
        if (!a.accessKey.empty()) out.push_back(std::move(a));
    }

    // groups.json is the authoritative membership source in export-iam:
    // user_mappings.json only carries direct user policies.
    if (groups.isObject()) {
        std::map<std::string, size_t> byKey;
        for (size_t i = 0; i < out.size(); ++i) byKey[out[i].accessKey] = i;
        for (const auto& [group, info] : groups.members()) {
            if (!info.isObject()) continue;
            const Value* members = info.find("members");
            if (!members || !members->isArray()) continue;
            for (const auto& m : members->items()) {
                auto it = byKey.find(m.asString());
                if (it == byKey.end()) continue;
                Account& a = out[it->second];
                if (std::find(a.groups.begin(), a.groups.end(), group) == a.groups.end())
                    a.groups.push_back(group);
            }
        }
    }
    LOG_INFO(vendor, " export-iam: parsed ", out.size(), " account(s)", groups.isObject() ? " with groups" : "");
    return Result<std::vector<Account>>(std::move(out));
}

} // namespace s3mm::module
