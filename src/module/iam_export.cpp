#include "s3mm/module/iam_export.hpp"

#include <algorithm>

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
    auto usersRaw = zip::extractFile(archive, "iam-assets/users.json");
    if (!usersRaw)
        return Result<std::vector<Account>>::failure(vendor + " export-iam: " + usersRaw.error());
    std::string err;
    Value users = Value::parseJson(usersRaw.value(), &err);
    if (!err.empty() || !users.isObject())
        return Result<std::vector<Account>>::failure(vendor + " export-iam: unparseable users.json: " + err);

    Value mappings;
    if (auto mappingRaw = zip::extractFile(archive, "iam-assets/user_mappings.json")) {
        std::string mappingErr;
        mappings = Value::parseJson(mappingRaw.value(), &mappingErr);
        if (!mappingErr.empty() || !mappings.isObject()) mappings = Value::null();
    }
    Value groups;
    if (auto groupsRaw = zip::extractFile(archive, "iam-assets/groups.json")) {
        std::string groupsErr;
        groups = Value::parseJson(groupsRaw.value(), &groupsErr);
        if (!groupsErr.empty() || !groups.isObject()) groups = Value::null();
    }

    std::vector<Account> out;
    for (const auto& [key, info] : users.members()) {
        if (!info.isObject()) continue;
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
    return Result<std::vector<Account>>(std::move(out));
}

} // namespace s3mm::module
