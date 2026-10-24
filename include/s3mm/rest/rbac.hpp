#pragma once
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"
#include "s3mm/rest/auth.hpp"

namespace s3mm::rest {

struct RbacPermission { std::string id; std::string name; std::string description; };

struct RbacRole { std::string id; std::string name; std::string description; std::vector<std::string> permissionIds; };

struct RbacBinding { std::string id; std::string subject; std::string subjectType; // user|role|group
    std::string roleId; std::string scope; };

struct RbacUser { std::string id; std::string username; std::string displayName; std::vector<std::string> roleIds; std::vector<std::string> permissionIds; std::string provider; };

struct AclEntry { std::string id; std::string subject; std::string subjectType; // user|role|group
    std::string effect; // allow|deny
    std::vector<std::string> actions; // read|write|manage
    std::string resourceType; std::string resourceId; };

class RbacStore {
public:
    RbacStore(const std::string& path);
    // permissions
    std::vector<RbacPermission> listPermissions() const;
    // roles
    std::vector<RbacRole> listRoles() const;
    std::optional<RbacRole> getRole(const std::string& id) const;
    bool addRole(const RbacRole& r);
    bool updateRole(const RbacRole& r);
    bool deleteRole(const std::string& id);
    // users (shadow of auth providers; for local management)
    std::vector<RbacUser> listUsers() const;
    std::optional<RbacUser> getUser(const std::string& id) const;
    bool upsertUser(const RbacUser& u);
    bool deleteUser(const std::string& id);
    // bindings
    std::vector<RbacBinding> listBindings() const;
    bool addBinding(const RbacBinding& b);
    bool deleteBinding(const std::string& id);
    // acl
    std::vector<AclEntry> listAcl(const std::string& resourceType, const std::string& resourceId) const;
    bool setAclEntry(const AclEntry& e);
    bool deleteAclEntry(const std::string& id);
    // evaluation helpers
    std::set<std::string> effectivePermissions(const AuthUser& user, const std::string& resourceType="", const std::string& resourceId="") const;
    bool hasPermission(const AuthUser& user, const std::string& permission, const std::string& resourceType="", const std::string& resourceId="") const;
    // seed
    void seedDefaults();
    void save() const;
    void load();
private:
    std::string path_;
    mutable std::mutex mtx_;
    std::vector<RbacPermission> permissions_;
    std::vector<RbacRole> roles_;
    std::vector<RbacUser> users_;
    std::vector<RbacBinding> bindings_;
    std::vector<AclEntry> acls_;
    void persist() const;
};

} // namespace s3mm::rest
