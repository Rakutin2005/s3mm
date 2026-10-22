#pragma once
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::rest {

/// Blank RBAC scaffolding. Intentionally not enforced yet: the structures and
/// service boundary are prepared so a future implementation can fill them in
/// without changing the REST module API.
struct RbacPermission {
    std::string id;
    std::string name;
    std::string description;
};

struct RbacRole {
    std::string id;
    std::string name;
    std::vector<std::string> permissionIds;
};

struct RbacUser {
    std::string id;
    std::string username;
    std::string displayName;
    std::vector<std::string> roleIds;
    std::vector<std::string> permissionIds;
};

class RbacService {
public:
    virtual ~RbacService() = default;
    virtual Result<std::vector<RbacUser>> listUsers() const {
        return Result<std::vector<RbacUser>>::failure("RBAC is not implemented yet");
    }
    virtual Result<std::vector<RbacRole>> listRoles() const {
        return Result<std::vector<RbacRole>>::failure("RBAC is not implemented yet");
    }
    virtual Result<std::vector<RbacPermission>> listPermissions() const {
        return Result<std::vector<RbacPermission>>::failure("RBAC is not implemented yet");
    }
};

} // namespace s3mm::rest
