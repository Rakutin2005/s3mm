#include "s3mm/rest/rbac.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <mutex>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::rest {

namespace {
Value vecStr(const std::vector<std::string>& v){ Value a=Value::array(); for(auto&s:v) a.push(Value::str(s)); return a; }
std::vector<std::string> fromVecStr(const Value* v){ std::vector<std::string> out; if(v&&v->isArray()) for(auto&x:v->items()) out.push_back(x.asString()); return out; }
}

RbacStore::RbacStore(const std::string& path) : path_(path) {
    load();
    if (permissions_.empty() && roles_.empty()) seedDefaults();
}

void RbacStore::load() {
    std::lock_guard<std::mutex> lk(mtx_);
    permissions_.clear(); roles_.clear(); users_.clear(); bindings_.clear(); acls_.clear();
    auto content = fs::readFile(path_);
    if (!content) return;
    std::string err;
    Value v = Value::parseJson(*content, &err);
    if (err.empty()==false || !v.isObject()) return;
    if (const Value* p = v.find("permissions")) if (p && p->isArray()) for (auto& x : p->items()) {
        RbacPermission rp; rp.id=x.getString("id"); rp.name=x.getString("name"); rp.description=x.getString("description"); if(!rp.id.empty()) permissions_.push_back(rp);
    }
    if (const Value* r = v.find("roles")) if (r && r->isArray()) for (auto& x : r->items()) {
        RbacRole rr; rr.id=x.getString("id"); rr.name=x.getString("name"); rr.description=x.getString("description"); rr.permissionIds=fromVecStr(x.find("permission_ids")); if(!rr.id.empty()) roles_.push_back(rr);
    }
    if (const Value* u = v.find("users")) if (u && u->isArray()) for (auto& x : u->items()) {
        RbacUser ru; ru.id=x.getString("id"); ru.username=x.getString("username"); ru.displayName=x.getString("display_name"); ru.provider=x.getString("provider"); ru.roleIds=fromVecStr(x.find("role_ids")); ru.permissionIds=fromVecStr(x.find("permission_ids")); if(!ru.id.empty()) users_.push_back(ru);
    }
    if (const Value* b = v.find("bindings")) if (b && b->isArray()) for (auto& x : b->items()) {
        RbacBinding rb; rb.id=x.getString("id"); rb.subject=x.getString("subject"); rb.subjectType=x.getString("subject_type"); rb.roleId=x.getString("role_id"); rb.scope=x.getString("scope"); if(!rb.id.empty()) bindings_.push_back(rb);
    }
    if (const Value* a = v.find("acls")) if (a && a->isArray()) for (auto& x : a->items()) {
        AclEntry ae; ae.id=x.getString("id"); ae.subject=x.getString("subject"); ae.subjectType=x.getString("subject_type"); ae.effect=x.getString("effect"); ae.resourceType=x.getString("resource_type"); ae.resourceId=x.getString("resource_id"); ae.actions=fromVecStr(x.find("actions")); if(!ae.id.empty()) acls_.push_back(ae);
    }
}

void RbacStore::persist() const {
    Value v = Value::object();
    Value perms = Value::array(); for (auto& p : permissions_) { Value x=Value::object(); x.set("id",Value::str(p.id)); x.set("name",Value::str(p.name)); x.set("description",Value::str(p.description)); perms.push(x); } v.set("permissions",perms);
    Value roles = Value::array(); for (auto& r : roles_) { Value x=Value::object(); x.set("id",Value::str(r.id)); x.set("name",Value::str(r.name)); x.set("description",Value::str(r.description)); x.set("permission_ids",vecStr(r.permissionIds)); roles.push(x); } v.set("roles",roles);
    Value users = Value::array(); for (auto& u : users_) { Value x=Value::object(); x.set("id",Value::str(u.id)); x.set("username",Value::str(u.username)); x.set("display_name",Value::str(u.displayName)); x.set("provider",Value::str(u.provider)); x.set("role_ids",vecStr(u.roleIds)); x.set("permission_ids",vecStr(u.permissionIds)); users.push(x); } v.set("users",users);
    Value binds = Value::array(); for (auto& b : bindings_) { Value x=Value::object(); x.set("id",Value::str(b.id)); x.set("subject",Value::str(b.subject)); x.set("subject_type",Value::str(b.subjectType)); x.set("role_id",Value::str(b.roleId)); x.set("scope",Value::str(b.scope)); binds.push(x); } v.set("bindings",binds);
    Value acls = Value::array(); for (auto& a : acls_) { Value x=Value::object(); x.set("id",Value::str(a.id)); x.set("subject",Value::str(a.subject)); x.set("subject_type",Value::str(a.subjectType)); x.set("effect",Value::str(a.effect)); x.set("resource_type",Value::str(a.resourceType)); x.set("resource_id",Value::str(a.resourceId)); x.set("actions",vecStr(a.actions)); acls.push(x); } v.set("acls",acls);
    fs::writeFileAtomic(path_, v.toJson(2));
}

void RbacStore::save() const { std::lock_guard<std::mutex> lk(mtx_); persist(); }

void RbacStore::seedDefaults() {
    std::lock_guard<std::mutex> lk(mtx_);
    auto addPerm = [&](const std::string& id,const std::string& name,const std::string& desc){
        for(auto&p:permissions_) if(p.id==id) return;
        permissions_.push_back({id,name,desc});
    };
    // permissions
    const char* resources[] = {"clusters","credentials","replications","targets","policies","buckets","objects","audit","rbac","settings","explorer"};
    const char* actions[] = {"read","write","manage"};
    for (auto r : resources) for (auto a : actions) addPerm(std::string(r)+":"+a, std::string(r)+":"+a, "");
    addPerm("*:*","*:*","wildcard");

    auto addRole = [&](const std::string& id,const std::string& name,const std::vector<std::string>& perms){
        for(auto&r:roles_) if(r.id==id) return;
        RbacRole rr; rr.id=id; rr.name=name; rr.permissionIds=perms; roles_.push_back(rr);
    };
    std::vector<std::string> allPerms; for(auto&p:permissions_) allPerms.push_back(p.id);
    addRole("admin","Administrator",allPerms);
    std::vector<std::string> opPerms; for(auto&p:permissions_){ if(p.id.find(":read")!=std::string::npos || p.id.find(":write")!=std::string::npos) opPerms.push_back(p.id);} 
    addRole("operator","Operator",opPerms);
    std::vector<std::string> audPerms; for(auto&p:permissions_) if(p.id.find(":read")!=std::string::npos || p.id.rfind("audit:",0)==0) audPerms.push_back(p.id);
    addRole("auditor","Auditor",audPerms);
    std::vector<std::string> viewPerms; for(auto&p:permissions_) if(p.id.find(":read")!=std::string::npos) viewPerms.push_back(p.id);
    addRole("viewer","Viewer",viewPerms);
    persist();
}

std::vector<RbacPermission> RbacStore::listPermissions() const { std::lock_guard<std::mutex> lk(mtx_); return permissions_; }
std::vector<RbacRole> RbacStore::listRoles() const { std::lock_guard<std::mutex> lk(mtx_); return roles_; }
std::optional<RbacRole> RbacStore::getRole(const std::string& id) const { std::lock_guard<std::mutex> lk(mtx_); for(auto&r:roles_) if(r.id==id) return r; return std::nullopt; }
bool RbacStore::addRole(const RbacRole& r){ std::lock_guard<std::mutex> lk(mtx_); for(auto&x:roles_) if(x.id==r.id) return false; roles_.push_back(r); persist(); return true; }
bool RbacStore::updateRole(const RbacRole& r){ std::lock_guard<std::mutex> lk(mtx_); for(auto&x:roles_) if(x.id==r.id){x=r; persist(); return true;} return false; }
bool RbacStore::deleteRole(const std::string& id){ std::lock_guard<std::mutex> lk(mtx_); auto it=std::remove_if(roles_.begin(),roles_.end(),[&](const RbacRole&r){return r.id==id;}); if(it==roles_.end()) return false; roles_.erase(it,roles_.end()); persist(); return true; }

std::vector<RbacUser> RbacStore::listUsers() const { std::lock_guard<std::mutex> lk(mtx_); return users_; }
std::optional<RbacUser> RbacStore::getUser(const std::string& id) const { std::lock_guard<std::mutex> lk(mtx_); for(auto&u:users_) if(u.id==id) return u; return std::nullopt; }
bool RbacStore::upsertUser(const RbacUser& u){ std::lock_guard<std::mutex> lk(mtx_); for(auto&x:users_) if(x.id==u.id){x=u; persist(); return true;} users_.push_back(u); persist(); return true; }
bool RbacStore::deleteUser(const std::string& id){ std::lock_guard<std::mutex> lk(mtx_); auto it=std::remove_if(users_.begin(),users_.end(),[&](const RbacUser&u){return u.id==id;}); if(it==users_.end()) return false; users_.erase(it,users_.end()); persist(); return true; }

std::vector<RbacBinding> RbacStore::listBindings() const { std::lock_guard<std::mutex> lk(mtx_); return bindings_; }
bool RbacStore::addBinding(const RbacBinding& b){ std::lock_guard<std::mutex> lk(mtx_); for(auto&x:bindings_) if(x.id==b.id) return false; bindings_.push_back(b); persist(); return true; }
bool RbacStore::deleteBinding(const std::string& id){ std::lock_guard<std::mutex> lk(mtx_); auto it=std::remove_if(bindings_.begin(),bindings_.end(),[&](const RbacBinding&b){return b.id==id;}); if(it==bindings_.end()) return false; bindings_.erase(it,bindings_.end()); persist(); return true; }

std::vector<AclEntry> RbacStore::listAcl(const std::string& rt, const std::string& rid) const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<AclEntry> out;
    for(auto&a:acls_) if(a.resourceType==rt && (rid.empty()||a.resourceId==rid)) out.push_back(a);
    return out;
}
bool RbacStore::setAclEntry(const AclEntry& e){ std::lock_guard<std::mutex> lk(mtx_); for(auto&x:acls_) if(x.id==e.id){x=e; persist(); return true;} acls_.push_back(e); persist(); return true; }
bool RbacStore::deleteAclEntry(const std::string& id){ std::lock_guard<std::mutex> lk(mtx_); auto it=std::remove_if(acls_.begin(),acls_.end(),[&](const AclEntry&a){return a.id==id;}); if(it==acls_.end()) return false; acls_.erase(it,acls_.end()); persist(); return true; }

std::set<std::string> RbacStore::effectivePermissions(const AuthUser& user, const std::string& rt, const std::string& rid) const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::set<std::string> out;
    // bindings for user
    for(auto&b:bindings_) {
        if (b.subjectType=="user" && b.subject==user.id) {
            // find role
            for(auto&r:roles_) if(r.id==b.roleId) for(auto&p:r.permissionIds) out.insert(p);
        }
        if (b.subjectType=="group") {
            for(auto&g:user.groups) if(b.subject==g) for(auto&r:roles_) if(r.id==b.roleId) for(auto&p:r.permissionIds) out.insert(p);
        }
    }
    // roleIds on user
    for(auto&rid2:user.roles) for(auto&r:roles_) if(r.id==rid2) for(auto&p:r.permissionIds) out.insert(p);
    // ACL overrides
    for(auto&a:acls_) {
        if (a.resourceType!=rt || (!rid.empty() && a.resourceId!=rid)) continue;
        bool subjectMatch=false;
        if (a.subjectType=="user" && a.subject==user.id) subjectMatch=true;
        if (a.subjectType=="role") for(auto&r:user.roles) if(a.subject==r) subjectMatch=true;
        if (a.subjectType=="group") for(auto&g:user.groups) if(a.subject==g) subjectMatch=true;
        if (!subjectMatch) continue;
        if (a.effect=="allow") for(auto&ac:a.actions) out.insert(rt+":"+ac);
        if (a.effect=="deny") for(auto&ac:a.actions) out.erase(rt+":"+ac);
    }
    if (out.count("*:*")) {
        // expand wildcard not needed; hasPermission handles
    }
    return out;
}

bool RbacStore::hasPermission(const AuthUser& user, const std::string& permission, const std::string& rt, const std::string& rid) const {
    auto perms = effectivePermissions(user, rt, rid);
    if (perms.count("*:*")) return true;
    if (perms.count(permission)) return true;
    // wildcard resource
    size_t colon = permission.find(':');
    if (colon != std::string::npos) {
        std::string action = permission.substr(colon);
        if (perms.count("*"+action)) return true;
    }
    return false;
}

} // namespace s3mm::rest
