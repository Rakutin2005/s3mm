#pragma once
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"
namespace s3mm::rest {
struct AuthUser { std::string id; std::string username; std::string displayName; std::string email; std::string provider; std::vector<std::string> roles; std::vector<std::string> groups; std::map<std::string,std::string> attributes; };
struct AuthResult { bool ok=false; std::string error; AuthUser user; std::string token; };
class AuthProvider { public: virtual ~AuthProvider()=default; virtual std::string name() const=0; virtual bool enabled() const=0; virtual AuthResult authenticate(const std::string&,const std::string&)=0; virtual std::optional<AuthUser> resolveToken(const std::string&){return std::nullopt;} };
class SessionManager { public: SessionManager(int t=3600):ttl_(t){} std::string create(const AuthUser&); std::optional<AuthUser> resolve(const std::string&); void revoke(const std::string&); void sweep(); private: struct S{AuthUser u; std::chrono::steady_clock::time_point e;}; std::mutex m_; std::map<std::string,S> s_; int ttl_; };
struct LocalUserRecord { std::string username,displayName,email,salt,hash; std::vector<std::string> roles; };
class LocalAuthProvider : public AuthProvider { public: LocalAuthProvider(const std::string& f,int i=3,int mm=65536,int p=4); std::string name() const override{return "local";} bool enabled() const override{return enabled_;} AuthResult authenticate(const std::string&,const std::string&) override; bool addUser(const LocalUserRecord&,const std::string&); bool removeUser(const std::string&); std::vector<LocalUserRecord> listUsers() const; const std::string& usersFile() const{return usersFile_;} void setEnabled(bool v){enabled_=v;} private: std::string usersFile_; int iters_,mem_,par_; bool enabled_=true; mutable std::mutex mtx_; std::vector<LocalUserRecord> users_; void load(); void save() const; std::string hashPw(const std::string&,const std::string&) const; };
struct LdapConfig { bool enabled=false; std::string url,bindDn,bindPassword,userSearchBase,userFilter="(&(objectClass=inetOrgPerson)(uid=%s))",groupSearchBase,groupFilter="(&(objectClass=groupOfNames)(member=%s))",attrUid="uid",attrMail="mail",attrDisplayName="cn"; std::map<std::string,std::string> groupRoleMap; };
class LdapAuthProvider : public AuthProvider { public: explicit LdapAuthProvider(const LdapConfig&); std::string name() const override{return "ldap";} bool enabled() const override{return cfg_.enabled;} AuthResult authenticate(const std::string&,const std::string&) override; void setConfig(const LdapConfig& c){cfg_=c;} private: LdapConfig cfg_; };
struct KeycloakConfig { bool enabled=false; std::string issuer,clientId,clientSecret,realmRolesMap; bool useIntrospection=true; };
class KeycloakAuthProvider : public AuthProvider { public: explicit KeycloakAuthProvider(const KeycloakConfig&); std::string name() const override{return "keycloak";} bool enabled() const override{return cfg_.enabled;} AuthResult authenticate(const std::string&,const std::string&) override; std::optional<AuthUser> resolveToken(const std::string&) override; void setConfig(const KeycloakConfig& c){cfg_=c; discover();} private: KeycloakConfig cfg_; std::string tokenEndpoint_,userinfoEndpoint_,introspectionEndpoint_; void discover(); std::map<std::string,std::string> parseRoleMap() const; };
} // namespace s3mm::rest
