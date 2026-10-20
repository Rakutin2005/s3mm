#pragma once
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/s3/client.hpp"

namespace s3mm::module {

/// What a vendor implementation supports. The generic engine degrades gracefully.
struct FeatureSet {
    bool credentials = true;   // account/user CRUD on the cluster
    bool acl = true;           // bucket ACL read/write
    bool bucketPolicy = true;  // bucket policy read/write
    bool versioning = true;
    bool tagging = true;
    bool inventory = false;    // S3 Inventory based delta detection
    bool iamPolicy = true;     // attaching inline/managed policies to accounts
};

/// One S3 account/user as seen by the admin API.
struct Account {
    std::string accessKey;
    std::string secretKey;   // empty when the vendor does not expose secrets
    bool hasSecret = false;
    std::string status;      // "enabled" | "disabled"
    std::vector<std::string> policies;
    std::vector<std::string> groups;
    /// bucket -> permission list ("READ,WRITE" etc). Empty map = no bucket grants.
    std::map<std::string, std::string> buckets;
};

/// Vendor-specific admin plane. Implemented in modules/s3mm_mod_<vendor>.so.
class IAdminProvider {
public:
    virtual ~IAdminProvider() = default;
    virtual const char* vendorName() const = 0;
    virtual FeatureSet features() const = 0;

    virtual Result<std::vector<Account>> listAccounts() = 0;
    virtual Result<Account> getAccount(const std::string& accessKey) = 0;
    virtual Result<void> createAccount(const Account& account) = 0;
    virtual Result<void> setSecret(const std::string& accessKey, const std::string& secretKey) = 0;
    virtual Result<void> setStatus(const std::string& accessKey, const std::string& status) = 0;
    /// Replace the full set of bucket grants of an account.
    virtual Result<void> setBucketAccess(const std::string& accessKey,
                                         const std::map<std::string, std::string>& buckets) = 0;
    virtual Result<void> addBucketAccess(const std::string& accessKey, const std::string& bucket,
                                         const std::string& permissions) = 0;
    virtual Result<void> removeBucketAccess(const std::string& accessKey, const std::string& bucket) = 0;
    virtual Result<void> attachPolicy(const std::string& accessKey, const std::string& policyName) = 0;
    virtual Result<void> deleteAccount(const std::string& accessKey) = 0;
};

struct ModuleInfo {
    const char* name = "unknown";
    const char* version = "0.0.0";
    const char* vendor = "generic";
};

/// A loadable module. Vendor specific code lives ONLY inside modules.
class IModule {
public:
    virtual ~IModule() = default;
    virtual ModuleInfo info() const = 0;
    /// Create the admin provider for a cluster endpoint.
    virtual Result<std::unique_ptr<IAdminProvider>> createAdmin(const s3::ClientOptions& options,
                                                                const sigv4::Credentials& credentials) = 0;
    /// Hook to adjust data plane client options (region, service name, headers...).
    virtual void adjustClientOptions(s3::ClientOptions&) {}
};

/// Every module .so exports this symbol.
extern "C" {
typedef IModule* (*CreateModuleFn)();
}

#define S3MM_MODULE_ENTRY(ClassName)                                             \
    extern "C" s3mm::module::IModule* s3mm_module_entry() { return new ClassName(); }

} // namespace s3mm::module
