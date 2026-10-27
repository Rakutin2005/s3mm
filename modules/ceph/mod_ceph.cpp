// Ceph RADOS Gateway (RGW) vendor module.
//
// The RGW admin plane is a separate REST API (port 7480, /admin/...) and is
// not reachable through the S3 endpoint, so account operations degrade to a
// clear answer while the feature flags describe the S3 data plane of RGW.
#include "s3mm/module/module.hpp"

#include "s3mm/common/log.hpp"

namespace s3mm::module {
namespace {

class CephAdminProvider : public IAdminProvider {
public:
    const char* vendorName() const override { return "ceph"; }

    FeatureSet features() const override {
        FeatureSet f;
        f.credentials = false; // RGW admin ops live on their own port/API
        f.acl = true;          // RGW implements S3 ACLs
        f.bucketPolicy = true;
        f.versioning = true;
        f.tagging = true;
        f.inventory = false;
        f.iamPolicy = false;
        return f;
    }

    Result<std::vector<Account>> listAccounts() override {
        LOG_WARN("ceph: the RGW admin API is not exposed through this module yet");
        return Result<std::vector<Account>>::failure(
            "ceph: the RGW admin API is not exposed through this module yet");
    }
    Result<Account> getAccount(const std::string&) override {
        LOG_WARN("ceph: the RGW admin API is not exposed through this module yet");
        return Result<Account>::failure(
            "ceph: the RGW admin API is not exposed through this module yet");
    }
    Result<void> createAccount(const Account&) override {
        LOG_WARN("ceph: createAccount is not supported by this module");
        return Result<void>::failure("ceph: createAccount is not supported by this module");
    }
    Result<void> setSecret(const std::string&, const std::string&) override {
        LOG_WARN("ceph: setSecret is not supported by this module");
        return Result<void>::failure("ceph: setSecret is not supported by this module");
    }
    Result<void> setStatus(const std::string&, const std::string&) override {
        LOG_WARN("ceph: setStatus is not supported by this module");
        return Result<void>::failure("ceph: setStatus is not supported by this module");
    }
    Result<void> setBucketAccess(const std::string&,
                                 const std::map<std::string, std::string>&) override {
        LOG_WARN("ceph: setBucketAccess is not supported by this module");
        return Result<void>::failure("ceph: setBucketAccess is not supported by this module");
    }
    Result<void> addBucketAccess(const std::string&, const std::string&,
                                 const std::string&) override {
        LOG_WARN("ceph: addBucketAccess is not supported by this module");
        return Result<void>::failure("ceph: addBucketAccess is not supported by this module");
    }
    Result<void> removeBucketAccess(const std::string&, const std::string&) override {
        LOG_WARN("ceph: removeBucketAccess is not supported by this module");
        return Result<void>::failure("ceph: removeBucketAccess is not supported by this module");
    }
    Result<void> attachPolicy(const std::string&, const std::string&) override {
        LOG_WARN("ceph: attachPolicy is not supported by this module");
        return Result<void>::failure("ceph: attachPolicy is not supported by this module");
    }
    Result<void> deleteAccount(const std::string&) override {
        LOG_WARN("ceph: deleteAccount is not supported by this module");
        return Result<void>::failure("ceph: deleteAccount is not supported by this module");
    }
};

class CephModule : public IModule {
public:
    ModuleInfo info() const override { return {"ceph", S3MM_VERSION, "ceph"}; }

    Result<std::unique_ptr<IAdminProvider>> createAdmin(const s3::ClientOptions& opts,
                                                        const sigv4::Credentials& creds) override {
        LOG_INFO("ceph: admin provider created for ", opts.endpoints.empty() ? std::string("<no endpoint>") : opts.endpoints.front(),
                 " (access_key=", creds.accessKey, "; no admin plane, account operations unsupported)");
        return Result<std::unique_ptr<IAdminProvider>>(
            std::unique_ptr<IAdminProvider>(new CephAdminProvider()));
    }

    void adjustClientOptions(s3::ClientOptions& opts) override {
        opts.service = "s3";
        // RGW predates virtual-host style in many deployments: path style is
        // the safe default (the registry may still override it).
        opts.pathStyle = true;
        LOG_DEBUG("ceph: client options adjusted: service=", opts.service, " path_style=", opts.pathStyle);
    }
};

} // namespace

S3MM_MODULE_ENTRY(CephModule)

} // namespace s3mm::module
