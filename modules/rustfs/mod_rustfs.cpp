// RustFS vendor module.
//
// RustFS speaks the S3 API; its own management API is separate from the data
// plane, so account operations degrade to a clear answer while the feature
// flags describe what the engine may rely on for the S3 data plane.
#include "s3mm/module/module.hpp"

namespace s3mm::module {
namespace {

class RustfsAdminProvider : public IAdminProvider {
public:
    const char* vendorName() const override { return "rustfs"; }

    FeatureSet features() const override {
        FeatureSet f;
        f.credentials = false; // the RustFS management API is a separate plane
        f.acl = false;         // conservative: rely on policies, not ACLs
        f.bucketPolicy = true;
        f.versioning = false;
        f.tagging = false;
        f.inventory = false;
        f.iamPolicy = false;
        return f;
    }

    Result<std::vector<Account>> listAccounts() override {
        return Result<std::vector<Account>>::failure(
            "rustfs: the management API is not exposed through this module yet");
    }
    Result<Account> getAccount(const std::string&) override {
        return Result<Account>::failure(
            "rustfs: the management API is not exposed through this module yet");
    }
    Result<void> createAccount(const Account&) override {
        return Result<void>::failure("rustfs: createAccount is not supported by this module");
    }
    Result<void> setSecret(const std::string&, const std::string&) override {
        return Result<void>::failure("rustfs: setSecret is not supported by this module");
    }
    Result<void> setStatus(const std::string&, const std::string&) override {
        return Result<void>::failure("rustfs: setStatus is not supported by this module");
    }
    Result<void> setBucketAccess(const std::string&,
                                 const std::map<std::string, std::string>&) override {
        return Result<void>::failure("rustfs: setBucketAccess is not supported by this module");
    }
    Result<void> addBucketAccess(const std::string&, const std::string&,
                                 const std::string&) override {
        return Result<void>::failure("rustfs: addBucketAccess is not supported by this module");
    }
    Result<void> removeBucketAccess(const std::string&, const std::string&) override {
        return Result<void>::failure("rustfs: removeBucketAccess is not supported by this module");
    }
    Result<void> attachPolicy(const std::string&, const std::string&) override {
        return Result<void>::failure("rustfs: attachPolicy is not supported by this module");
    }
    Result<void> deleteAccount(const std::string&) override {
        return Result<void>::failure("rustfs: deleteAccount is not supported by this module");
    }
};

class RustfsModule : public IModule {
public:
    ModuleInfo info() const override { return {"rustfs", S3MM_VERSION, "rustfs"}; }

    Result<std::unique_ptr<IAdminProvider>> createAdmin(const s3::ClientOptions&,
                                                        const sigv4::Credentials&) override {
        return Result<std::unique_ptr<IAdminProvider>>(
            std::unique_ptr<IAdminProvider>(new RustfsAdminProvider()));
    }

    void adjustClientOptions(s3::ClientOptions& opts) override {
        opts.service = "s3";
        opts.pathStyle = true;
    }
};

} // namespace

S3MM_MODULE_ENTRY(RustfsModule)

} // namespace s3mm::module
