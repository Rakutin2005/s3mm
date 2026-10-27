// AWS S3 vendor module.
//
// AWS-specific behaviour beyond the generic S3 data plane:
//  - no local admin plane on the cluster itself (accounts live in IAM and are
//    not managed through this module), so account operations degrade to a
//    clear "not supported" answer while the feature flags tell the engine
//    which bucket-level features it may rely on;
//  - S3 Inventory is available on AWS (used for delta detection).
#include "s3mm/module/module.hpp"

#include "s3mm/common/log.hpp"

namespace s3mm::module {
namespace {

class AwsAdminProvider : public IAdminProvider {
public:
    const char* vendorName() const override { return "aws"; }

    FeatureSet features() const override {
        FeatureSet f;
        f.credentials = false;  // IAM is not reachable through the S3 endpoint
        f.acl = true;
        f.bucketPolicy = true;
        f.versioning = true;
        f.tagging = true;
        f.inventory = true;     // S3 Inventory reports
        f.iamPolicy = false;
        return f;
    }

    Result<std::vector<Account>> listAccounts() override {
        LOG_WARN("aws: account management is not supported through the S3 endpoint (use IAM)");
        return Result<std::vector<Account>>::failure(
            "aws: account management is not supported through the S3 endpoint (use IAM)");
    }
    Result<Account> getAccount(const std::string&) override {
        LOG_WARN("aws: account management is not supported through the S3 endpoint (use IAM)");
        return Result<Account>::failure(
            "aws: account management is not supported through the S3 endpoint (use IAM)");
    }
    Result<void> createAccount(const Account&) override {
        LOG_WARN("aws: createAccount is not supported (use IAM)");
        return Result<void>::failure("aws: createAccount is not supported (use IAM)");
    }
    Result<void> setSecret(const std::string&, const std::string&) override {
        LOG_WARN("aws: setSecret is not supported (use IAM)");
        return Result<void>::failure("aws: setSecret is not supported (use IAM)");
    }
    Result<void> setStatus(const std::string&, const std::string&) override {
        LOG_WARN("aws: setStatus is not supported (use IAM)");
        return Result<void>::failure("aws: setStatus is not supported (use IAM)");
    }
    Result<void> setBucketAccess(const std::string&, const std::map<std::string, std::string>&) override {
        LOG_WARN("aws: setBucketAccess is not supported (use bucket policies)");
        return Result<void>::failure("aws: setBucketAccess is not supported (use bucket policies)");
    }
    Result<void> addBucketAccess(const std::string&, const std::string&, const std::string&) override {
        LOG_WARN("aws: addBucketAccess is not supported (use bucket policies)");
        return Result<void>::failure("aws: addBucketAccess is not supported (use bucket policies)");
    }
    Result<void> removeBucketAccess(const std::string&, const std::string&) override {
        LOG_WARN("aws: removeBucketAccess is not supported (use bucket policies)");
        return Result<void>::failure("aws: removeBucketAccess is not supported (use bucket policies)");
    }
    Result<void> attachPolicy(const std::string&, const std::string&) override {
        LOG_WARN("aws: attachPolicy is not supported (use IAM)");
        return Result<void>::failure("aws: attachPolicy is not supported (use IAM)");
    }
    Result<void> deleteAccount(const std::string&) override {
        LOG_WARN("aws: deleteAccount is not supported (use IAM)");
        return Result<void>::failure("aws: deleteAccount is not supported (use IAM)");
    }
};

class AwsModule : public IModule {
public:
    ModuleInfo info() const override { return {"aws", S3MM_VERSION, "aws"}; }

    Result<std::unique_ptr<IAdminProvider>> createAdmin(const s3::ClientOptions& opts,
                                                        const sigv4::Credentials& creds) override {
        LOG_INFO("aws: admin provider created for ", opts.endpoints.empty() ? std::string("<no endpoint>") : opts.endpoints.front(),
                 " (access_key=", creds.accessKey, "; no admin plane, account operations unsupported)");
        return Result<std::unique_ptr<IAdminProvider>>(
            std::unique_ptr<IAdminProvider>(new AwsAdminProvider()));
    }

    void adjustClientOptions(s3::ClientOptions& opts) override {
        // The registry already chooses virtual-host vs path style per cluster;
        // AWS needs nothing beyond the generic data plane.
        opts.service = "s3";
        LOG_DEBUG("aws: client options adjusted: service=", opts.service);
    }
};

} // namespace

S3MM_MODULE_ENTRY(AwsModule)

} // namespace s3mm::module
