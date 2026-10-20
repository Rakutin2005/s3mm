#pragma once
#include <string>

#include "s3mm/common/time.hpp"
#include "s3mm/s3/http.hpp"

namespace s3mm::sigv4 {

struct Credentials {
    std::string accessKey;
    std::string secretKey;
    std::string sessionToken;
    std::string region = "us-east-1";
};

struct SigningResult {
    std::string canonicalRequest;
    std::string stringToSign;
    std::string signature;
    std::string authorization;
    std::string signedHeaders;
    std::string amzDate;
    std::string payloadHash;
};

/// Sign `request` in place (adds x-amz-date, x-amz-content-sha256, x-amz-security-token,
/// Authorization). `service` is "s3" for data plane, "iam"/"minio" for admin planes.
SigningResult sign(http::Request& request, const Credentials& creds, const std::string& service,
                   tm::TimePoint now = tm::now());

/// Deterministic variant used by unit tests (fixed timestamp, no side effects on clocks).
SigningResult signAt(http::Request& request, const Credentials& creds, const std::string& service,
                     const std::string& amzDateTime);

} // namespace s3mm::sigv4
