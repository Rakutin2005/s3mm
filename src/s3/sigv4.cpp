#include "s3mm/s3/sigv4.hpp"

#include <algorithm>
#include <map>

#include "s3mm/common/crypto.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::sigv4 {

static std::string binaryHmac(const std::string& key, const std::string& data) {
    auto d = crypto::hmacSha256(key, data);
    return std::string(reinterpret_cast<const char*>(d.data()), d.size());
}

static std::string canonicalPath(const std::string& rawPath) {
    std::string path = rawPath.empty() ? "/" : rawPath;
    std::vector<std::string> segments = str::split(path, '/', false);
    std::vector<std::string> encoded;
    for (const auto& s : segments) encoded.push_back(http::urlEncode(s, true));
    std::string out = "/" + str::join(encoded, "/");
    if (!path.empty() && path.back() == '/' && out.back() != '/') out += '/';
    return out;
}

SigningResult signAt(http::Request& request, const Credentials& creds, const std::string& service,
                     const std::string& amzDateTime) {
    SigningResult out;
    out.amzDate = amzDateTime;
    std::string dateStamp = amzDateTime.substr(0, 8);

    auto parts = http::parseUrl(request.url);
    std::string host = parts.host;
    bool defaultPort = (parts.scheme == "https" && parts.port == "443") || (parts.scheme == "http" && parts.port == "80");
    if (!defaultPort && !parts.port.empty()) host += ":" + parts.port;

    // payload hash
    if (!request.payloadHash.empty()) out.payloadHash = request.payloadHash;
    else if (request.unsignedPayload || !request.bodyFile.empty()) out.payloadHash = "UNSIGNED-PAYLOAD";
    else out.payloadHash = crypto::sha256Hex(request.body);

    // canonical query string
    std::vector<std::string> queryParams;
    for (const auto& [k, v] : request.query)
        queryParams.push_back(http::urlEncode(k, true) + "=" + http::urlEncode(v, true));
    std::string canonicalQuery = str::join(queryParams, "&");

    // canonical headers: everything the caller set plus the signed x-amz headers
    std::map<std::string, std::string> headers;
    for (const auto& [k, v] : request.headers) {
        std::string key = str::toLower(str::trim(k));
        if (key == "authorization" || key == "content-length" || key == "expect" || key == "connection") continue;
        headers[key] = str::trim(v);
    }
    headers["host"] = host;
    headers["x-amz-content-sha256"] = out.payloadHash;
    headers["x-amz-date"] = amzDateTime;
    if (!creds.sessionToken.empty()) headers["x-amz-security-token"] = creds.sessionToken;
    if (!request.range.empty()) headers["range"] = str::trim(request.range);

    std::vector<std::string> headerNames;
    for (const auto& [k, v] : headers) headerNames.push_back(k);
    std::string signedHeaders = str::join(headerNames, ";");
    std::string canonicalHeaders;
    for (const auto& name : headerNames) canonicalHeaders += name + ":" + headers[name] + "\n";

    out.canonicalRequest = request.method + "\n" + canonicalPath(parts.path) + "\n" + canonicalQuery + "\n" +
                           canonicalHeaders + "\n" + signedHeaders + "\n" + out.payloadHash;
    out.signedHeaders = signedHeaders;

    std::string scope = dateStamp + "/" + creds.region + "/" + service + "/aws4_request";
    out.stringToSign = "AWS4-HMAC-SHA256\n" + amzDateTime + "\n" + scope + "\n" + crypto::sha256Hex(out.canonicalRequest);

    std::string kDate = binaryHmac("AWS4" + creds.secretKey, dateStamp);
    std::string kRegion = binaryHmac(kDate, creds.region);
    std::string kService = binaryHmac(kRegion, service);
    std::string kSigning = binaryHmac(kService, "aws4_request");
    out.signature = crypto::toHex(reinterpret_cast<const unsigned char*>(binaryHmac(kSigning, out.stringToSign).data()),
                                  32);

    out.authorization = "AWS4-HMAC-SHA256 Credential=" + creds.accessKey + "/" + scope +
                        ", SignedHeaders=" + signedHeaders + ", Signature=" + out.signature;

    request.headers["Host"] = host;
    request.headers["x-amz-content-sha256"] = out.payloadHash;
    request.headers["x-amz-date"] = amzDateTime;
    if (!creds.sessionToken.empty()) request.headers["x-amz-security-token"] = creds.sessionToken;
    request.headers["Authorization"] = out.authorization;
    return out;
}

SigningResult sign(http::Request& request, const Credentials& creds, const std::string& service, tm::TimePoint now) {
    return signAt(request, creds, service, tm::toIso8601(now).substr(0, 19) + "Z");
}

} // namespace s3mm::sigv4
