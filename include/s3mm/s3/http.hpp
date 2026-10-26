#pragma once
#include <map>
#include <string>
#include <vector>

namespace s3mm::http {

struct Response {
    long status = 0;
    std::map<std::string, std::string> headers; // lower-cased keys, last value wins
    std::string body;
    std::string curlError;
    double totalSeconds = 0;

    bool ok() const { return status >= 200 && status < 300; }
    bool transportError() const { return status == 0; }
    std::string header(const std::string& lowerName) const {
        auto it = headers.find(lowerName);
        return it == headers.end() ? std::string() : it->second;
    }
    std::string errorText() const;
};

struct Request {
    std::string method = "GET";
    std::string url;                                 // scheme://host[:port]/path, or unix:/path/to/sock#scheme://host:port/path
    std::map<std::string, std::string> query;        // sorted at send time
    std::map<std::string, std::string> headers;      // header name -> value
    std::string body;                                // in-memory body
    std::string bodyFile;                            // streamed body (mutually exclusive with body)
    std::string payloadHash;                         // pre-computed x-amz-content-sha256 (optional)
    bool unsignedPayload = false;                    // use UNSIGNED-PAYLOAD for streaming uploads
    std::string range;                               // Range header, e.g. "bytes=0-8191"
    bool insecure = false;                           // disable TLS verification
    int timeoutSec = 120;
    int connectTimeoutSec = 10;
    int64_t maxResponseBytes = 0;                    // 0 = unlimited
};

/// Percent-encode according to RFC 3986 (S3 flavour: '/' kept or encoded by flag).
std::string urlEncode(const std::string& s, bool encodeSlash);

/// scheme://host[:port]/path?query=k=v&... (query values are encoded).
std::string buildUrl(const std::string& base, const std::string& path,
                     const std::map<std::string, std::string>& query);

/// Parse "scheme://host[:port]" into parts.
struct UrlParts {
    std::string scheme, host, port, path;
    bool valid = false;
};
UrlParts parseUrl(const std::string& url);

class Client {
public:
    Client();
    ~Client();
    Response send(const Request& request);
    /// Streaming download; writes to path only on HTTP 2xx.
    Response downloadToFile(const Request& request, const std::string& path);

private:
    Response perform(const Request& request, void* curlFile);
};

/// Global one-time curl initialisation (idempotent).
void initGlobal();

} // namespace s3mm::http
