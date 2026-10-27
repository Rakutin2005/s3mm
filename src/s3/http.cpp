#include "s3mm/s3/http.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <mutex>

#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::http {

void initGlobal() {
    static std::once_flag once;
    std::call_once(once, [] {
        CURLcode rc = curl_global_init(CURL_GLOBAL_ALL);
        if (rc != CURLE_OK) LOG_ERROR("http: curl_global_init failed: ", curl_easy_strerror(rc), " (code ", (int)rc, ")");
        else LOG_DEBUG("http: curl initialised: ", curl_version());
    });
}

static std::string redactUrl(const std::string& url) {
    static const char* sensitive[] = {"x-amz-signature", "x-amz-credential", "x-amz-security-token"};
    auto q = url.find('?');
    if (q == std::string::npos) return url;
    std::string out = url.substr(0, q + 1);
    size_t pos = q + 1;
    while (pos <= url.size()) {
        size_t amp = url.find('&', pos);
        std::string part = url.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        auto eq = part.find('=');
        std::string key = str::toLower(part.substr(0, eq));
        bool hide = false;
        for (const char* s : sensitive) hide = hide || key == s;
        out += (hide && eq != std::string::npos) ? part.substr(0, eq + 1) + "***" : part;
        if (amp == std::string::npos) break;
        out += '&';
        pos = amp + 1;
    }
    return out;
}

Client::Client() { initGlobal(); }
Client::~Client() = default;

std::string Response::errorText() const {
    if (!curlError.empty()) return curlError;
    return "HTTP " + std::to_string(status);
}

std::string urlEncode(const std::string& s, bool encodeSlash) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        bool unreserved = std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved || (c == '/' && !encodeSlash)) {
            out += (char)c;
            continue;
        }
        out += '%';
        out += hex[c >> 4];
        out += hex[c & 0xF];
    }
    return out;
}

std::string buildUrl(const std::string& base, const std::string& path,
                     const std::map<std::string, std::string>& query) {
    std::string out = base;
    if (!path.empty()) {
        while (!out.empty() && out.back() == '/') out.pop_back();
        if (path[0] != '/') out += "/";
        out += path;
    }
    if (!query.empty()) {
        size_t scheme = out.find("://");
        size_t slash = (scheme == std::string::npos) ? std::string::npos : out.find('/', scheme + 3);
        if (slash == std::string::npos) out += "/";
        out += "?";
        bool first = true;
        for (const auto& [k, v] : query) {
            if (!first) out += "&";
            first = false;
            out += urlEncode(k, true) + "=" + urlEncode(v, true);
        }
    }
    return out;
}

UrlParts parseUrl(const std::string& url) {
    UrlParts p;
    auto pos = url.find("://");
    if (pos == std::string::npos) return p;
    p.scheme = url.substr(0, pos);
    size_t start = pos + 3;
    size_t slash = url.find('/', start);
    std::string hostPort = url.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
    p.path = slash == std::string::npos ? "/" : url.substr(slash);
    auto colon = hostPort.rfind(':');
    if (colon != std::string::npos && hostPort.find(']') < colon) colon = std::string::npos; // ipv6 literal
    if (colon != std::string::npos) {
        p.host = hostPort.substr(0, colon);
        p.port = hostPort.substr(colon + 1);
    } else {
        p.host = hostPort;
        p.port = p.scheme == "https" ? "443" : "80";
    }
    p.valid = !p.host.empty();
    return p;
}

static size_t headerCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);
    size_t total = size * nitems;
    std::string line(buffer, total);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string key = str::toLower(str::trim(std::string_view(line).substr(0, colon)));
        std::string value = str::trim(std::string_view(line).substr(colon + 1));
        (*headers)[key] = value;
    }
    return total;
}

struct FileSinkState {
    std::FILE* file = nullptr;
    int64_t limit = 0;      // 0 = unlimited
    int64_t written = 0;
    bool overflow = false;
};

static size_t fileWriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* st = static_cast<FileSinkState*>(userdata);
    size_t total = size * nmemb;
    if (st->limit > 0 && st->written + (int64_t)total > st->limit) { // abort: response too large
        st->overflow = true;
        return 0;
    }
    size_t n = std::fwrite(ptr, 1, total, st->file);
    st->written += (int64_t)n;
    return n; // < total aborts the transfer
}

struct ReadState {
    std::FILE* file = nullptr;
    std::string buffer;
    size_t offset = 0;
};

static size_t readCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    auto* st = static_cast<ReadState*>(userdata);
    if (st->file) return std::fread(buffer, size, nitems, st->file);
    size_t avail = st->buffer.size() - st->offset;
    size_t want = size * nitems;
    size_t n = avail < want ? avail : want;
    if (n) std::memcpy(buffer, st->buffer.data() + st->offset, n);
    st->offset += n;
    return n;
}

Response Client::send(const Request& request) { return perform(request, nullptr); }

Response Client::downloadToFile(const Request& request, const std::string& path) {
    std::string tmp = path + ".part";
    LOG_DEBUG("http: download ", request.method, " ", redactUrl(request.url), " -> ", path);
    std::FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) {
        LOG_ERROR("http: cannot open download temp file ", tmp, " for writing: ", std::strerror(errno));
        Response r;
        r.curlError = "cannot open " + tmp + " for writing";
        return r;
    }
    Response r = perform(request, f);
    std::fclose(f);
    if (r.ok()) {
        if (std::rename(tmp.c_str(), path.c_str()) != 0) {
            LOG_ERROR("http: cannot rename ", tmp, " -> ", path, ": ", std::strerror(errno));
            r.status = 0;
            r.curlError = "cannot rename " + tmp;
        }
    } else {
        LOG_DEBUG("http: download to ", path, " failed (", r.errorText(), "), removing ", tmp);
        std::remove(tmp.c_str());
    }
    return r;
}

Response Client::perform(const Request& request, void* curlFile) {
    Response response;
    CURL* curl = curl_easy_init();
    if (!curl) {
        LOG_ERROR("http: curl_easy_init failed for ", request.method, " ", redactUrl(request.url));
        response.curlError = "curl_easy_init failed";
        return response;
    }

    // Unix-socket transport: an endpoint of the form
    //   unix:/path/to/sock#http://authority/path
    // connects through the socket but keeps a normal http:// URL for signing
    // and routing. s3mmc exposes each remote destination as such a socket, so
    // the core treats a cluster behind the mesh like any local S3 endpoint.
    std::string url = request.url;
    std::string unixSocketPath;
    if (url.rfind("unix:", 0) == 0) {
        auto hash = url.find('#');
        if (hash == std::string::npos) {
            LOG_ERROR("http: malformed unix endpoint (missing '#'): ", redactUrl(url));
            response.curlError = "malformed unix endpoint (missing '#'): " + url;
            curl_easy_cleanup(curl);
            return response;
        }
        unixSocketPath = url.substr(5, hash - 5);
        while (!unixSocketPath.empty() && unixSocketPath.front() == '/') unixSocketPath.erase(0, 1); // strip "unix://"
        url = url.substr(hash + 1);
        if (url.rfind("https://", 0) == 0) {
            // TLS over a UNIX socket is not meaningful here; s3mmc terminates
            // mTLS on its TCP side and speaks plain HTTP into the socket.
            url = "http://" + url.substr(8);
        }
    }

    // The query must be appended to the *effective* URL (after unix unwrapping),
    // otherwise buildUrl would choke on the "unix:" scheme.
    if (!request.query.empty()) url = buildUrl(url, "", request.query);

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    if (!unixSocketPath.empty()) {
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, unixSocketPath.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)request.timeoutSec);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)request.connectTimeoutSec);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "s3mm/0.1");
    char errbuf[CURL_ERROR_SIZE];
    errbuf[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

    const std::string logUrl = redactUrl(url);
    const char* transport = unixSocketPath.empty() ? "tcp" : "unix";
    LOG_DEBUG("http: ", request.method, " ", logUrl, " via ", transport,
              unixSocketPath.empty() ? std::string() : " socket=/" + unixSocketPath,
              " timeout=", request.timeoutSec, "s connect_timeout=", request.connectTimeoutSec, "s",
              request.insecure ? " tls_verify=off" : "",
              request.range.empty() ? std::string() : " range=" + request.range,
              request.bodyFile.empty() ? " body=" + std::to_string(request.body.size()) + "B" : " body_file=" + request.bodyFile,
              " headers=", request.headers.size(),
              request.maxResponseBytes > 0 ? " max_response=" + std::to_string(request.maxResponseBytes) : std::string());

    struct curl_slist* hdrs = nullptr;
    for (const auto& [k, v] : request.headers) hdrs = curl_slist_append(hdrs, (k + ": " + v).c_str());
    if (hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    if (request.insecure) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    // CURLOPT_RANGE expects "start-end"; the S3 "bytes=" unit belongs to the
    // wire header only and must not be passed to curl (curl adds it itself).
    std::string range = request.range;
    if (range.rfind("bytes=", 0) == 0) range.erase(0, std::strlen("bytes="));
    if (!range.empty()) curl_easy_setopt(curl, CURLOPT_RANGE, range.c_str());

    ReadState readState;
    if (!request.bodyFile.empty()) {
        readState.file = std::fopen(request.bodyFile.c_str(), "rb");
        if (!readState.file) {
            LOG_ERROR("http: cannot open body file ", request.bodyFile, " for ", request.method, " ", logUrl, ": ", std::strerror(errno));
            response.curlError = "cannot open body file " + request.bodyFile;
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(curl);
            return response;
        }
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallback);
        curl_easy_setopt(curl, CURLOPT_READDATA, &readState);
        struct stat st{};
        if (fstat(fileno(readState.file), &st) == 0) {
            curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)st.st_size);
            LOG_DEBUG("http: streaming body file ", request.bodyFile, " (", (long long)st.st_size, " bytes)");
        } else {
            LOG_WARN("http: fstat on body file ", request.bodyFile, " failed: ", std::strerror(errno), "; size unknown");
        }
    } else if (request.method == "POST" || request.method == "PUT" || request.method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)request.body.size());
    }
    if (request.method != "GET" && request.method != "POST" && request.method != "HEAD")
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request.method.c_str());
    else if (request.method == "HEAD")
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    std::string sink;
    struct SinkState {
        std::string* data;
        int64_t limit;
        bool overflow;
    } sinkState{&sink, request.maxResponseBytes, false};
    FileSinkState fileState{static_cast<std::FILE*>(curlFile), request.maxResponseBytes, 0, false};
    if (curlFile) {
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fileState);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fileWriteCallback);
    } else {
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sinkState);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            auto* st = static_cast<SinkState*>(userdata);
            size_t total = size * nmemb;
            if (st->limit > 0 && (int64_t)(st->data->size() + total) > st->limit) { // abort: response too large
                st->overflow = true;
                return 0;
            }
            st->data->append(ptr, total);
            return total;
        });
    }
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCallback);

    auto start = std::chrono::steady_clock::now();
    CURLcode rc = curl_easy_perform(curl);
    response.totalSeconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    if (readState.file) std::fclose(readState.file);
    if (rc != CURLE_OK) {
        response.status = 0;
        const bool tooLarge = rc == CURLE_WRITE_ERROR && (curlFile ? fileState.overflow : sinkState.overflow);
        response.curlError = tooLarge
            ? "response exceeds " + std::to_string(request.maxResponseBytes) + " bytes limit"
            : std::string(curl_easy_strerror(rc));
        LOG_ERROR("http: ", request.method, " ", logUrl, " via ", transport,
                  unixSocketPath.empty() ? std::string() : " (/" + unixSocketPath + ")",
                  " failed after ", (long long)(response.totalSeconds * 1000), " ms: curl error ", (int)rc, " ",
                  response.curlError, errbuf[0] ? std::string(" (") + errbuf + ")" : std::string(),
                  tooLarge ? std::string(" [") + curl_easy_strerror(rc) + "]" : std::string());
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
        int64_t size = curlFile ? fileState.written : (int64_t)sink.size();
        if (!curlFile) response.body = std::move(sink);
        long long ms = (long long)(response.totalSeconds * 1000);
        if (response.ok()) {
            LOG_DEBUG("http: ", request.method, " ", logUrl, " -> ", response.status, " ", size, " bytes in ", ms, " ms (", transport, ")");
        } else if (response.status == 404 && (request.method == "HEAD" || request.method == "GET")) {
            LOG_DEBUG("http: ", request.method, " ", logUrl, " -> 404 ", size, " bytes in ", ms, " ms (", transport, ")");
        } else {
            LOG_WARN("http: ", request.method, " ", logUrl, " -> HTTP ", response.status, " ", size, " bytes in ", ms, " ms (", transport, ")",
                     (!curlFile && !response.body.empty()) ? " body: " + log::clip(response.body) : std::string());
        }
    }
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return response;
}

} // namespace s3mm::http
