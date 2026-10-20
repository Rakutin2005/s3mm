#include "s3mm/s3/http.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>

#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>

#include "s3mm/common/str.hpp"

namespace s3mm::http {

void initGlobal() {
    static std::once_flag once;
    std::call_once(once, [] { curl_global_init(CURL_GLOBAL_ALL); });
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

static size_t fileWriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* f = static_cast<std::FILE*>(userdata);
    return std::fwrite(ptr, size, nmemb, f);
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
    std::FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) {
        Response r;
        r.curlError = "cannot open " + tmp + " for writing";
        return r;
    }
    Response r = perform(request, f);
    std::fclose(f);
    if (r.ok()) {
        if (std::rename(tmp.c_str(), path.c_str()) != 0) {
            r.status = 0;
            r.curlError = "cannot rename " + tmp;
        }
    } else {
        std::remove(tmp.c_str());
    }
    return r;
}

Response Client::perform(const Request& request, void* curlFile) {
    Response response;
    CURL* curl = curl_easy_init();
    if (!curl) {
        response.curlError = "curl_easy_init failed";
        return response;
    }

    std::string url = request.url;
    if (!request.query.empty()) url = buildUrl(request.url, "", request.query);

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)request.timeoutSec);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)request.connectTimeoutSec);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "s3mm/0.1");

    struct curl_slist* hdrs = nullptr;
    for (const auto& [k, v] : request.headers) hdrs = curl_slist_append(hdrs, (k + ": " + v).c_str());
    if (hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    if (request.insecure) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    if (!request.range.empty()) curl_easy_setopt(curl, CURLOPT_RANGE, request.range.c_str());

    ReadState readState;
    if (!request.bodyFile.empty()) {
        readState.file = std::fopen(request.bodyFile.c_str(), "rb");
        if (!readState.file) {
            response.curlError = "cannot open body file " + request.bodyFile;
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(curl);
            return response;
        }
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallback);
        curl_easy_setopt(curl, CURLOPT_READDATA, &readState);
        struct stat st{};
        if (fstat(fileno(readState.file), &st) == 0) curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)st.st_size);
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
    } sinkState{&sink, request.maxResponseBytes};
    if (curlFile) {
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, curlFile);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fileWriteCallback);
    } else {
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sinkState);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            auto* st = static_cast<SinkState*>(userdata);
            size_t total = size * nmemb;
            if (st->limit > 0 && (int64_t)(st->data->size() + total) > st->limit) return 0; // abort: response too large
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
        response.curlError = curl_easy_strerror(rc);
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
        if (!curlFile) response.body = std::move(sink);
    }
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return response;
}

} // namespace s3mm::http
