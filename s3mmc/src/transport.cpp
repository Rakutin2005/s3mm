#include "s3mm/transport.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <mutex>

#include "s3mm/common/crypto.hpp"
#include "s3mm/common/fs.hpp"

namespace s3mm::s3mmc {

namespace {

constexpr int64_t kIoTimeoutMs = 120'000; // per-frame read/write budget

bool writeAllRaw(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        pollfd p{fd, POLLOUT, 0};
        if (::poll(&p, 1, kIoTimeoutMs) <= 0) return false;
        ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

/// Allocate a unique spool file path inside `dir` (created on demand).
std::string allocSpoolPath(const std::string& dir) {
    static std::atomic<uint64_t> seq{0};
    std::string base = dir.empty() ? std::string("/tmp") : dir;
    fs::mkdirp(base);
    return base + "/s3mmc-spool-" + std::to_string((uint64_t)::time(nullptr)) + "-" +
           std::to_string(seq.fetch_add(1)) + ".bin";
}

} // namespace

// --------------------------------------------------------------- base impl --

Result<void> Channel::sendFile(Value frame, const std::string& filePath, const std::string& dataKey) {
    auto sz = fs::fileSize(filePath);
    if (!sz) return Result<void>::failure("spool: cannot stat '" + filePath + "'");
    if (*sz <= spoolThreshold_) {
        auto body = fs::readFile(filePath);
        if (!body) return Result<void>::failure("spool: cannot read '" + filePath + "'");
        Value payload = Value::object();
        payload.set("b64", Value::str(base64Encode(*body)));
        payload.set("bytes", Value::number((int64_t)*sz));
        frame.set(dataKey, payload);
        fs::removeFile(filePath);
        return send(frame);
    }
    Value payload = Value::object();
    payload.set("file", Value::str(filePath));
    payload.set("bytes", Value::number((int64_t)*sz));
    frame.set(dataKey, payload);
    return send(frame); // sender keeps the file until the receiver deletes it
}

void Channel::takeSpool(const std::string& path) {
    if (!path.empty()) fs::removeFile(path);
}

bool Channel::spliceToFile(int outFd, uint64_t expectedBytes, int64_t timeoutMs) {
    // Default: unsupported (TLS channels override this).
    (void)outFd; (void)expectedBytes; (void)timeoutMs;
    return false;
}

bool Channel::drainBytes(uint64_t n, int64_t timeoutMs) {
    (void)n; (void)timeoutMs;
    return false;
}

// ------------------------------------------------------------ unix channel --

namespace {

class UnixChannel : public Channel {
public:
    explicit UnixChannel(int fd) : fd_(fd) {}
    ~UnixChannel() override {
        if (fd_ >= 0) ::close(fd_);
    }
    int raw() const { return fd_; }

    Result<void> send(const Value& frame) override {
        std::lock_guard<std::mutex> lk(writeMutex_);
        std::string line = frame.toJson(); // escapeJson makes this newline-safe
        line.push_back('\n');
        if (!writeAllRaw(fd_, line.data(), line.size()))
            return Result<void>::failure("unix send failed");
        return Result<void>::success();
    }

    /// Read one length-prefixed binary blob (see core-side protocol) into a
    /// file descriptor. Layout: 8-byte big-endian length, then raw bytes.
    bool readBlobToFile(int outFd, uint64_t* blobLen, int64_t timeoutMs) {
        unsigned char hdr[8];
        if (!readRawExact(hdr, 8, timeoutMs)) return false;
        uint64_t len = 0;
        for (int i = 0; i < 8; ++i) len = (len << 8) | hdr[i];
        if (blobLen) *blobLen = len;
        return spliceToFile(outFd, len, timeoutMs);
    }

    /// Write one length-prefixed binary blob from a file.
    bool writeBlobFromFile(const std::string& path) {
        auto body = fs::readFile(path);
        if (!body) return false;
        uint64_t len = body->size();
        unsigned char hdr[8];
        for (int i = 7; i >= 0; --i) { hdr[i] = (unsigned char)(len & 0xFF); len >>= 8; }
        std::lock_guard<std::mutex> lk(writeMutex_);
        if (!writeAllRaw(fd_, (const char*)hdr, 8)) return false;
        return writeAllRaw(fd_, body->data(), body->size());
    }

    /// UNIX channels may reference spool files by path (same host): resolve
    /// {"file":...} payloads into a path the caller must takeSpool().
    Result<Value> recvFrame(std::string* spoolPathOut) override {
        std::string line;
        char buf[65536];
        for (;;) {
            pollfd p{fd_, POLLIN, 0};
            int pr = ::poll(&p, 1, kIoTimeoutMs);
            if (pr <= 0) return Result<Value>::failure(pr == 0 ? "unix recv timeout" : "unix recv interrupted");
            ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
            if (n == 0) return Result<Value>::failure("connection closed");
            if (n < 0) {
                if (errno == EINTR) continue;
                return Result<Value>::failure("unix recv failed");
            }
            line.append(buf, (size_t)n);
            auto nl = line.find('\n');
            if (nl != std::string::npos) {
                // buffer any surplus bytes for the next frame
                pending_.append(line.substr(nl + 1));
                line.resize(nl);
                std::string err;
                auto v = Value::parseJson(line, &err);
                if (!err.empty()) return Result<Value>::failure("frame parse: " + err);
                if (spoolPathOut) {
                    spoolPathOut->clear();
                    if (v.isObject()) {
                        if (const Value* d = v.find("data"); d && d->isObject()) {
                            std::string f = d->getString("file");
                            if (!f.empty() && fs::exists(f)) *spoolPathOut = f;
                        }
                    }
                }
                return Result<Value>(std::move(v));
            }
            if (line.size() > 64ull * 1024 * 1024)
                return Result<Value>::failure("frame too large");
        }
    }

    Result<Value> recv() override {
        // Serve from the buffered remainder first (frames can arrive glued).
        if (!pending_.empty()) {
            auto nl = pending_.find('\n');
            if (nl != std::string::npos) {
                std::string line = pending_.substr(0, nl);
                pending_.erase(0, nl + 1);
                std::string err;
                auto v = Value::parseJson(line, &err);
                if (!err.empty()) return Result<Value>::failure("frame parse: " + err);
                return Result<Value>(std::move(v));
            }
            std::string rest;
            char buf[65536];
            for (;;) {
                pollfd p{fd_, POLLIN, 0};
                int pr = ::poll(&p, 1, kIoTimeoutMs);
                if (pr <= 0) return Result<Value>::failure("unix recv timeout");
                ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
                if (n == 0) return Result<Value>::failure("connection closed");
                if (n < 0) { if (errno == EINTR) continue; return Result<Value>::failure("unix recv failed"); }
                pending_.append(buf, (size_t)n);
                auto nl2 = pending_.find('\n');
                if (nl2 != std::string::npos) {
                    std::string line = pending_.substr(0, nl2);
                    pending_.erase(0, nl2 + 1);
                    std::string err;
                    auto v = Value::parseJson(line, &err);
                    if (!err.empty()) return Result<Value>::failure("frame parse: " + err);
                    return Result<Value>(std::move(v));
                }
                if (pending_.size() > 64ull * 1024 * 1024) return Result<Value>::failure("frame too large");
            }
            (void)rest;
        }
        return recvFrame(nullptr);
    }

    /// Read exactly `len` raw bytes into a file descriptor.
    bool spliceToFile(int outFd, uint64_t expectedBytes, int64_t timeoutMs) override {
        uint64_t got = 0;
        char buf[65536];
        while (got < expectedBytes) {
            pollfd p{fd_, POLLIN, 0};
            if (::poll(&p, 1, timeoutMs) <= 0) return false;
            size_t want = (size_t)std::min<uint64_t>(sizeof(buf), expectedBytes - got);
            ssize_t n = ::recv(fd_, buf, want, 0);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                return false;
            }
            size_t off = 0;
            while (off < (size_t)n) {
                ssize_t w = ::write(outFd, buf + off, (size_t)n - off);
                if (w <= 0) return false;
                off += (size_t)w;
            }
            got += (uint64_t)n;
        }
        return true;
    }

    bool drainBytes(uint64_t n, int64_t timeoutMs) override {
        char buf[65536];
        while (n > 0) {
            pollfd p{fd_, POLLIN, 0};
            if (::poll(&p, 1, timeoutMs) <= 0) return false;
            size_t want = (size_t)std::min<uint64_t>(sizeof(buf), n);
            ssize_t r = ::recv(fd_, buf, want, 0);
            if (r <= 0) {
                if (r < 0 && errno == EINTR) continue;
                return false;
            }
            n -= (uint64_t)r;
        }
        return true;
    }

private:
    bool readRawExact(void* dst, size_t len, int64_t timeoutMs) {
        size_t got = 0;
        char* p = (char*)dst;
        while (got < len) {
            pollfd poll_{fd_, POLLIN, 0};
            if (::poll(&poll_, 1, timeoutMs) <= 0) return false;
            ssize_t n = ::recv(fd_, p + got, len - got, 0);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                return false;
            }
            got += (size_t)n;
        }
        return true;
    }

    int fd_ = -1;
    std::string pending_;          // bytes buffered past the last newline
    std::mutex writeMutex_;        // serialises frame/blob writers
};

// ---------------------------------------------------------------- tls chan --

class TlsChannel : public Channel {
public:
    TlsChannel(int fd, SSL* ssl) : fd_(fd), ssl_(ssl) {}
    ~TlsChannel() override {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        if (fd_ >= 0) ::close(fd_);
    }

    Result<void> send(const Value& frame) override {
        std::string line = frame.toJson();
        for (auto& ch : line)
            if (ch == '\n') ch = ' ';
        line.push_back('\n');
        size_t off = 0;
        while (off < line.size()) {
            pollfd p{fd_, POLLOUT, 0};
            if (::poll(&p, 1, kIoTimeoutMs) <= 0) return Result<void>::failure("tls send timeout");
            int n = SSL_write(ssl_, line.data() + off, (int)(line.size() - off));
            if (n <= 0) {
                int err = SSL_get_error(ssl_, n);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) continue;
                return Result<void>::failure("tls send failed");
            }
            off += (size_t)n;
        }
        return Result<void>::success();
    }

    Result<Value> recvFrame(std::string* spoolPathOut) override {
        std::string line;
        char buf[65536];
        for (;;) {
            pollfd p{fd_, POLLIN, 0};
            int pr = ::poll(&p, 1, kIoTimeoutMs);
            if (pr <= 0) return Result<Value>::failure(pr == 0 ? "tls recv timeout" : "tls recv interrupted");
            int n = SSL_read(ssl_, buf, sizeof(buf));
            if (n <= 0) {
                int err = SSL_get_error(ssl_, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                return Result<Value>::failure("tls recv failed / closed");
            }
            line.append(buf, (size_t)n);
            auto nl = line.find('\n');
            if (nl != std::string::npos) {
                line.resize(nl);
                std::string err;
                auto v = Value::parseJson(line, &err);
                if (!err.empty()) return Result<Value>::failure("frame parse: " + err);
                // Spooled payloads arrive as {"file": local-path}: on TCP we
                // never share paths, so a remote peer must inline data. The
                // "file" form is only produced/consumed over UNIX sockets.
                if (spoolPathOut) spoolPathOut->clear();
                return Result<Value>(std::move(v));
            }
            if (line.size() > 64ull * 1024 * 1024)
                return Result<Value>::failure("peer frame too large");
        }
    }

    Result<Value> recv() override { return recvFrame(nullptr); }

    /// Stream the TLS record body straight into a local file.
    bool spliceToFile(int outFd, uint64_t expectedBytes, int64_t timeoutMs) override {
        uint64_t got = 0;
        char buf[65536];
        while (got < expectedBytes) {
            pollfd p{fd_, POLLIN, 0};
            if (::poll(&p, 1, timeoutMs) <= 0) return false;
            int n = SSL_read(ssl_, buf, sizeof(buf));
            if (n <= 0) {
                int err = SSL_get_error(ssl_, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                return false;
            }
            size_t off = 0;
            while (off < (size_t)n) {
                ssize_t w = ::write(outFd, buf + off, (size_t)n - off);
                if (w <= 0) return false;
                off += (size_t)w;
            }
            got += (size_t)n;
        }
        return true;
    }

private:
    int fd_ = -1;
    SSL* ssl_ = nullptr;

public:
    /// CN of the counterparty certificate (empty when absent).
    std::string peerCommonName() const {
        if (!ssl_) return {};
        X509* cert = SSL_get1_peer_certificate(ssl_);
        if (!cert) return {};
        std::string cn;
        X509_NAME* subj = X509_get_subject_name(cert);
        int idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
        if (idx >= 0) {
            X509_NAME_ENTRY* ent = X509_NAME_get_entry(subj, idx);
            ASN1_STRING* data = X509_NAME_ENTRY_get_data(ent);
            unsigned char* utf8 = nullptr;
            int len = ASN1_STRING_to_UTF8(&utf8, data);
            if (len >= 0 && utf8) {
                cn.assign(reinterpret_cast<const char*>(utf8), (size_t)len);
                OPENSSL_free(utf8);
            }
        }
        X509_free(cert);
        return cn;
    }
};

} // namespace

Result<std::shared_ptr<Channel>> makeUnixChannel(int fd) {
    return Result<std::shared_ptr<Channel>>(std::make_shared<UnixChannel>(fd));
}

Result<std::shared_ptr<Channel>> makeTlsChannel(int fd, bool clientRole, const std::string& certFile,
                                                const std::string& keyFile, const std::string& caFile) {
    // Per-material contexts: a static shared ctx would silently reuse the
    // first-loaded cert/CA when several ClusterClient instances (tests) or
    // live TLS reconfiguration are involved.
    static std::mutex ctxMutex;
    static std::map<std::string, SSL_CTX*> ctxCache;
    std::string key = (clientRole ? "c|" : "s|") + certFile + "|" + keyFile + "|" + caFile;
    SSL_CTX* ctx = nullptr;
    {
        std::lock_guard<std::mutex> lk(ctxMutex);
        auto it = ctxCache.find(key);
        if (it != ctxCache.end()) ctx = it->second;
    }
    if (!ctx) {
        SSL_CTX* fresh = SSL_CTX_new(clientRole ? TLS_client_method() : TLS_server_method());
        if (!fresh) return Result<std::shared_ptr<Channel>>::failure("SSL_CTX_new failed");
        bool ok = true;
        if (!certFile.empty() && !keyFile.empty()) {
            ok &= SSL_CTX_use_certificate_file(fresh, certFile.c_str(), SSL_FILETYPE_PEM) == 1;
            ok &= SSL_CTX_use_PrivateKey_file(fresh, keyFile.c_str(), SSL_FILETYPE_PEM) == 1;
            ok &= SSL_CTX_check_private_key(fresh) == 1;
        }
        if (ok && !caFile.empty()) {
            ok = SSL_CTX_load_verify_locations(fresh, caFile.c_str(), nullptr) == 1;
            // mTLS: always verify the counterparty against our CA.
            SSL_CTX_set_verify(fresh, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        } else if (ok) {
            SSL_CTX_set_verify(fresh, SSL_VERIFY_NONE, nullptr);
        }
        if (!ok) {
            SSL_CTX_free(fresh);
            return Result<std::shared_ptr<Channel>>::failure(
                "TLS context setup failed (cert=" + certFile + " key=" + keyFile + " ca=" + caFile + ")");
        }
        ctx = fresh;
        std::lock_guard<std::mutex> lk(ctxMutex);
        auto res = ctxCache.emplace(key, ctx);
        if (!res.second) {           // lost a race — keep the winner, free ours
            SSL_CTX_free(ctx);
            ctx = res.first->second;
        }
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) return Result<std::shared_ptr<Channel>>::failure("SSL_new failed");
    SSL_set_fd(ssl, fd);
    if (clientRole) SSL_set_tlsext_host_name(ssl, "s3mmc-peer.local"); // stable SNI, no hostname check
    int rc = clientRole ? SSL_connect(ssl) : SSL_accept(ssl);
    if (rc <= 0) {
        unsigned long e = ERR_get_error();
        char eb[256] = {};
        ERR_error_string_n(e, eb, sizeof(eb));
        SSL_free(ssl);
        return Result<std::shared_ptr<Channel>>::failure(std::string("TLS handshake failed: ") + eb);
    }
    return Result<std::shared_ptr<Channel>>(std::make_shared<TlsChannel>(fd, ssl));
}

std::string tlsPeerCommonName(const std::shared_ptr<Channel>& ch) {
    auto* tls = dynamic_cast<TlsChannel*>(ch.get());
    return tls ? tls->peerCommonName() : std::string();
}

} // namespace s3mm::s3mmc
