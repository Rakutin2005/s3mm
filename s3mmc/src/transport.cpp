#include "s3mm/transport.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>

#include "s3mm/common/crypto.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"

namespace s3mm::s3mmc {

namespace {

constexpr int64_t kIoTimeoutMs = 120'000; // per-frame read/write budget

std::string frameKind(const Value& v) {
    if (!v.isObject()) return "?";
    std::string t = v.getString("type");
    if (t.empty()) t = v.getString("cmd");
    if (t.empty()) t = v.getString("op");
    return t.empty() ? std::string("?") : t;
}

/// Drain the OpenSSL error queue into one readable string.
std::string sslErrors() {
    std::string out;
    while (unsigned long e = ERR_get_error()) {
        char eb[256] = {};
        ERR_error_string_n(e, eb, sizeof(eb));
        if (!out.empty()) out += "; ";
        out += eb;
    }
    return out.empty() ? std::string("no OpenSSL error queued") : out;
}

bool writeAllRaw(int fd, const char* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        pollfd p{fd, POLLOUT, 0};
        int pr = ::poll(&p, 1, kIoTimeoutMs);
        if (pr <= 0) {
            LOG_ERROR("transport: fd ", fd, " write ", pr == 0 ? "timeout" : std::strerror(errno), " after ", off, "/", len, " bytes");
            return false;
        }
        ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            LOG_ERROR("transport: fd ", fd, " send failed after ", off, "/", len, " bytes: ",
                      n < 0 ? std::strerror(errno) : "peer closed");
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

} // namespace

// --------------------------------------------------------------- base impl --

Result<void> Channel::sendFile(Value frame, const std::string& filePath, const std::string& dataKey) {
    auto sz = fs::fileSize(filePath);
    if (!sz) {
        LOG_ERROR("transport: sendFile ", frameKind(frame), ": cannot stat spool '", filePath, "'");
        return Result<void>::failure("spool: cannot stat '" + filePath + "'");
    }
    if (*sz <= spoolThreshold_) {
        auto body = fs::readFile(filePath);
        if (!body) {
            LOG_ERROR("transport: sendFile ", frameKind(frame), ": cannot read spool '", filePath, "'");
            return Result<void>::failure("spool: cannot read '" + filePath + "'");
        }
        LOG_DEBUG("transport: sendFile ", frameKind(frame), ": inlining ", *sz, " bytes from '", filePath,
                  "' as base64 (threshold ", spoolThreshold_, ")");
        Value payload = Value::object();
        payload.set("b64", Value::str(s3mm::crypto::base64Encode(*body)));
        payload.set("bytes", Value::number((int64_t)*sz));
        frame.set(dataKey, payload);
        fs::removeFile(filePath);
        return send(frame);
    }
    LOG_DEBUG("transport: sendFile ", frameKind(frame), ": spool reference '", filePath, "' ", *sz,
              " bytes (threshold ", spoolThreshold_, ")");
    Value payload = Value::object();
    payload.set("file", Value::str(filePath));
    payload.set("bytes", Value::number((int64_t)*sz));
    frame.set(dataKey, payload);
    return send(frame); // sender keeps the file until the receiver deletes it
}

void Channel::takeSpool(const std::string& path) {
    if (path.empty()) return;
    LOG_DEBUG("transport: removing consumed spool '", path, "'");
    if (!fs::removeFile(path) && fs::exists(path)) LOG_WARN("transport: cannot remove spool '", path, "'");
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
        if (!writeAllRaw(fd_, line.data(), line.size())) {
            LOG_ERROR("transport: unix fd ", fd_, " send of '", frameKind(frame), "' (", line.size(), " bytes) failed");
            return Result<void>::failure("unix send failed");
        }
        LOG_DEBUG("transport: unix fd ", fd_, " sent '", frameKind(frame), "' ", line.size(), " bytes");
        return Result<void>::success();
    }

    /// Read one length-prefixed binary blob (see core-side protocol) into a
    /// file descriptor. Layout: 8-byte big-endian length, then raw bytes.
    bool readBlobToFile(int outFd, uint64_t* blobLen, int64_t timeoutMs) {
        unsigned char hdr[8];
        if (!readRawExact(hdr, 8, timeoutMs)) {
            LOG_ERROR("transport: unix fd ", fd_, " blob header read failed");
            return false;
        }
        uint64_t len = 0;
        for (int i = 0; i < 8; ++i) len = (len << 8) | hdr[i];
        if (blobLen) *blobLen = len;
        LOG_DEBUG("transport: unix fd ", fd_, " receiving blob of ", len, " bytes");
        return spliceToFile(outFd, len, timeoutMs);
    }

    /// Write one length-prefixed binary blob from a file.
    bool writeBlobFromFile(const std::string& path) {
        auto body = fs::readFile(path);
        if (!body) {
            LOG_ERROR("transport: unix fd ", fd_, " cannot read blob source '", path, "'");
            return false;
        }
        LOG_DEBUG("transport: unix fd ", fd_, " sending blob '", path, "' ", body->size(), " bytes");
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
        char buf[65536];
        for (;;) {
            // Serve from the buffered remainder first (frames can arrive glued).
            auto nl = pending_.find('\n');
            if (nl != std::string::npos) {
                std::string line = pending_.substr(0, nl);
                pending_.erase(0, nl + 1);
                if (!pending_.empty())
                    LOG_DEBUG("transport: unix fd ", fd_, " keeping ", pending_.size(), " bytes past frame end");
                std::string err;
                auto v = Value::parseJson(line, &err);
                if (!err.empty()) {
                    LOG_ERROR("transport: unix fd ", fd_, " frame parse error: ", err, " (", log::clip(line), ")");
                    return Result<Value>::failure("frame parse: " + err);
                }
                LOG_DEBUG("transport: unix fd ", fd_, " received '", frameKind(v), "' ", line.size(), " bytes");
                if (spoolPathOut) {
                    spoolPathOut->clear();
                    if (v.isObject()) {
                        if (const Value* d = v.find("data"); d && d->isObject()) {
                            std::string f = d->getString("file");
                            if (!f.empty() && fs::exists(f)) *spoolPathOut = f;
                            else if (!f.empty()) LOG_WARN("transport: unix fd ", fd_, " spool reference '", f, "' does not exist");
                        }
                    }
                }
                return Result<Value>(std::move(v));
            }
            if (pending_.size() > 64ull * 1024 * 1024) {
                LOG_ERROR("transport: unix fd ", fd_, " frame too large (", pending_.size(), " bytes without newline)");
                return Result<Value>::failure("frame too large");
            }
            pollfd p{fd_, POLLIN, 0};
            int pr = ::poll(&p, 1, kIoTimeoutMs);
            if (pr <= 0) {
                LOG_WARN("transport: unix fd ", fd_, " recv ", pr == 0 ? "timeout" : "interrupted",
                         " (", pending_.size(), " bytes buffered)");
                return Result<Value>::failure(pr == 0 ? "unix recv timeout" : "unix recv interrupted");
            }
            ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
            if (n == 0) {
                LOG_DEBUG("transport: unix fd ", fd_, " closed by peer");
                return Result<Value>::failure("connection closed");
            }
            if (n < 0) {
                if (errno == EINTR) continue;
                LOG_ERROR("transport: unix fd ", fd_, " recv failed: ", std::strerror(errno));
                return Result<Value>::failure("unix recv failed");
            }
            pending_.append(buf, (size_t)n);
        }
    }

    Result<Value> recv() override { return recvFrame(nullptr); }

    /// Read exactly `len` raw bytes into a file descriptor.
    bool spliceToFile(int outFd, uint64_t expectedBytes, int64_t timeoutMs) override {
        uint64_t got = 0;
        char buf[65536];
        log::Stopwatch sw;
        while (got < expectedBytes) {
            pollfd p{fd_, POLLIN, 0};
            if (::poll(&p, 1, timeoutMs) <= 0) {
                LOG_ERROR("transport: unix fd ", fd_, " splice timeout at ", got, "/", expectedBytes, " bytes");
                return false;
            }
            size_t want = (size_t)std::min<uint64_t>(sizeof(buf), expectedBytes - got);
            ssize_t n = ::recv(fd_, buf, want, 0);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                LOG_ERROR("transport: unix fd ", fd_, " splice recv failed at ", got, "/", expectedBytes, " bytes: ",
                          n < 0 ? std::strerror(errno) : "peer closed");
                return false;
            }
            size_t off = 0;
            while (off < (size_t)n) {
                ssize_t w = ::write(outFd, buf + off, (size_t)n - off);
                if (w <= 0) {
                    LOG_ERROR("transport: unix fd ", fd_, " splice write to fd ", outFd, " failed: ", std::strerror(errno));
                    return false;
                }
                off += (size_t)w;
            }
            got += (uint64_t)n;
        }
        LOG_DEBUG("transport: unix fd ", fd_, " spliced ", got, " bytes in ", sw.ms(), " ms");
        return true;
    }

    bool drainBytes(uint64_t n, int64_t timeoutMs) override {
        char buf[65536];
        LOG_DEBUG("transport: unix fd ", fd_, " draining ", n, " bytes");
        while (n > 0) {
            pollfd p{fd_, POLLIN, 0};
            if (::poll(&p, 1, timeoutMs) <= 0) {
                LOG_ERROR("transport: unix fd ", fd_, " drain timeout with ", n, " bytes left");
                return false;
            }
            size_t want = (size_t)std::min<uint64_t>(sizeof(buf), n);
            ssize_t r = ::recv(fd_, buf, want, 0);
            if (r <= 0) {
                if (r < 0 && errno == EINTR) continue;
                LOG_ERROR("transport: unix fd ", fd_, " drain failed with ", n, " bytes left: ",
                          r < 0 ? std::strerror(errno) : "peer closed");
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
            if (::poll(&poll_, 1, timeoutMs) <= 0) {
                LOG_ERROR("transport: unix fd ", fd_, " read timeout at ", got, "/", len, " bytes");
                return false;
            }
            ssize_t n = ::recv(fd_, p + got, len - got, 0);
            if (n <= 0) {
                if (n < 0 && errno == EINTR) continue;
                LOG_ERROR("transport: unix fd ", fd_, " read failed at ", got, "/", len, " bytes: ",
                          n < 0 ? std::strerror(errno) : "peer closed");
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
        LOG_DEBUG("transport: tls fd ", fd_, " closing session");
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
            if (::poll(&p, 1, kIoTimeoutMs) <= 0) {
                LOG_ERROR("transport: tls fd ", fd_, " send timeout for '", frameKind(frame), "' at ", off, "/", line.size(), " bytes");
                return Result<void>::failure("tls send timeout");
            }
            int n = SSL_write(ssl_, line.data() + off, (int)(line.size() - off));
            if (n <= 0) {
                int err = SSL_get_error(ssl_, n);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) continue;
                LOG_ERROR("transport: tls fd ", fd_, " SSL_write of '", frameKind(frame), "' failed (ssl error ", err,
                          "): ", sslErrors());
                return Result<void>::failure("tls send failed");
            }
            off += (size_t)n;
        }
        LOG_DEBUG("transport: tls fd ", fd_, " sent '", frameKind(frame), "' ", line.size(), " bytes");
        return Result<void>::success();
    }

    Result<Value> recvFrame(std::string* spoolPathOut) override {
        char buf[65536];
        for (;;) {
            auto nl = pending_.find('\n');
            if (nl != std::string::npos) {
                std::string line = pending_.substr(0, nl);
                pending_.erase(0, nl + 1);
                if (!pending_.empty())
                    LOG_DEBUG("transport: tls fd ", fd_, " keeping ", pending_.size(), " bytes past frame end");
                std::string err;
                auto v = Value::parseJson(line, &err);
                if (!err.empty()) {
                    LOG_ERROR("transport: tls fd ", fd_, " frame parse error: ", err, " (", log::clip(line), ")");
                    return Result<Value>::failure("frame parse: " + err);
                }
                LOG_DEBUG("transport: tls fd ", fd_, " received '", frameKind(v), "' ", line.size(), " bytes");
                // Spooled payloads arrive as {"file": local-path}: on TCP we
                // never share paths, so a remote peer must inline data. The
                // "file" form is only produced/consumed over UNIX sockets.
                if (spoolPathOut) spoolPathOut->clear();
                return Result<Value>(std::move(v));
            }
            if (pending_.size() > 64ull * 1024 * 1024) {
                LOG_ERROR("transport: tls fd ", fd_, " peer frame too large (", pending_.size(), " bytes without newline)");
                return Result<Value>::failure("peer frame too large");
            }
            // SSL may hold already-decrypted bytes the socket poll cannot see.
            if (SSL_pending(ssl_) <= 0) {
                pollfd p{fd_, POLLIN, 0};
                int pr = ::poll(&p, 1, kIoTimeoutMs);
                if (pr <= 0) {
                    LOG_WARN("transport: tls fd ", fd_, " recv ", pr == 0 ? "timeout" : "interrupted",
                             " (", pending_.size(), " bytes buffered)");
                    return Result<Value>::failure(pr == 0 ? "tls recv timeout" : "tls recv interrupted");
                }
            }
            int n = SSL_read(ssl_, buf, sizeof(buf));
            if (n <= 0) {
                int err = SSL_get_error(ssl_, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                if (err == SSL_ERROR_ZERO_RETURN || (err == SSL_ERROR_SYSCALL && n == 0))
                    LOG_DEBUG("transport: tls fd ", fd_, " closed by peer");
                else
                    LOG_ERROR("transport: tls fd ", fd_, " SSL_read failed (ssl error ", err, "): ", sslErrors());
                return Result<Value>::failure("tls recv failed / closed");
            }
            pending_.append(buf, (size_t)n);
        }
    }

    Result<Value> recv() override { return recvFrame(nullptr); }

    /// Stream the TLS record body straight into a local file.
    bool spliceToFile(int outFd, uint64_t expectedBytes, int64_t timeoutMs) override {
        uint64_t got = 0;
        char buf[65536];
        log::Stopwatch sw;
        if (!pending_.empty()) {
            size_t take = (size_t)std::min<uint64_t>(pending_.size(), expectedBytes);
            size_t off = 0;
            while (off < take) {
                ssize_t w = ::write(outFd, pending_.data() + off, take - off);
                if (w <= 0) {
                    LOG_ERROR("transport: tls fd ", fd_, " splice write to fd ", outFd, " failed: ", std::strerror(errno));
                    return false;
                }
                off += (size_t)w;
            }
            pending_.erase(0, take);
            got = take;
            LOG_DEBUG("transport: tls fd ", fd_, " splice took ", take, " buffered bytes");
        }
        while (got < expectedBytes) {
            pollfd p{fd_, POLLIN, 0};
            if (SSL_pending(ssl_) <= 0 && ::poll(&p, 1, timeoutMs) <= 0) {
                LOG_ERROR("transport: tls fd ", fd_, " splice timeout at ", got, "/", expectedBytes, " bytes");
                return false;
            }
            int want = (int)std::min<uint64_t>(sizeof(buf), expectedBytes - got);
            int n = SSL_read(ssl_, buf, want);
            if (n <= 0) {
                int err = SSL_get_error(ssl_, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
                LOG_ERROR("transport: tls fd ", fd_, " splice SSL_read failed at ", got, "/", expectedBytes,
                          " bytes (ssl error ", err, "): ", sslErrors());
                return false;
            }
            size_t off = 0;
            while (off < (size_t)n) {
                ssize_t w = ::write(outFd, buf + off, (size_t)n - off);
                if (w <= 0) {
                    LOG_ERROR("transport: tls fd ", fd_, " splice write to fd ", outFd, " failed: ", std::strerror(errno));
                    return false;
                }
                off += (size_t)w;
            }
            got += (size_t)n;
        }
        LOG_DEBUG("transport: tls fd ", fd_, " spliced ", got, " bytes in ", sw.ms(), " ms");
        return true;
    }

private:
    int fd_ = -1;
    SSL* ssl_ = nullptr;
    std::string pending_;          // bytes buffered past the last newline

public:
    /// CN of the counterparty certificate (empty when absent).
    std::string peerCommonName() const {
        if (!ssl_) return {};
        X509* cert = SSL_get1_peer_certificate(ssl_);
        if (!cert) {
            LOG_DEBUG("transport: tls fd ", fd_, " counterparty presented no certificate");
            return {};
        }
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
        if (cn.empty()) LOG_WARN("transport: tls fd ", fd_, " peer certificate has no CN");
        return cn;
    }
};

} // namespace

Result<std::shared_ptr<Channel>> makeUnixChannel(int fd) {
    LOG_DEBUG("transport: unix channel on fd ", fd);
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
    const char* role = clientRole ? "client" : "server";
    if (ctx) LOG_DEBUG("transport: reusing cached TLS ", role, " context (cert=", certFile, " ca=", caFile, ")");
    if (!ctx) {
        LOG_DEBUG("transport: creating TLS ", role, " context cert='", certFile, "' key='", keyFile, "' ca='", caFile, "'");
        SSL_CTX* fresh = SSL_CTX_new(clientRole ? TLS_client_method() : TLS_server_method());
        if (!fresh) {
            LOG_ERROR("transport: SSL_CTX_new (", role, ") failed: ", sslErrors());
            return Result<std::shared_ptr<Channel>>::failure("SSL_CTX_new failed");
        }
        bool ok = true;
        if (!certFile.empty() && !keyFile.empty()) {
            if (SSL_CTX_use_certificate_file(fresh, certFile.c_str(), SSL_FILETYPE_PEM) != 1) {
                LOG_ERROR("transport: cannot load certificate '", certFile, "': ", sslErrors());
                ok = false;
            }
            if (SSL_CTX_use_PrivateKey_file(fresh, keyFile.c_str(), SSL_FILETYPE_PEM) != 1) {
                LOG_ERROR("transport: cannot load private key '", keyFile, "': ", sslErrors());
                ok = false;
            }
            if (SSL_CTX_check_private_key(fresh) != 1) {
                LOG_ERROR("transport: private key '", keyFile, "' does not match certificate '", certFile, "': ", sslErrors());
                ok = false;
            }
        } else {
            LOG_WARN("transport: TLS ", role, " context without own certificate (cert='", certFile, "' key='", keyFile, "')");
        }
        if (ok && !caFile.empty()) {
            ok = SSL_CTX_load_verify_locations(fresh, caFile.c_str(), nullptr) == 1;
            if (!ok) LOG_ERROR("transport: cannot load CA '", caFile, "': ", sslErrors());
            // mTLS: always verify the counterparty against our CA.
            SSL_CTX_set_verify(fresh, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        } else if (ok) {
            LOG_WARN("transport: TLS ", role, " context has no CA: peer verification DISABLED (test mode)");
            SSL_CTX_set_verify(fresh, SSL_VERIFY_NONE, nullptr);
        }
        if (!ok) {
            LOG_ERROR("transport: TLS ", role, " context setup failed (cert=", certFile, " key=", keyFile, " ca=", caFile, ")");
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
            LOG_DEBUG("transport: TLS ", role, " context race lost, using cached one");
        } else {
            LOG_INFO("transport: TLS ", role, " context ready (cert=", certFile, " ca=", caFile.empty() ? "<none>" : caFile, ")");
        }
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        LOG_ERROR("transport: SSL_new failed: ", sslErrors());
        return Result<std::shared_ptr<Channel>>::failure("SSL_new failed");
    }
    SSL_set_fd(ssl, fd);
    if (clientRole) SSL_set_tlsext_host_name(ssl, "s3mmc-peer.local"); // stable SNI, no hostname check
    LOG_DEBUG("transport: TLS ", role, " handshake on fd ", fd);
    log::Stopwatch sw;
    int rc = clientRole ? SSL_connect(ssl) : SSL_accept(ssl);
    if (rc <= 0) {
        int sslErr = SSL_get_error(ssl, rc);
        long vr = SSL_get_verify_result(ssl);
        unsigned long e = ERR_get_error();
        char eb[256] = {};
        ERR_error_string_n(e, eb, sizeof(eb));
        LOG_ERROR("transport: TLS ", role, " handshake on fd ", fd, " failed after ", sw.ms(), " ms (ssl error ", sslErr,
                  "): ", eb, (vr != X509_V_OK ? std::string(", verify: ") + X509_verify_cert_error_string(vr) : std::string()),
                  (sslErr == SSL_ERROR_SYSCALL && errno ? std::string(", errno: ") + std::strerror(errno) : std::string()));
        ERR_clear_error();
        SSL_free(ssl);
        return Result<std::shared_ptr<Channel>>::failure(std::string("TLS handshake failed: ") + eb);
    }
    if (log::initialized() && log::enabled(log::Level::Info)) {
        std::string subject = "<none>", issuer;
        if (X509* pc = SSL_get1_peer_certificate(ssl)) {
            char sb[512] = {};
            X509_NAME_oneline(X509_get_subject_name(pc), sb, sizeof(sb));
            subject = sb;
            char ib[512] = {};
            X509_NAME_oneline(X509_get_issuer_name(pc), ib, sizeof(ib));
            issuer = ib;
            X509_free(pc);
        }
        LOG_INFO("transport: TLS ", role, " handshake on fd ", fd, " ok in ", sw.ms(), " ms: ", SSL_get_version(ssl), " ",
                 SSL_get_cipher_name(ssl), ", peer subject=", subject, issuer.empty() ? "" : " issuer=", issuer,
                 ", verify=", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
    }
    return Result<std::shared_ptr<Channel>>(std::make_shared<TlsChannel>(fd, ssl));
}

std::string tlsPeerCommonName(const std::shared_ptr<Channel>& ch) {
    auto* tls = dynamic_cast<TlsChannel*>(ch.get());
    return tls ? tls->peerCommonName() : std::string();
}

} // namespace s3mm::s3mmc
