#include "s3mm/daemon/peerserver.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <thread>
#include <string>
#include <vector>

#include "s3mm/common/log.hpp"
#include "s3mm/common/fs.hpp"

namespace s3mm::daemon {

PeerServer::PeerServer() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

PeerServer::~PeerServer() {
    close();
    if (sslCtx_) SSL_CTX_free((SSL_CTX*)sslCtx_);
}

Result<void> PeerServer::listen(const std::string& address, int port,
                               const std::string& certFile, const std::string& keyFile,
                               const std::string& caFile) {
    certFile_ = certFile; keyFile_ = keyFile; caFile_ = caFile;
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return Result<void>::failure("socket failed");
    int opt = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (::inet_pton(AF_INET, address.c_str(), &addr.sin_addr) != 1) {
        ::close(fd); return Result<void>::failure("invalid address");
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd); return Result<void>::failure("bind failed");
    }
    if (::listen(fd, 16) < 0) {
        ::close(fd); return Result<void>::failure("listen failed");
    }
    // SSL context
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ::close(fd); return Result<void>::failure("SSL_CTX_new failed"); }
    if (!certFile.empty()) {
        if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx); ::close(fd); return Result<void>::failure("cert load failed");
        }
    }
    if (!keyFile.empty()) {
        if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx); ::close(fd); return Result<void>::failure("key load failed");
        }
    }
    if (!caFile.empty()) {
        SSL_CTX_load_verify_locations(ctx, caFile.c_str(), nullptr);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }
    sslCtx_ = ctx;
    fd_ = fd;
    // Start accept thread
    std::thread([this]() {
        while (fd_ >= 0) {
            int client = ::accept(fd_, nullptr, nullptr);
            if (client < 0) continue;
            SSL* ssl = SSL_new((SSL_CTX*)sslCtx_);
            SSL_set_fd(ssl, client);
            if (SSL_accept(ssl) <= 0) {
                SSL_free(ssl); ::close(client); continue;
            }
            // read one line
            std::string req;
            char buf[4096];
            for (;;) {
                int n = SSL_read(ssl, buf, sizeof(buf));
                if (n <= 0) break;
                req.append(buf, n);
                if (req.find('\n') != std::string::npos) break;
            }
            std::string resp;
            if (handler_) resp = handler_(req);
            else resp = "{\"error\":\"no handler\"}\n";
            SSL_write(ssl, resp.c_str(), resp.size());
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ::close(client);
        }
    }).detach();
    return Result<void>::success();
}

void PeerServer::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

} // namespace s3mm::daemon
