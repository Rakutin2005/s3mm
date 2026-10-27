#include "s3mm/common/crypto.hpp"

#include <cstdio>
#include <cstring>
#include <random>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "s3mm/common/log.hpp"

namespace s3mm::crypto {

static std::string opensslError() {
    unsigned long e = ERR_get_error();
    if (!e) return "no OpenSSL error queued";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof buf);
    return buf;
}

Digest sha256(std::string_view data) {
    Digest out{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) LOG_ERROR("crypto: EVP_MD_CTX_new failed: ", opensslError());
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
    ok = EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 && ok;
    unsigned int len = 0;
    ok = EVP_DigestFinal_ex(ctx, out.data(), &len) == 1 && ok;
    EVP_MD_CTX_free(ctx);
    if (!ok) LOG_ERROR("crypto: SHA-256 over ", data.size(), " bytes failed: ", opensslError());
    return out;
}

Digest hmacSha256(std::string_view key, std::string_view data) {
    Digest out{};
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key.data(), (int)key.size(), reinterpret_cast<const unsigned char*>(data.data()), data.size(),
              out.data(), &len))
        LOG_ERROR("crypto: HMAC-SHA256 failed: ", opensslError());
    return out;
}

std::string toHex(const unsigned char* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += hex[data[i] >> 4];
        out += hex[data[i] & 0xF];
    }
    return out;
}

std::string toHex(const Digest& d) { return toHex(d.data(), d.size()); }

std::string sha256Hex(std::string_view data) { return toHex(sha256(data)); }
std::string hmacSha256Hex(std::string_view key, std::string_view data) { return toHex(hmacSha256(key, data)); }

static const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(std::string_view data) {
    std::string out;
    size_t i = 0;
    while (i + 3 <= data.size()) {
        unsigned v = ((unsigned char)data[i] << 16) | ((unsigned char)data[i + 1] << 8) | (unsigned char)data[i + 2];
        out += kB64[(v >> 18) & 63];
        out += kB64[(v >> 12) & 63];
        out += kB64[(v >> 6) & 63];
        out += kB64[v & 63];
        i += 3;
    }
    size_t rest = data.size() - i;
    if (rest == 1) {
        unsigned v = (unsigned char)data[i] << 16;
        out += kB64[(v >> 18) & 63];
        out += kB64[(v >> 12) & 63];
        out += "==";
    } else if (rest == 2) {
        unsigned v = ((unsigned char)data[i] << 16) | ((unsigned char)data[i + 1] << 8);
        out += kB64[(v >> 18) & 63];
        out += kB64[(v >> 12) & 63];
        out += kB64[(v >> 6) & 63];
        out += '=';
    }
    return out;
}

std::optional<std::string> base64Decode(std::string_view text) {
    int decode[256];
    for (int& d : decode) d = -1;
    for (int i = 0; i < 64; ++i) decode[(unsigned char)kB64[i]] = i;
    std::string out;
    int val = 0, valb = -8;
    for (char c : text) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int d = decode[(unsigned char)c];
        if (d < 0) {
            LOG_DEBUG("crypto: base64 decode failed: invalid character 0x", std::hex, (int)(unsigned char)c, std::dec,
                      " in ", text.size(), "-byte input");
            return std::nullopt;
        }
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out += (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

std::string randomBytes(size_t n) {
    std::string out(n, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), (int)n) != 1) {
        // Extremely unlikely; fall back to a non-OpenSSL source so callers never see garbage.
        LOG_WARN("crypto: RAND_bytes(", n, ") failed: ", opensslError(), "; falling back to std::random_device");
        std::random_device rd;
        for (size_t i = 0; i < n; ++i) out[i] = (char)(rd() & 0xFF);
    }
    return out;
}

std::string randomHex(size_t n) { return toHex(reinterpret_cast<const unsigned char*>(randomBytes(n).data()), n); }

Digest pbkdf2(const std::string& passphrase, std::string_view salt, int iterations, size_t keyLen) {
    Digest out{};
    LOG_DEBUG("crypto: PBKDF2-SHA256 derive, iterations=", iterations, " salt=", salt.size(), "B key=", keyLen, "B");
    if (PKCS5_PBKDF2_HMAC(passphrase.c_str(), (int)passphrase.size(), reinterpret_cast<const unsigned char*>(salt.data()),
                          (int)salt.size(), iterations, EVP_sha256(), (int)keyLen, out.data()) != 1)
        LOG_ERROR("crypto: PBKDF2 key derivation failed: ", opensslError());
    return out;
}

} // namespace s3mm::crypto
