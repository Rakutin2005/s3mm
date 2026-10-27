#include "s3mm/common/secret.hpp"

#include <cstring>

#include <openssl/evp.h>

#include "s3mm/common/crypto.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::secret {

static const char* kBegin = "-----BEGIN S3MM SECRET-----";
static const char* kEnd = "-----END S3MM SECRET-----";
static const int kIterations = 100000;

std::string seal(const std::string& plaintext, const std::string& passphrase) {
    std::string salt = crypto::randomBytes(16);
    std::string iv = crypto::randomBytes(12);
    auto key = crypto::pbkdf2(passphrase, salt, kIterations);

    LOG_DEBUG("secret: sealing ", log::redact(plaintext));
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) LOG_ERROR("secret: EVP_CIPHER_CTX_new failed while sealing");
    std::string ciphertext(plaintext.size(), '\0');
    int len = 0, total = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()),
                       reinterpret_cast<const unsigned char*>(iv.data()));
    if (!plaintext.empty()) {
        EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()), (int)plaintext.size());
        total = len;
    }
    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + total, &len);
    total += len;
    ciphertext.resize((size_t)total);
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof tag, tag);
    EVP_CIPHER_CTX_free(ctx);

    std::string blob;
    blob += (char)1; // version
    blob += salt;
    blob += iv;
    blob.append(reinterpret_cast<char*>(tag), sizeof tag);
    blob += ciphertext;

    std::string b64 = crypto::base64Encode(blob);
    std::string out = kBegin;
    out += '\n';
    for (size_t i = 0; i < b64.size(); i += 64) out += b64.substr(i, 64) + "\n";
    out += kEnd;
    return out;
}

Result<std::string> open(const std::string& pemBlock, const std::string& passphrase) {
    auto bpos = pemBlock.find(kBegin);
    auto epos = pemBlock.find(kEnd);
    if (bpos == std::string::npos || epos == std::string::npos || epos < bpos) {
        LOG_WARN("secret: not an s3mm secret block");
        return Result<std::string>::failure("not an s3mm secret block");
    }
    auto nl = pemBlock.find('\n', bpos);
    std::string body = pemBlock.substr(nl == std::string::npos ? epos : nl + 1, epos - (nl == std::string::npos ? bpos : nl + 1));
    auto blob = crypto::base64Decode(body);
    if (!blob) {
        LOG_WARN("secret: invalid base64 in secret block");
        return Result<std::string>::failure("invalid base64 in secret block");
    }
    if (blob->size() < 1 + 16 + 12 + 16) {
        LOG_WARN("secret: secret block too short");
        return Result<std::string>::failure("secret block too short");
    }
    if ((*blob)[0] != (char)1) {
        LOG_WARN("secret: unsupported secret block version");
        return Result<std::string>::failure("unsupported secret block version");
    }

    size_t off = 1;
    std::string_view salt(blob->data() + off, 16); off += 16;
    std::string_view iv(blob->data() + off, 12); off += 12;
    std::string_view tag(blob->data() + off, 16); off += 16;
    std::string_view ciphertext(blob->data() + off, blob->size() - off);

    auto key = crypto::pbkdf2(passphrase, salt, kIterations);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::string plaintext(ciphertext.size(), '\0');
    int len = 0, total = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) == 1;
    ok = ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char*>(key.data()),
                                  reinterpret_cast<const unsigned char*>(iv.data())) == 1;
    if (ok && !ciphertext.empty())
        ok = EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &len,
                               reinterpret_cast<const unsigned char*>(ciphertext.data()), (int)ciphertext.size()) == 1;
    if (ok) total = len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<char*>(tag.data())) == 1;
    int fin = 0;
    ok = ok && EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + total, &fin) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        LOG_WARN("secret: cannot decrypt secret (wrong passphrase or corrupted data)");
        return Result<std::string>::failure("cannot decrypt secret (wrong passphrase or corrupted data)");
    }
    plaintext.resize((size_t)(total + fin));
    LOG_DEBUG("secret: opened sealed block -> ", log::redact(plaintext));
    return Result<std::string>(std::move(plaintext));
}

bool isPemBlock(const std::string& value) { return value.find(kBegin) != std::string::npos; }

std::string openMaybe(const std::string& value, const std::string& passphrase) {
    if (!isPemBlock(value)) return value;
    auto res = open(value, passphrase);
    if (!res.ok()) LOG_WARN("secret: cannot open sealed value (", res.error(), "); using empty value");
    return res.ok() ? res.value() : std::string{};
}

} // namespace s3mm::secret
