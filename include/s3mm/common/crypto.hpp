#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace s3mm::crypto {

using Digest = std::array<unsigned char, 32>;

Digest sha256(std::string_view data);
Digest hmacSha256(std::string_view key, std::string_view data);
std::string sha256Hex(std::string_view data);
std::string hmacSha256Hex(std::string_view key, std::string_view data);
std::string toHex(const unsigned char* data, size_t len);
std::string toHex(const Digest& d);

std::string base64Encode(std::string_view data);
std::optional<std::string> base64Decode(std::string_view text);

std::string randomBytes(size_t n);
std::string randomHex(size_t n);

/// PBKDF2-HMAC-SHA256 key derivation.
Digest pbkdf2(const std::string& passphrase, std::string_view salt, int iterations, size_t keyLen = 32);

} // namespace s3mm::crypto
