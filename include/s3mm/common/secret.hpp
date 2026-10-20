#pragma once
#include <optional>
#include <string>

#include "s3mm/common/result.hpp"

namespace s3mm::secret {

/// Secrets at rest are stored as PEM-style text blocks whose body is a binary
/// container (version | salt | iv | gcm tag | ciphertext) rendered in base64.
/// The decryption key is derived from the passphrase configured in s3mm.conf
/// (usually pulled in via `include` of a 0400 file).
///
///   -----BEGIN S3MM SECRET-----
///   AAEAB...
///   -----END S3MM SECRET-----

std::string seal(const std::string& plaintext, const std::string& passphrase);
Result<std::string> open(const std::string& pemBlock, const std::string& passphrase);

/// Accepts either a PEM block or a plain string; plain strings are returned as-is.
std::string openMaybe(const std::string& value, const std::string& passphrase);

bool isPemBlock(const std::string& value);

} // namespace s3mm::secret
