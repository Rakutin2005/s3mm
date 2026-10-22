#pragma once
#include <string>
#include <string_view>

#include "s3mm/common/result.hpp"

namespace s3mm::zip {

/// Extract one file from an in-memory ZIP archive (stored or deflated).
///
/// This is deliberately small: it is used for the plaintext IAM export ZIP
/// returned by MinIO/RustFS (-admin/v3/export-iam), not as a general-purpose
/// archive library. ZIP64 and encrypted entries are not supported.
Result<std::string> extractFile(std::string_view archive, std::string_view name);

} // namespace s3mm::zip
