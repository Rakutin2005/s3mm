#pragma once
#include <string>
#include <string_view>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/module/module.hpp"

namespace s3mm::module {

/// Parse the plaintext ZIP returned by `GET <vendor>/admin/v3/export-iam`.
/// Both MinIO and RustFS use the same iam-assets/users.json +
/// iam-assets/user_mappings.json layout, including the secret keys.
Result<std::vector<Account>> parseIamExport(std::string_view archive, const std::string& vendor);

} // namespace s3mm::module
