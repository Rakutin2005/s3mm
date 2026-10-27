#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "s3mm/common/result.hpp"

namespace s3mm::fs {

std::optional<std::string> readFile(const std::string& path);
/// Atomic write: temp file in the same directory + rename.
bool writeFileAtomic(const std::string& path, std::string_view content, bool fsyncDir = false);
bool appendFile(const std::string& path, std::string_view content);

bool exists(const std::string& path);
bool isDir(const std::string& path);
bool isRegular(const std::string& path);
std::optional<uint64_t> fileSize(const std::string& path);
bool mkdirp(const std::string& path);
bool removeFile(const std::string& path);
bool removeTree(const std::string& path);
/// Directory entries (names only, sorted). Missing dir -> empty.
std::vector<std::string> listDir(const std::string& path);
/// POSIX permission bits (st_mode & 0777); nullopt on error.
std::optional<unsigned> permissions(const std::string& path);
bool setPermissions(const std::string& path, unsigned mode);

/// Read a file that must not be readable by group/other; returns error string otherwise.
Result<std::string> readSecretFile(const std::string& path);

std::string joinPath(std::string_view a, std::string_view b);
std::string dirname(const std::string& path);
std::string basename(const std::string& path);

} // namespace s3mm::fs
