#pragma once
#include <string>

#include "s3mm/common/value.hpp"

namespace s3mm::cli {

enum class Format { Table, Json, Yaml };

/// "table" (default), "json" or "yaml"; throws UsageError otherwise.
Format formatFromString(const std::string& s);

/// Render one result Value for terminal output (always newline-terminated).
std::string render(const Value& v, Format f);

/// One-line textual form of a single cell (used by the table renderer).
std::string cell(const Value& v);

} // namespace s3mm::cli
