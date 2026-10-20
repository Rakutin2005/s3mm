#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace s3mm::units {

/// Parse a byte size: "1G", "50g", "16MiB", "1024", "2.5M", "300KB".
std::optional<uint64_t> tryParseSize(std::string_view s);
uint64_t parseSize(std::string_view s); // throws Error

/// Parse a duration: "1d2h3m4s", "5m", "500ms", "1w", "90". Returns milliseconds.
std::optional<int64_t> tryParseDuration(std::string_view s);
int64_t parseDuration(std::string_view s); // throws Error
/// Parse duration but round up to whole seconds (config thresholds are second-granular).
int64_t parseDurationSeconds(std::string_view s);

std::string formatSize(uint64_t bytes);
std::string formatDuration(int64_t ms);

} // namespace s3mm::units
