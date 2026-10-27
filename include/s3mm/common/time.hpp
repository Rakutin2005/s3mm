#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <chrono>

namespace s3mm::tm {

using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

TimePoint now();
int64_t nowMs();
time_t toSeconds(TimePoint t);

/// ISO-8601 / RFC3339 UTC: 2026-10-20T12:34:56Z
std::string toIso8601(TimePoint t);
std::string toIso8601Ms(TimePoint t); // with milliseconds
/// Parse ISO-8601/RFC3339 (Z or +hh:mm offset, optional fraction).
std::optional<TimePoint> fromIso8601(std::string_view s);
/// HTTP date (RFC 7231 IMF-fixdate, as in Last-Modified): Tue, 20 Oct 2026 12:34:56 GMT
std::optional<TimePoint> fromHttpDate(std::string_view s);
/// AmazonS3 style: 2026-10-20T12:34:56.000Z
std::string toS3Time(TimePoint t);

std::string timeAgo(TimePoint t); // "3m ago", "never"

} // namespace s3mm::tm
