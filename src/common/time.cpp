#include "s3mm/common/time.hpp"

#include <cctype>
#include <cstdio>
#include <ctime>

#include "s3mm/common/units.hpp"

namespace s3mm::tm {

TimePoint now() { return Clock::now(); }
int64_t nowMs() { return std::chrono::duration_cast<std::chrono::milliseconds>(now().time_since_epoch()).count(); }
time_t toSeconds(TimePoint t) { return Clock::to_time_t(t); }

static std::string fmtUtc(TimePoint t, const char* pattern) {
    std::time_t tt = Clock::to_time_t(t);
    std::tm tm{};
    ::gmtime_r(&tt, &tm);
    char buf[64];
    std::strftime(buf, sizeof buf, pattern, &tm);
    return buf;
}

std::string toIso8601(TimePoint t) { return fmtUtc(t, "%Y-%m-%dT%H:%M:%SZ"); }

std::string toIso8601Ms(TimePoint t) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count() % 1000;
    if (ms < 0) ms += 1000;
    char buf[80];
    std::snprintf(buf, sizeof buf, "%s.%03dZ", fmtUtc(t, "%Y-%m-%dT%H:%M:%S").c_str(), (int)ms);
    return buf;
}

std::string toS3Time(TimePoint t) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count() % 1000;
    if (ms < 0) ms += 1000;
    char buf[80];
    std::snprintf(buf, sizeof buf, "%s.%03dZ", fmtUtc(t, "%Y-%m-%dT%H:%M:%S").c_str(), (int)ms);
    return buf;
}

std::optional<TimePoint> fromHttpDate(std::string_view s) {
    std::string t(s);
    std::tm tm{};
    const char* end = ::strptime(t.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (!end || *end) return std::nullopt;
    return Clock::from_time_t(::timegm(&tm));
}

std::optional<TimePoint> fromIso8601(std::string_view s) {
    std::string t(s);
    if (t.size() < 19) return std::nullopt;
    for (size_t i : {0, 3, 6, 11, 14})
        if (i >= t.size() || !std::isdigit((unsigned char)t[i])) return std::nullopt;
    std::tm tm{};
    tm.tm_year = std::stoi(t.substr(0, 4)) - 1900;
    tm.tm_mon = std::stoi(t.substr(5, 2)) - 1;
    tm.tm_mday = std::stoi(t.substr(8, 2));
    tm.tm_hour = std::stoi(t.substr(11, 2));
    tm.tm_min = std::stoi(t.substr(14, 2));
    tm.tm_sec = t.size() > 17 ? std::stoi(t.substr(17, 2)) : 0;
    size_t pos = 19;
    int fracMs = 0;
    if (pos < t.size() && t[pos] == '.') {
        size_t j = pos + 1;
        while (j < t.size() && std::isdigit((unsigned char)t[j])) ++j;
        std::string frac = t.substr(pos + 1, j - pos - 1);
        while (frac.size() < 3) frac += '0';
        fracMs = std::stoi(frac.substr(0, 3));
        pos = j;
    }
    int offsetSec = 0;
    if (pos < t.size() && (t[pos] == 'Z' || t[pos] == 'z')) {
        offsetSec = 0;
    } else if (pos + 5 < t.size() && (t[pos] == '+' || t[pos] == '-')) {
        int sign = t[pos] == '-' ? -1 : 1;
        offsetSec = sign * (std::stoi(t.substr(pos + 1, 2)) * 3600 + std::stoi(t.substr(pos + 4, 2)) * 60);
    } else {
        return std::nullopt; // require explicit timezone to avoid ambiguity
    }
    time_t tt = timegm(&tm);
    if (tt == (time_t)-1) return std::nullopt;
    tt -= offsetSec;
    return TimePoint(std::chrono::seconds(tt)) + std::chrono::milliseconds(fracMs);
}

std::string timeAgo(TimePoint t) {
    if (t.time_since_epoch().count() == 0) return "never";
    int64_t diffMs = std::chrono::duration_cast<std::chrono::milliseconds>(now() - t).count();
    if (diffMs < 0) return "in " + units::formatDuration(-diffMs);
    return units::formatDuration(diffMs) + " ago";
}

} // namespace s3mm::tm
