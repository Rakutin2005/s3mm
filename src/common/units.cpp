#include "s3mm/common/units.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>

#include "s3mm/common/error.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::units {

static bool suffixToMul(std::string_view sfx, uint64_t& mul) {
    mul = 1;
    if (sfx.empty()) return true;
    std::string s = str::toLower(sfx);
    if (s == "b") mul = 1;
    else if (s == "k" || s == "kb") mul = 1000ULL;
    else if (s == "ki" || s == "kib") mul = 1024ULL;
    else if (s == "m" || s == "mb") mul = 1000ULL * 1000;
    else if (s == "mi" || s == "mib") mul = 1024ULL * 1024;
    else if (s == "g" || s == "gb") mul = 1000ULL * 1000 * 1000;
    else if (s == "gi" || s == "gib") mul = 1024ULL * 1024 * 1024;
    else if (s == "t" || s == "tb") mul = 1000ULL * 1000 * 1000 * 1000;
    else if (s == "ti" || s == "tib") mul = 1024ULL * 1024 * 1024 * 1024;
    else return false;
    return true;
}

std::optional<uint64_t> tryParseSize(std::string_view s) {
    std::string t = str::trim(s);
    if (t.empty()) return std::nullopt;
    size_t i = 0;
    while (i < t.size() && (std::isdigit((unsigned char)t[i]) || t[i] == '.')) ++i;
    if (i == 0) return std::nullopt;
    std::string numStr = t.substr(0, i);
    std::string sfx = str::trim(std::string_view(t).substr(i));
    uint64_t mul = 1;
    if (!suffixToMul(sfx, mul)) return std::nullopt;
    char* end = nullptr;
    double v = std::strtod(numStr.c_str(), &end);
    if (end == numStr.c_str()) return std::nullopt;
    if (v < 0) return std::nullopt;
    return (uint64_t)(v * (double)mul + 0.5);
}

uint64_t parseSize(std::string_view s) {
    auto v = tryParseSize(s);
    if (!v) throw Error("invalid size: '" + std::string(s) + "'");
    return *v;
}

std::optional<int64_t> tryParseDuration(std::string_view s) {
    std::string t = str::trim(s);
    if (t.empty()) return std::nullopt;
    int64_t totalMs = 0;
    size_t i = 0;
    bool any = false;
    while (i < t.size()) {
        if (!std::isdigit((unsigned char)t[i]) && t[i] != '.') return std::nullopt;
        size_t j = i;
        while (j < t.size() && (std::isdigit((unsigned char)t[j]) || t[j] == '.')) ++j;
        std::string numStr = t.substr(i, j - i);
        size_t k = j;
        while (k < t.size() && std::isalpha((unsigned char)t[k])) ++k;
        std::string unit = str::toLower(std::string_view(t).substr(j, k - j));
        char* end = nullptr;
        double v = std::strtod(numStr.c_str(), &end);
        if (end == numStr.c_str()) return std::nullopt;
        int64_t mul;
        if (unit.empty() || unit == "s") mul = 1000;
        else if (unit == "ms") mul = 1;
        else if (unit == "m") mul = 60 * 1000;
        else if (unit == "h") mul = 3600 * 1000;
        else if (unit == "d") mul = 86400 * 1000;
        else if (unit == "w") mul = 7 * 86400 * 1000;
        else return std::nullopt;
        totalMs += (int64_t)(v * (double)mul);
        i = k;
        any = true;
    }
    if (!any) return std::nullopt;
    return totalMs;
}

int64_t parseDuration(std::string_view s) {
    auto v = tryParseDuration(s);
    if (!v) throw Error("invalid duration: '" + std::string(s) + "'");
    return *v;
}

int64_t parseDurationSeconds(std::string_view s) {
    int64_t ms = parseDuration(s);
    return (ms + 999) / 1000;
}

std::string formatSize(uint64_t bytes) {
    const char* suffixes[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
    double v = (double)bytes;
    int u = 0;
    while (v >= 1024.0 && u < 5) {
        v /= 1024.0;
        ++u;
    }
    char buf[64];
    if (u == 0)
        std::snprintf(buf, sizeof buf, "%lluB", (unsigned long long)bytes);
    else
        std::snprintf(buf, sizeof buf, "%.1f%s", v, suffixes[u]);
    return buf;
}

std::string formatDuration(int64_t ms) {
    if (ms < 0) ms = 0;
    if (ms < 1000) return std::to_string(ms) + "ms";
    int64_t s = ms / 1000;
    if (s < 60) return std::to_string(s) + "s";
    if (s < 3600) return std::to_string(s / 60) + "m" + std::to_string(s % 60) + "s";
    if (s < 86400) return std::to_string(s / 3600) + "h" + std::to_string((s % 3600) / 60) + "m";
    return std::to_string(s / 86400) + "d" + std::to_string((s % 86400) / 3600) + "h";
}

} // namespace s3mm::units
