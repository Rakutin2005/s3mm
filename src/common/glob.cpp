#include "s3mm/common/glob.hpp"

#include <algorithm>
#include <filesystem>

#include "s3mm/common/str.hpp"

namespace s3mm::glob {

static bool matchRec(std::string_view p, std::string_view v) {
    while (!p.empty()) {
        if (p[0] == '*') {
            // collapse consecutive stars
            while (!p.empty() && p[0] == '*') p.remove_prefix(1);
            if (p.empty()) return true;
            for (size_t i = 0; i <= v.size(); ++i)
                if (matchRec(p, v.substr(i))) return true;
            return false;
        }
        if (v.empty()) return false;
        if (p[0] == '?' || p[0] == v[0]) {
            p.remove_prefix(1);
            v.remove_prefix(1);
            continue;
        }
        return false;
    }
    return v.empty();
}

bool match(std::string_view pattern, std::string_view value) { return matchRec(pattern, value); }

bool matchFilter(const std::vector<std::string>& patterns, std::string_view value) {
    bool anyPositive = false;
    bool positiveMatch = false;
    for (const auto& pat : patterns) {
        if (pat.empty()) continue;
        if (pat[0] == '!') {
            if (match(std::string_view(pat).substr(1), value)) return false;
            continue;
        }
        anyPositive = true;
        if (match(pat, value)) positiveMatch = true;
    }
    if (!anyPositive) return true;
    return positiveMatch;
}

bool matchFilterList(std::string_view patterns, std::string_view value) {
    return matchFilter(str::splitList(patterns), value);
}

std::vector<std::string> expand(std::string_view pattern) {
    namespace fs = std::filesystem;
    std::vector<std::string> out;
    std::string pat(pattern);
    std::error_code ec;
    fs::path base(".");
    std::string leaf = pat;
    auto pos = pat.find_last_of('/');
    if (pos != std::string::npos) {
        base = pat.substr(0, pos + 1);
        leaf = pat.substr(pos + 1);
    }
    if (!fs::exists(base, ec)) return out;
    for (const auto& e : fs::directory_iterator(base, ec)) {
        std::string name = e.path().filename().string();
        if (match(leaf, name)) out.push_back((base / name).string());
    }
    std::sort(out.begin(), out.end());
    return out;
}

} // namespace s3mm::glob
