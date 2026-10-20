#include "s3mm/common/str.hpp"
#include "s3mm/common/error.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>

namespace s3mm::str {

static bool isSpace(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

std::string ltrim(std::string_view s) {
    size_t i = 0;
    while (i < s.size() && isSpace(s[i])) ++i;
    return std::string(s.substr(i));
}

std::string rtrim(std::string_view s) {
    size_t e = s.size();
    while (e > 0 && isSpace(s[e - 1])) --e;
    return std::string(s.substr(0, e));
}

std::string trim(std::string_view s) { return ltrim(rtrim(s)); }

std::vector<std::string> split(std::string_view s, char delim, bool keepEmpty) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == delim) {
            std::string part(s.substr(start, i - start));
            if (keepEmpty || !part.empty()) out.push_back(std::move(part));
            start = i + 1;
        }
    }
    return out;
}

std::vector<std::string> splitWS(std::string_view s) {
    std::vector<std::string> out;
    std::string cur;
    bool inQuote = false;
    char quote = 0;
    for (char c : s) {
        if (inQuote) {
            if (c == quote) { inQuote = false; continue; }
            cur += c;
            continue;
        }
        if (c == '\'' || c == '"') { inQuote = true; quote = c; continue; }
        if (isSpace(c)) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
            continue;
        }
        cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::vector<std::string> splitList(std::string_view s) {
    std::vector<std::string> out;
    for (auto& p : split(s, ',')) {
        std::string t = trim(p);
        if (!t.empty()) out.push_back(std::move(t));
    }
    return out;
}

std::vector<std::string> tokenize(std::string_view s) {
    std::vector<std::string> out;
    std::string cur;
    bool has = false;
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (quote) {
            if (c == quote) { quote = 0; continue; }
            if (c == '\\' && quote == '"' && i + 1 < s.size()) { cur += s[++i]; continue; }
            cur += c;
            has = true;
            continue;
        }
        if (c == '\'' || c == '"') { quote = c; has = true; continue; }
        if (c == '\\' && i + 1 < s.size()) { cur += s[++i]; has = true; continue; }
        if (isSpace(c)) {
            if (has) { out.push_back(cur); cur.clear(); has = false; }
            continue;
        }
        cur += c;
        has = true;
    }
    if (quote) throw Error("unterminated quote in: " + std::string(s));
    if (has) out.push_back(cur);
    return out;
}

std::string join(const std::vector<std::string>& parts, std::string_view sep) {
    std::ostringstream os;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) os << sep;
        os << parts[i];
    }
    return os.str();
}

std::string toLower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
    return out;
}

std::string toUpper(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::toupper(c); });
    return out;
}

bool startsWith(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.substr(0, p.size()) == p; }
bool endsWith(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.substr(s.size() - p.size()) == p; }

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
    return true;
}

std::string replaceAll(std::string s, std::string_view from, std::string_view to) {
    if (from.empty()) return s;
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

std::string escapeJson(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

std::string quoteShell(std::string_view s) {
    bool need = s.empty();
    for (char c : s)
        if (c == ' ' || c == '\t' || c == '\n' || c == '"' || c == '\'' || c == '\\') need = true;
    if (!need) return std::string(s);
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out += c;
    }
    out += "'";
    return out;
}

std::string escapeYaml(std::string_view s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += (char)c;
        }
    }
    return out;
}

std::string padRight(std::string_view s, size_t width) {
    std::string out(s);
    if (out.size() < width) out.append(width - out.size(), ' ');
    return out;
}

std::string padLeft(std::string_view s, size_t width) {
    std::string out(s);
    if (out.size() < width) out.insert(0, width - out.size(), ' ');
    return out;
}

std::optional<int64_t> parseInt64(std::string_view s) {
    std::string t = trim(s);
    if (t.empty()) return std::nullopt;
    char* end = nullptr;
    long long v = std::strtoll(t.c_str(), &end, 10);
    if (end == t.c_str() || *end != '\0') return std::nullopt;
    return (int64_t)v;
}

std::optional<double> parseDouble(std::string_view s) {
    std::string t = trim(s);
    if (t.empty()) return std::nullopt;
    char* end = nullptr;
    double v = std::strtod(t.c_str(), &end);
    if (end == t.c_str() || *end != '\0') return std::nullopt;
    return v;
}

std::string expandEnv(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '$') { out += s[i]; continue; }
        if (i + 1 < s.size() && s[i + 1] == '{') {
            size_t j = s.find('}', i + 2);
            if (j == std::string_view::npos) { out += s[i]; continue; }
            std::string name(s.substr(i + 2, j - i - 2));
            const char* v = std::getenv(name.c_str());
            if (v) out += v;
            i = j;
            continue;
        }
        if (i + 1 < s.size() && (std::isalnum((unsigned char)s[i + 1]) || s[i + 1] == '_')) {
            size_t j = i + 1;
            while (j < s.size() && (std::isalnum((unsigned char)s[j]) || s[j] == '_')) ++j;
            std::string name(s.substr(i + 1, j - i - 1));
            const char* v = std::getenv(name.c_str());
            if (v) out += v;
            i = j - 1;
            continue;
        }
        out += s[i];
    }
    return out;
}

} // namespace s3mm::str
