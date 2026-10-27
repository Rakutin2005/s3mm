#include "s3mm/common/value.hpp"

#include <cmath>
#include <cstdio>

#include "s3mm/common/str.hpp"

namespace s3mm {

static std::string numToString(double d) {
    if (std::floor(d) == d && std::abs(d) < 1e15) return std::to_string((int64_t)d);
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.10g", d);
    return buf;
}

Value& Value::set(const std::string& key, Value v) {
    if (type_ != Type::Object) { type_ = Type::Object; members_.clear(); }
    for (auto& [k, existing] : members_) {
        if (k == key) { existing = std::move(v); return *this; }
    }
    members_.emplace_back(key, std::move(v));
    return *this;
}

const Value* Value::find(const std::string& key) const {
    if (type_ != Type::Object) return nullptr;
    for (const auto& [k, v] : members_)
        if (k == key) return &v;
    return nullptr;
}

const std::string& Value::getString(const std::string& key, const std::string& def) const {
    const Value* v = find(key);
    if (!v || v->type_ != Type::String) return def;
    return v->str_;
}

static void toJsonRec(const Value& v, std::string& out, int indent, int depth) {
    auto pad = [indent, depth](std::string& o) {
        if (indent > 0) o.append((size_t)indent * (size_t)depth, ' ');
    };
    auto nl = [&]() {
        if (indent > 0) out += '\n';
    };
    switch (v.type()) {
        case Value::Type::Null: out += "null"; break;
        case Value::Type::Bool: out += v.asBool() ? "true" : "false"; break;
        case Value::Type::Number: out += numToString(v.asDouble()); break;
        case Value::Type::String: out += '"' + str::escapeJson(v.asString()) + '"'; break;
        case Value::Type::Array: {
            if (v.items().empty()) { out += "[]"; break; }
            out += '[';
            nl();
            for (size_t i = 0; i < v.items().size(); ++i) {
                pad(out);
                toJsonRec(v.items()[i], out, indent, depth + 1);
                if (i + 1 < v.items().size()) out += ',';
                nl();
            }
            pad(out);
            out += ']';
            break;
        }
        case Value::Type::Object: {
            if (v.members().empty()) { out += "{}"; break; }
            out += '{';
            nl();
            for (size_t i = 0; i < v.members().size(); ++i) {
                pad(out);
                out += '"' + str::escapeJson(v.members()[i].first) + "\": ";
                toJsonRec(v.members()[i].second, out, indent, depth + 1);
                if (i + 1 < v.members().size()) out += ',';
                nl();
            }
            pad(out);
            out += '}';
            break;
        }
    }
}

std::string Value::toJson(int indent) const {
    std::string out;
    toJsonRec(*this, out, indent, 0);
    return out;
}

static bool yamlScalarNeedsQuotes(const std::string& s) {
    if (s.empty()) return true;
    if (s.size() > 1 && (s.front() == '"' || s.front() == '\'')) return true;
    for (char c : s) {
        if (c == '\n' || c == '\t' || c == ':' || c == '#' || c == '\'' || c == '"' || c == '\\' || c == '{' ||
            c == '}' || c == '[' || c == ']' || c == ',' || c == '&')
            return true;
    }
    if (str::trim(s) != s) return true;
    return false;
}

static void toYamlRec(const Value& v, std::string& out, int depth, int indent) {
    auto pad = [&]() { out.append((size_t)indent * (size_t)depth, ' '); };
    switch (v.type()) {
        case Value::Type::Null: out += "null"; break;
        case Value::Type::Bool: out += v.asBool() ? "true" : "false"; break;
        case Value::Type::Number: out += numToString(v.asDouble()); break;
        case Value::Type::String: {
            const std::string& s = v.asString();
            if (yamlScalarNeedsQuotes(s)) out += '"' + str::escapeYaml(s) + '"';
            else out += s;
            break;
        }
        case Value::Type::Array: {
            if (v.items().empty()) { out += "[]"; break; }
            for (const auto& item : v.items()) {
                out += '\n';
                pad();
                out += "- ";
                if (item.isArray() || item.isObject()) toYamlRec(item, out, depth + 1, indent);
                else toYamlRec(item, out, depth, indent);
            }
            break;
        }
        case Value::Type::Object: {
            if (v.members().empty()) { out += "{}"; break; }
            for (const auto& [k, val] : v.members()) {
                out += '\n';
                pad();
                out += k + ":";
                if (val.isObject() || val.isArray()) {
                    if ((val.isObject() && val.members().empty()) || (val.isArray() && val.items().empty())) {
                        out += val.isObject() ? " {}" : " []";
                    } else {
                        toYamlRec(val, out, depth + 1, indent);
                    }
                } else {
                    out += ' ';
                    toYamlRec(val, out, depth, indent);
                }
            }
            break;
        }
    }
}

std::string Value::toYaml(int indent) const {
    std::string out;
    toYamlRec(*this, out, 0, indent <= 0 ? 2 : indent);
    return out.empty() ? out : out.substr(1);
}

// ------------------------------------------------------------------ parser --

namespace {
struct JsonParser {
    std::string_view text;
    size_t pos = 0;
    std::string error;

    void skipWs() {
        while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\t' || text[pos] == '\n' || text[pos] == '\r')) ++pos;
    }
    bool eof() { return pos >= text.size(); }
    char peek() { return eof() ? '\0' : text[pos]; }
    bool fail(const std::string& m) {
        if (error.empty()) error = m + " at offset " + std::to_string(pos);
        return false;
    }

    bool parseString(std::string& out) {
        if (peek() != '"') return fail("expected string");
        ++pos;
        while (!eof()) {
            char c = text[pos++];
            if (c == '"') return true;
            if (c == '\\') {
                if (eof()) return fail("bad escape");
                char e = text[pos++];
                switch (e) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'n': out += '\n'; break;
                    case 't': out += '\t'; break;
                    case 'r': out += '\r'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'u': {
                        if (pos + 4 > text.size()) return fail("bad \\u escape");
                        unsigned code = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = text[pos++];
                            code <<= 4;
                            if (h >= '0' && h <= '9') code |= (unsigned)(h - '0');
                            else if (h >= 'a' && h <= 'f') code |= (unsigned)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') code |= (unsigned)(h - 'A' + 10);
                            else return fail("bad \\u escape");
                        }
                        if (code < 0x80) out += (char)code;
                        else if (code < 0x800) { out += (char)(0xC0 | (code >> 6)); out += (char)(0x80 | (code & 0x3F)); }
                        else { out += (char)(0xE0 | (code >> 12)); out += (char)(0x80 | ((code >> 6) & 0x3F)); out += (char)(0x80 | (code & 0x3F)); }
                        break;
                    }
                    default: return fail("bad escape");
                }
                continue;
            }
            out += c;
        }
        return fail("unterminated string");
    }

    bool parseValue(Value& out, int depth) {
        if (depth > 64) return fail("nesting too deep");
        skipWs();
        char c = peek();
        if (c == '{') {
            ++pos;
            out = Value::object();
            skipWs();
            if (peek() == '}') { ++pos; return true; }
            while (true) {
                skipWs();
                std::string key;
                if (!parseString(key)) return false;
                skipWs();
                if (peek() != ':') return fail("expected ':'");
                ++pos;
                Value child;
                if (!parseValue(child, depth + 1)) return false;
                out.set(key, std::move(child));
                skipWs();
                if (peek() == ',') { ++pos; continue; }
                if (peek() == '}') { ++pos; return true; }
                return fail("expected ',' or '}'");
            }
        }
        if (c == '[') {
            ++pos;
            out = Value::array();
            skipWs();
            if (peek() == ']') { ++pos; return true; }
            while (true) {
                Value child;
                if (!parseValue(child, depth + 1)) return false;
                out.push(std::move(child));
                skipWs();
                if (peek() == ',') { ++pos; continue; }
                if (peek() == ']') { ++pos; return true; }
                return fail("expected ',' or ']'");
            }
        }
        if (c == '"') {
            std::string s;
            if (!parseString(s)) return false;
            out = Value::str(std::move(s));
            return true;
        }
        if (text.substr(pos, 4) == "true") { pos += 4; out = Value::boolean(true); return true; }
        if (text.substr(pos, 5) == "false") { pos += 5; out = Value::boolean(false); return true; }
        if (text.substr(pos, 4) == "null") { pos += 4; out = Value::null(); return true; }
        size_t start = pos;
        while (pos < text.size() && (std::isdigit((unsigned char)text[pos]) || text[pos] == '-' || text[pos] == '+' ||
                                     text[pos] == '.' || text[pos] == 'e' || text[pos] == 'E'))
            ++pos;
        if (pos == start) return fail("unexpected token");
        auto num = str::parseDouble(text.substr(start, pos - start));
        if (!num) return fail("invalid number");
        out = Value::number(*num);
        return true;
    }
};
} // namespace

Value Value::parseJson(std::string_view text, std::string* error) {
    JsonParser p{text, 0, {}};
    Value out;
    if (!p.parseValue(out, 0)) {
        if (error) *error = p.error;
        return Value();
    }
    p.skipWs();
    if (!p.eof()) {
        if (error) *error = "trailing data at offset " + std::to_string(p.pos);
        return Value();
    }
    if (error) error->clear();
    return out;
}

} // namespace s3mm
