#include "s3mm/cli/render.hpp"

#include <algorithm>
#include <sstream>

#include "s3mm/common/error.hpp"
#include "s3mm/common/log.hpp"

namespace s3mm::cli {

Format formatFromString(const std::string& s) {
    if (s.empty() || s == "table") return Format::Table;
    if (s == "json") return Format::Json;
    if (s == "yaml") return Format::Yaml;
    LOG_WARN("unknown output format '", s, "'");
    throw UsageError("unknown output format '" + s + "' (table|json|yaml)");
}

std::string cell(const Value& v) {
    switch (v.type()) {
        case Value::Type::Null:
            return "";
        case Value::Type::Bool:
            return v.asBool() ? "yes" : "no";
        case Value::Type::Number:
            return v.toJson();
        case Value::Type::String:
            return v.asString();
        case Value::Type::Array: {
            std::string out;
            for (const auto& it : v.items()) {
                if (!out.empty()) out += ",";
                out += it.isString() ? it.asString() : it.toJson();
            }
            return out;
        }
        case Value::Type::Object:
            return v.toJson();
    }
    return {};
}

namespace {

bool scalarArray(const Value& v) {
    if (!v.isArray()) return false;
    for (const auto& it : v.items())
        if (it.isObject() || it.isArray()) return false;
    return true;
}

/// Array of objects as an aligned column table.
std::string arrayTable(const Value& v) {
    std::vector<std::string> cols;
    for (const auto& row : v.items()) {
        if (!row.isObject()) continue;
        for (const auto& [k, val] : row.members())
            if (std::find(cols.begin(), cols.end(), k) == cols.end()) cols.push_back(k);
    }
    if (cols.empty()) {
        // plain scalar array: one element per line
        std::string out;
        for (const auto& row : v.items()) out += cell(row) + "\n";
        return out;
    }
    std::vector<size_t> width(cols.size());
    for (size_t i = 0; i < cols.size(); ++i) width[i] = cols[i].size();

    std::vector<std::vector<std::string>> rows;
    for (const auto& row : v.items()) {
        if (!row.isObject()) {
            rows.push_back({cell(row)});
            continue;
        }
        std::vector<std::string> out(cols.size());
        for (size_t i = 0; i < cols.size(); ++i) {
            const Value* f = row.find(cols[i]);
            out[i] = f ? cell(*f) : "";
            width[i] = std::max(width[i], out[i].size());
        }
        rows.push_back(std::move(out));
    }
    if (rows.empty()) return {};

    std::ostringstream os;
    for (size_t i = 0; i < cols.size(); ++i) {
        if (i) os << "  ";
        os << cols[i];
    }
    os << "\n";
    for (size_t i = 0; i < cols.size(); ++i) {
        if (i) os << "  ";
        os << std::string(width[i], '-');
    }
    os << "\n";
    for (const auto& row : rows) {
        for (size_t i = 0; i < row.size(); ++i) {
            if (i) os << "  ";
            os << row[i];
        }
        os << "\n";
    }
    return os.str();
}

/// Scalar array as `key: a,b,c`, or as an indented list when too wide.
void emitArray(std::ostringstream& os, const std::string& indent, const std::string& key,
               const Value& v) {
    if (v.items().empty()) {
        os << indent << key << ":\n";
        return;
    }
    if (scalarArray(v)) {
        std::string joined = cell(v);
        if (joined.size() <= 72) {
            os << indent << key << ": " << joined << "\n";
            return;
        }
        os << indent << key << ":\n";
        for (const auto& it : v.items()) os << indent << "  - " << cell(it) << "\n";
        return;
    }
    // array of objects (or mixed): one compact line per element
    os << indent << key << ":\n";
    for (const auto& item : v.items()) {
        if (item.isObject()) {
            std::string line;
            for (const auto& [k, val] : item.members()) {
                if (!line.empty()) line += "  ";
                line += k + "=" + cell(val);
            }
            os << indent << "  - " << line << "\n";
        } else {
            os << indent << "  - " << cell(item) << "\n";
        }
    }
}

void emitObject(std::ostringstream& os, const std::string& indent, const Value& v) {
    for (const auto& [k, val] : v.members()) {
        if (val.isObject()) {
            os << indent << k << ":\n";
            emitObject(os, indent + "  ", val);
        } else if (val.isArray()) {
            emitArray(os, indent, k, val);
        } else {
            os << indent << k << ": " << cell(val) << "\n";
        }
    }
}

} // namespace

std::string render(const Value& v, Format f) {
    LOG_DEBUG("rendering ", v.isArray() ? "array" : v.isObject() ? "object" : "value", " of ", v.size(),
              " item(s) as ", f == Format::Json ? "json" : f == Format::Yaml ? "yaml" : "table");
    if (f == Format::Json) {
        std::string out = v.toJson(2);
        if (out.empty() || out.back() != '\n') out += "\n";
        return out;
    }
    if (f == Format::Yaml) {
        std::string out = v.toYaml();
        if (!out.empty() && out.back() != '\n') out += "\n";
        return out;
    }
    // table
    if (v.isArray()) return arrayTable(v);
    if (v.isObject()) {
        std::ostringstream os;
        emitObject(os, "", v);
        return os.str();
    }
    std::string s = cell(v);
    return s.empty() ? s : s + "\n";
}

} // namespace s3mm::cli
