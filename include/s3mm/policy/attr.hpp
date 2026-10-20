#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "s3mm/common/time.hpp"

namespace s3mm::policy {

/// Typed attribute value used by the rule engine (distinct from the JSON-ish Value).
class PValue {
public:
    enum class Kind { String, Number, Bool, List };

    static PValue str(std::string s) { PValue v; v.kind_ = Kind::String; v.str_ = std::move(s); return v; }
    static PValue num(double d) { PValue v; v.kind_ = Kind::Number; v.num_ = d; return v; }
    static PValue num(int64_t d) { return num((double)d); }
    static PValue boolean(bool b) { PValue v; v.kind_ = Kind::Bool; v.bool_ = b; return v; }
    static PValue list(std::vector<std::string> items) { PValue v; v.kind_ = Kind::List; v.list_ = std::move(items); return v; }

    Kind kind() const { return kind_; }
    bool isNumber() const { return kind_ == Kind::Number; }
    bool isList() const { return kind_ == Kind::List; }
    bool isBool() const { return kind_ == Kind::Bool; }
    const std::string& asString() const { return str_; }
    double asNumber() const { return num_; }
    bool asBool() const { return bool_; }
    const std::vector<std::string>& asList() const { return list_; }

    /// Canonical string form for output and for string comparisons.
    std::string toString() const;

private:
    Kind kind_ = Kind::String;
    double num_ = 0;
    bool bool_ = false;
    std::string str_;
    std::vector<std::string> list_;
};

/// Attribute context handed to the engine for one evaluation.
class Context {
public:
    void set(const std::string& key, PValue v) { attrs_[key] = std::move(v); }
    void set(const std::string& key, const std::string& v) { attrs_[key] = PValue::str(v); }
    void set(const std::string& key, const char* v) { attrs_[key] = PValue::str(v); }
    void set(const std::string& key, uint64_t v) { attrs_[key] = PValue::num((double)v); }
    void set(const std::string& key, int64_t v) { attrs_[key] = PValue::num((double)v); }
    void set(const std::string& key, int v) { attrs_[key] = PValue::num((double)v); }
    void setBool(const std::string& key, bool v) { attrs_[key] = PValue::boolean(v); }
    void setTime(const std::string& key, tm::TimePoint t) {
        attrs_[key] = PValue::str(tm::toIso8601(t));
        attrs_[key + "-age"] = PValue::num((int64_t)std::chrono::duration_cast<std::chrono::seconds>(tm::now() - t).count());
    }
    void setTags(const std::string& prefix, const std::map<std::string, std::string>& tags) {
        for (const auto& [k, v] : tags) attrs_[prefix + "." + k] = PValue::str(v);
    }
    /// Alias: attrs_["destination.name"] = v
    void setAlias(const std::string& key, const std::string& alias) {
        auto it = attrs_.find(key);
        if (it != attrs_.end()) attrs_[alias] = it->second;
    }

    const PValue* find(const std::string& key) const {
        auto it = attrs_.find(key);
        return it == attrs_.end() ? nullptr : &it->second;
    }
    const std::map<std::string, PValue>& attrs() const { return attrs_; }

    /// Debug / logging helper: name=value pairs.
    std::string dump() const;

private:
    std::map<std::string, PValue> attrs_;
};

} // namespace s3mm::policy
