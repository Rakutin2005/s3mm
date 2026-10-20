#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace s3mm {

/// Minimal JSON-like value used for CLI output (-o json|yaml) and metrics.
class Value {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Value() = default;
    static Value null() { return Value(); }
    static Value boolean(bool b) { Value v; v.type_ = Type::Bool; v.bool_ = b; return v; }
    static Value number(double d) { Value v; v.type_ = Type::Number; v.num_ = d; return v; }
    static Value number(int64_t i) { Value v; v.type_ = Type::Number; v.num_ = (double)i; v.int_ = (int64_t)i; v.isInt_ = true; return v; }
    static Value number(uint64_t i) { return number((int64_t)i); }
    static Value str(std::string s) { Value v; v.type_ = Type::String; v.str_ = std::move(s); return v; }
    static Value array() { Value v; v.type_ = Type::Array; return v; }
    static Value object() { Value v; v.type_ = Type::Object; return v; }

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::Null; }
    bool isObject() const { return type_ == Type::Object; }
    bool isArray() const { return type_ == Type::Array; }
    bool isString() const { return type_ == Type::String; }

    bool asBool(bool def = false) const { return type_ == Type::Bool ? bool_ : def; }
    double asDouble(double def = 0) const { return type_ == Type::Number ? num_ : def; }
    int64_t asInt(int64_t def = 0) const {
        if (type_ != Type::Number) return def;
        return isInt_ ? int_ : (int64_t)num_;
    }
    const std::string& asString() const { return str_; }
    std::string asString(const std::string& def) const { return type_ == Type::String ? str_ : def; }

    // object access -----------------------------------------------------------
    Value& set(const std::string& key, Value v);
    const Value* find(const std::string& key) const;
    const std::string& getString(const std::string& key, const std::string& def = {}) const;
    const std::vector<std::pair<std::string, Value>>& members() const { return members_; }

    // array access ------------------------------------------------------------
    void push(Value v) { items_.push_back(std::move(v)); }
    const std::vector<Value>& items() const { return items_; }
    size_t size() const { return type_ == Type::Object ? members_.size() : items_.size(); }

    std::string toJson(int indent = 0) const;
    std::string toYaml(int indent = 0) const;

    /// Parse a JSON document (used for policy JSON payloads); returns null value on error.
    static Value parseJson(std::string_view text, std::string* error = nullptr);

private:
    Type type_ = Type::Null;
    bool bool_ = false;
    double num_ = 0;
    int64_t int_ = 0;
    bool isInt_ = false;
    std::string str_;
    std::vector<Value> items_;
    std::vector<std::pair<std::string, Value>> members_;
};

} // namespace s3mm
