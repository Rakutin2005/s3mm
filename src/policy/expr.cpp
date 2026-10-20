#include "s3mm/policy/expr.hpp"

#include <algorithm>
#include <regex>

#include "s3mm/common/glob.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/units.hpp"

namespace s3mm::policy {

std::string PValue::toString() const {
    switch (kind_) {
        case Kind::String: return str_;
        case Kind::Number: {
            double d = num_;
            if (d == (double)(int64_t)d) return std::to_string((int64_t)d);
            return std::to_string(d);
        }
        case Kind::Bool: return bool_ ? "true" : "false";
        case Kind::List: return str::join(list_, ",");
    }
    return {};
}

std::string Context::dump() const {
    std::vector<std::string> parts;
    for (const auto& [k, v] : attrs_) parts.push_back(k + "=" + v.toString());
    return str::join(parts, " ");
}

// ------------------------------------------------------------------ compare --

static std::optional<double> literalAsNumber(const std::string& literal) {
    if (auto d = str::parseDouble(literal)) return d;
    if (auto sz = units::tryParseSize(literal)) return (double)*sz;
    return std::nullopt;
}

bool compare(const PValue& left, Op op, const std::string& literal, const std::vector<std::string>& list) {
    switch (op) {
        case Op::Exists: return true;
        case Op::In: {
            std::string s = left.toString();
            if (left.isList()) {
                for (const auto& item : left.asList()) {
                    for (const auto& v : list)
                        if (v == item || glob::match(v, item)) return true;
                }
                return false;
            }
            for (const auto& v : list)
                if (v == s || glob::match(v, s)) return true;
            return false;
        }
        case Op::Regex:
        case Op::NotRegex: {
            bool matched = false;
            try {
                std::regex re(literal, std::regex::ECMAScript | std::regex::icase);
                matched = std::regex_match(left.toString(), re);
            } catch (const std::regex_error&) {
                matched = false;
            }
            return op == Op::Regex ? matched : !matched;
        }
        default: break;
    }

    if (left.isList()) {
        for (const auto& item : left.asList())
            if (compare(PValue::str(item), op, literal, {})) return true;
        return false;
    }

    if (left.isBool()) {
        std::string lit = str::toLower(literal);
        bool litBool = (lit == "true" || lit == "on" || lit == "yes" || lit == "1");
        switch (op) {
            case Op::Eq: return left.asBool() == litBool;
            case Op::Ne: return left.asBool() != litBool;
            default: break;
        }
    }

    auto litNum = literalAsNumber(literal);
    if (left.isNumber() && litNum) {
        double a = left.asNumber(), b = *litNum;
        switch (op) {
            case Op::Eq: return a == b;
            case Op::Ne: return a != b;
            case Op::Lt: return a < b;
            case Op::Le: return a <= b;
            case Op::Gt: return a > b;
            case Op::Ge: return a >= b;
            default: return false;
        }
    }

    const std::string& a = left.toString();
    switch (op) {
        case Op::Eq: return a == literal;
        case Op::Ne: return a != literal;
        case Op::Lt: return a < literal;
        case Op::Le: return a <= literal;
        case Op::Gt: return a > literal;
        case Op::Ge: return a >= literal;
        default: return false;
    }
}

const char* opName(Op op) {
    switch (op) {
        case Op::Eq: return "=";
        case Op::Ne: return "!=";
        case Op::Lt: return "<";
        case Op::Le: return "<=";
        case Op::Gt: return ">";
        case Op::Ge: return ">=";
        case Op::Regex: return "~";
        case Op::NotRegex: return "!~";
        case Op::In: return "in";
        case Op::Exists: return "exists";
    }
    return "?";
}

// ------------------------------------------------------------------- nodes --

bool AllExpr::eval(const Context& ctx) const {
    for (const auto& e : items_)
        if (!e->eval(ctx)) return false;
    return true;
}

std::string AllExpr::toString() const {
    std::vector<std::string> parts;
    for (const auto& e : items_) parts.push_back(e->toString());
    return str::join(parts, " and ");
}

void AllExpr::collectFields(std::vector<std::string>& out) const {
    for (const auto& e : items_) e->collectFields(out);
}

bool AnyExpr::eval(const Context& ctx) const {
    for (const auto& e : items_)
        if (e->eval(ctx)) return true;
    return false;
}

std::string AnyExpr::toString() const {
    std::vector<std::string> parts;
    for (const auto& e : items_) parts.push_back(e->toString());
    return "(" + str::join(parts, " or ") + ")";
}

void AnyExpr::collectFields(std::vector<std::string>& out) const {
    for (const auto& e : items_) e->collectFields(out);
}

bool CmpExpr::eval(const Context& ctx) const {
    const PValue* v = ctx.find(field_);
    if (!v) {
        // A missing attribute never matches, except for negative comparisons.
        return op_ == Op::Ne || op_ == Op::NotRegex;
    }
    return compare(*v, op_, literal_, list_);
}

std::string CmpExpr::toString() const {
    if (op_ == Op::In) return field_ + " in [" + str::join(list_, ",") + "]";
    if (op_ == Op::Exists) return field_ + " exists";
    std::string lit = literal_;
    bool needQuote = lit.empty();
    for (char c : lit)
        if (c == ' ' || c == '\t' || c == '\'' || c == '"') needQuote = true;
    if (needQuote) lit = str::quoteShell(lit);
    return field_ + opName(op_) + lit;
}

bool ExistsExpr::eval(const Context& ctx) const {
    bool present = ctx.find(field_) != nullptr;
    return negate_ ? !present : present;
}

std::string ExistsExpr::toString() const { return field_ + (negate_ ? " !exists" : " exists"); }

} // namespace s3mm::policy
