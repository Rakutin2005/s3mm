#pragma once
#include <string>
#include <vector>

#include "s3mm/policy/expr.hpp"

namespace s3mm::policy {

/// Cursor over the token list produced by the CLI/config layer (quotes already
/// resolved: `message='a b'` arrives as the single token `message=a b`).
struct Cursor {
    const std::vector<std::string>& toks;
    size_t pos = 0;

    bool empty() const { return pos >= toks.size(); }
    const std::string& peek() const { return toks[empty() ? toks.size() - 1 : pos]; }
    const std::string& next() { return toks[pos++]; }
    bool peekIs(const char* word) const { return !empty() && peek() == word; }
    bool peekIsAny(std::initializer_list<const char*> words) const {
        if (empty()) return false;
        for (const char* w : words)
            if (peek() == w) return true;
        return false;
    }
    std::string rest() const {
        std::string out;
        for (size_t i = pos; i < toks.size(); ++i) {
            if (!out.empty()) out += ' ';
            out += toks[i];
        }
        return out;
    }
};

/// A single parsed comparison: `field op value`.
struct Term {
    std::string field;      // resolved field name (scope prefix applied)
    Op op = Op::Eq;
    std::string value;
    std::vector<std::string> list;
    std::string raw;
};

/// Split one token such as `size>=50G`, `name=b1`, `!~^tmp/`, `enabled` into a Term.
/// `scopePrefix` ("", "destination.") is applied unless the token carries its own
/// explicit `source.`/`destination.` prefix.
std::optional<Term> parseTerm(const std::string& token, const std::string& scopePrefix);

/// Parse an expression from the cursor. Stops at any of `stopWords`, at a
/// depth-0 closing parenthesis, or at the end of input.
ExprPtr parseExpression(Cursor& cur, std::string& scopePrefix, const std::vector<std::string>& stopWords);

/// Validate a regular expression literal; returns error text when invalid.
std::optional<std::string> validateRegex(const std::string& pattern);

} // namespace s3mm::policy
