#include "s3mm/policy/lexer.hpp"

#include <cstring>
#include <optional>
#include <regex>

#include "s3mm/common/str.hpp"
#include "s3mm/common/units.hpp"

namespace s3mm::policy {

static const char* kTwoCharOps[] = {">=", "<=", "!=", "!~", "==", "=~"};
static const char* kOneCharOps[] = {">", "<", "=", "~"};

std::optional<std::string> validateRegex(const std::string& pattern) {
    try {
        std::regex re(pattern, std::regex::ECMAScript | std::regex::icase);
        (void)re;
        return std::nullopt;
    } catch (const std::regex_error& e) {
        return std::string("invalid regular expression '") + pattern + "': " + e.what();
    }
}

static std::optional<std::pair<Op, std::string>> splitOperator(const std::string& token) {
    for (const char* two : kTwoCharOps) {
        auto pos = token.find(two);
        if (pos != std::string::npos && pos > 0) {
            std::string right = token.substr(pos + 2);
            Op op;
            std::string opStr(two);
            if (opStr == ">=") op = Op::Ge;
            else if (opStr == "<=") op = Op::Le;
            else if (opStr == "!=") op = Op::Ne;
            else if (opStr == "!~") op = Op::NotRegex;
            else if (opStr == "==") op = Op::Eq;
            else op = Op::Regex; // "=~"
            return std::make_pair(op, right);
        }
    }
    for (const char* one : kOneCharOps) {
        auto pos = token.find(one);
        if (pos != std::string::npos && pos > 0) {
            Op op;
            std::string opStr(one);
            if (opStr == ">") op = Op::Gt;
            else if (opStr == "<") op = Op::Lt;
            else if (opStr == "=") op = Op::Eq;
            else op = Op::Regex;
            return std::make_pair(op, token.substr(pos + 1));
        }
    }
    return std::nullopt;
}

std::optional<Term> parseTerm(const std::string& token, const std::string& scopePrefix) {
    if (token.empty()) return std::nullopt;
    std::string field = token;
    std::string prefix = scopePrefix;

    for (const char* p : {"source.", "src."}) {
        if (str::startsWith(field, p)) {
            prefix = "";
            field = field.substr(std::strlen(p));
            break;
        }
    }
    for (const char* p : {"destination.", "dest."}) {
        if (str::startsWith(field, p)) {
            prefix = "destination.";
            field = field.substr(std::strlen(p));
            break;
        }
    }

    auto split = splitOperator(field);
    Term t;
    t.raw = token;
    if (!split) {
        t.field = prefix + field;
        t.op = Op::Exists;
        return t;
    }
    auto [op, literal] = *split;
    // strip the scope prefix from the left side, then re-apply
    std::string name = field.substr(0, field.find_first_of("=!<>~"));
    name = str::trim(name);
    for (const char* p : {"source.", "src.", "destination.", "dest."}) {
        if (str::startsWith(name, p)) {
            prefix = str::startsWith(name, "destination.") || str::startsWith(name, "dest.") ? "destination." : "";
            name = name.substr(std::strlen(p));
            break;
        }
    }
    t.field = prefix + name;
    t.op = op;
    t.value = literal;
    return t;
}

static bool isStopWord(const std::string& word, const std::vector<std::string>& stopWords) {
    for (const auto& s : stopWords)
        if (s == word) return true;
    return false;
}

static ExprPtr parseOr(Cursor& cur, std::string& scopePrefix, const std::vector<std::string>& stopWords, int depth);

static ExprPtr parsePrimary(Cursor& cur, std::string& scopePrefix, const std::vector<std::string>& stopWords, int depth) {
    if (cur.empty()) return nullptr;
    const std::string tok = cur.peek();

    if (tok == "(") {
        cur.next();
        auto inner = parseOr(cur, scopePrefix, stopWords, depth + 1);
        if (cur.peekIs(")")) cur.next();
        return inner;
    }
    if (tok == ")" || isStopWord(tok, stopWords)) return nullptr;
    if (tok == "source" || tok == "src") {
        cur.next();
        scopePrefix = "";
        return parsePrimary(cur, scopePrefix, stopWords, depth);
    }
    if (tok == "destination" || tok == "dest") {
        cur.next();
        scopePrefix = "destination.";
        return parsePrimary(cur, scopePrefix, stopWords, depth);
    }

    cur.next();
    // `field exists` / `field !exists`
    if (!cur.empty() && (cur.peek() == "exists" || cur.peek() == "!exists")) {
        bool negate = cur.peek() == "!exists";
        cur.next();
        auto term = parseTerm(tok, scopePrefix);
        if (!term) throw Error("invalid field in existence check: '" + tok + "'");
        return std::make_shared<ExistsExpr>(term->field, negate);
    }
    // `field in a,b,c`
    if (!cur.empty() && cur.peek() == "in") {
        cur.next();
        std::vector<std::string> list;
        while (!cur.empty() && !isStopWord(cur.peek(), stopWords) && cur.peek() != ")" && cur.peek() != "and" &&
               cur.peek() != "or" && cur.peek() != "not") {
            for (auto& part : str::splitList(cur.next())) list.push_back(part);
        }
        auto term = parseTerm(tok, scopePrefix);
        if (!term) throw Error("invalid field before 'in': '" + tok + "'");
        return std::make_shared<CmpExpr>(term->field, Op::In, "", std::move(list));
    }

    auto term = parseTerm(tok, scopePrefix);
    if (!term) throw Error("cannot parse condition term: '" + tok + "'");
    if (term->op == Op::Regex || term->op == Op::NotRegex) {
        if (auto err = validateRegex(term->value)) throw Error(*err);
    }
    return std::make_shared<CmpExpr>(term->field, term->op, term->value);
}

static ExprPtr parseNot(Cursor& cur, std::string& scopePrefix, const std::vector<std::string>& stopWords, int depth) {
    if (cur.peekIs("not") || (!cur.empty() && cur.peek() == "!")) {
        cur.next();
        auto inner = parseNot(cur, scopePrefix, stopWords, depth);
        if (!inner) throw Error("'not' must be followed by a condition");
        return std::make_shared<NotExpr>(inner);
    }
    return parsePrimary(cur, scopePrefix, stopWords, depth);
}

static ExprPtr parseAnd(Cursor& cur, std::string& scopePrefix, const std::vector<std::string>& stopWords, int depth) {
    auto left = parseNot(cur, scopePrefix, stopWords, depth);
    if (!left) return nullptr;
    std::vector<ExprPtr> items{std::move(left)};
    while (!cur.empty()) {
        if (cur.peekIs("and") || cur.peekIs("&&")) {
            cur.next();
            auto right = parseNot(cur, scopePrefix, stopWords, depth);
            if (!right) throw Error("'and' must be followed by a condition");
            items.push_back(std::move(right));
            continue;
        }
        if (cur.peekIs("or") || cur.peekIs("||") || cur.peekIs(")") || isStopWord(cur.peek(), stopWords)) break;
        // implicit AND
        auto right = parseNot(cur, scopePrefix, stopWords, depth);
        if (!right) break;
        items.push_back(std::move(right));
    }
    if (items.size() == 1) return items[0];
    return std::make_shared<AllExpr>(std::move(items));
}

static ExprPtr parseOr(Cursor& cur, std::string& scopePrefix, const std::vector<std::string>& stopWords, int depth) {
    auto left = parseAnd(cur, scopePrefix, stopWords, depth);
    if (!left) return nullptr;
    std::vector<ExprPtr> items{std::move(left)};
    while (!cur.empty() && (cur.peekIs("or") || cur.peekIs("||"))) {
        cur.next();
        auto right = parseAnd(cur, scopePrefix, stopWords, depth);
        if (!right) throw Error("'or' must be followed by a condition");
        items.push_back(std::move(right));
    }
    if (items.size() == 1) return items[0];
    return std::make_shared<AnyExpr>(std::move(items));
}

ExprPtr parseExpression(Cursor& cur, std::string& scopePrefix, const std::vector<std::string>& stopWords) {
    return parseOr(cur, scopePrefix, stopWords, 0);
}

} // namespace s3mm::policy
