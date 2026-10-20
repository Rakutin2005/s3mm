#pragma once
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/policy/expr.hpp"

namespace s3mm::policy {

enum class Category { Access, Bucket, Object };
const char* categoryName(Category c);
std::optional<Category> categoryFromString(const std::string& s); // acl|access|bucket|object

/// One action inside a rule: `log message="too big" level=warning` or `redirect quarantine-batch`.
struct Action {
    std::string name;
    std::string positional;  // first bare argument (e.g. redirect target)
    std::map<std::string, std::string> params;

    std::string param(const std::string& key, const std::string& fallback = {}) const {
        auto it = params.find(key);
        return it == params.end() ? fallback : it->second;
    }
    bool hasParam(const std::string& key) const { return params.count(key) > 0; }
    std::string toString() const;
};

struct ActionSpec {
    const char* name;
    bool terminal;    // determines the outcome of the rule (accept/drop/quarantine/redirect/pass)
    bool positional;  // takes a bare positional argument
};

const ActionSpec* findActionSpec(const std::string& name);
const std::vector<ActionSpec>& allActionSpecs();

struct Rule {
    int order = 0;
    std::string name;
    Category category = Category::Object;
    ExprPtr condition; // nullptr = match everything
    std::vector<Action> actions;
    std::string source; // original tokens, for round-tripping
    std::string file;
    int line = 0;

    bool matches(const Context& ctx) const { return !condition || condition->eval(ctx); }
    std::string conditionText() const { return condition ? condition->toString() : "true"; }
    /// Canonical single-line DSL representation.
    std::string toString() const;

    /// Parse a rule from tokens (already quote-resolved). `category` may be
    /// overridden by a leading category token inside the tokens.
    static Result<Rule> parse(Category category, const std::vector<std::string>& tokens);
    /// Parse a full rule line: [order] [name=..] <category> <condition> action <actions>
    static Result<Rule> parseLine(const std::string& line);
};

} // namespace s3mm::policy
