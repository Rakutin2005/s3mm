#include "s3mm/policy/rule.hpp"

#include <algorithm>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/policy/lexer.hpp"

namespace s3mm::policy {

const char* categoryName(Category c) {
    switch (c) {
        case Category::Access: return "acl";
        case Category::Bucket: return "bucket";
        case Category::Object: return "object";
    }
    return "object";
}

std::optional<Category> categoryFromString(const std::string& s) {
    if (s == "acl" || s == "access") return Category::Access;
    if (s == "bucket") return Category::Bucket;
    if (s == "object") return Category::Object;
    return std::nullopt;
}

static const std::vector<ActionSpec> kActions = {
    {"accept", true, false},   {"drop", true, false},        {"quarantine", true, false},
    {"redirect", true, true},  {"pass", true, false},        {"log", false, false},
    {"set", false, false},     {"propagate", false, false},
};

const ActionSpec* findActionSpec(const std::string& name) {
    for (const auto& a : kActions)
        if (name == a.name) return &a;
    return nullptr;
}

const std::vector<ActionSpec>& allActionSpecs() { return kActions; }

std::string Action::toString() const {
    std::string out = name;
    if (positional.empty() && params.empty()) return out;
    if (!positional.empty()) out += " " + str::quoteShell(positional);
    for (const auto& [k, v] : params) out += " " + k + "=" + str::quoteShell(v);
    return out;
}

std::string Rule::toString() const {
    std::string out = std::to_string(order);
    if (!name.empty()) out += " name=" + str::quoteShell(name);
    out += " ";
    out += categoryName(category);
    if (condition) out += " " + condition->toString();
    out += " action ";
    std::vector<std::string> parts;
    for (const auto& a : actions) parts.push_back(a.toString());
    out += str::join(parts, ", ");
    return out;
}

// ------------------------------------------------------------------- parse --

static Result<void> validateActions(const std::vector<Action>& actions) {
    if (actions.empty()) return Result<void>("rule has no actions (use 'action accept|drop|...')");
    int terminals = 0;
    bool hasAcceptDrop = false;
    for (const auto& a : actions) {
        const ActionSpec* spec = findActionSpec(a.name);
        if (!spec) {
            std::vector<std::string> names;
            for (const auto& s : kActions) names.push_back(s.name);
            return Result<void>("unknown action '" + a.name + "' (known: " + str::join(names, ",") + ")");
        }
        if (spec->terminal) {
            ++terminals;
            if (a.name == "accept" || a.name == "drop") hasAcceptDrop = true;
            if (a.name == "pass" && hasAcceptDrop)
                return Result<void>("action 'pass' cannot be combined with accept/drop in one rule");
        }
        if (a.name == "quarantine" && a.hasParam("name") && a.param("name").empty())
            return Result<void>("quarantine action requires a non-empty name=");
        if (a.name == "redirect" && a.positional.empty())
            return Result<void>("redirect action requires a target batch name: redirect <batch>");
        if (a.name == "pass" && (!a.positional.empty() || !a.params.empty()))
            return Result<void>("action 'pass' takes no arguments");
    }
    if (terminals > 1)
        return Result<void>("rule has " + std::to_string(terminals) +
                            " outcome actions (accept/drop/quarantine/redirect/pass); only one is allowed");
    return Result<void>::success();
}

Result<Rule> Rule::parse(Category category, const std::vector<std::string>& tokens) {
    Rule rule;
    rule.category = category;
    for (const auto& t : tokens) {
        if (!rule.source.empty()) rule.source += ' ';
        rule.source += str::quoteShell(t);
    }
    if (tokens.empty()) return Result<Rule>::failure("empty rule");

    size_t i = 0;
    // optional order number
    if (auto num = str::parseInt64(tokens[0])) {
        if (tokens.size() > 1) {
            rule.order = (int)*num;
            i = 1;
        }
    }
    // optional name=...
    while (i < tokens.size() && str::startsWith(tokens[i], "name=")) {
        rule.name = tokens[i].substr(5);
        ++i;
    }
    // optional category token
    if (i < tokens.size()) {
        if (auto cat = categoryFromString(tokens[i])) {
            rule.category = *cat;
            ++i;
        }
    }

    // condition tokens up to 'action'
    std::vector<std::string> condTokens;
    while (i < tokens.size() && tokens[i] != "action") {
        condTokens.push_back(tokens[i]);
        ++i;
    }
    // Join `field op value` triplets into single tokens ("size" ">=" "1M" -> "size>=1M")
    // so the lexer's term parser can apply the operator.
    {
        static const char* const ops[] = {">=", "<=", "!=", "!~", "==", "=~", ">", "<", "=", "~"};
        auto isOp = [&](const std::string& t) {
            for (const char* o : ops) if (t == o) return true;
            return false;
        };
        std::vector<std::string> joined;
        size_t n = 0;
        while (n < condTokens.size()) {
            if (n + 2 < condTokens.size() && isOp(condTokens[n + 1])) {
                joined.push_back(condTokens[n] + condTokens[n + 1] + condTokens[n + 2]);
                n += 3;
            } else {
                joined.push_back(condTokens[n]);
                ++n;
            }
        }
        condTokens.swap(joined);
    }
    if (i < tokens.size() && tokens[i] == "action") ++i;

    std::string scope;
    try {
        Cursor cur{condTokens};
        auto expr = parseExpression(cur, scope, {});
        if (!cur.empty()) {
            LOG_DEBUG("rule parse: unexpected token '", cur.peek(), "' in condition of: ", rule.source);
            return Result<Rule>::failure("unexpected token in condition: '" + cur.peek() + "'");
        }
        rule.condition = expr; // nullptr = match all
    } catch (const Error& e) {
        LOG_DEBUG("rule parse: condition error in: ", rule.source, ": ", e.what());
        return Result<Rule>::failure(e.what());
    }

    // action list
    std::vector<std::string> actTokens(tokens.begin() + (long)i, tokens.end());
    std::vector<Action> actions;
    Action* current = nullptr;
    for (size_t n = 0; n < actTokens.size(); ++n) {
        std::string tok = actTokens[n];
        // a token may carry a trailing comma: `accept,` or `log,`
        while (!tok.empty() && tok.back() == ',') tok.pop_back();
        if (tok.empty()) continue;
        auto eq = tok.find('=');
        std::string key = eq == std::string::npos ? std::string() : tok.substr(0, eq);
        if (findActionSpec(tok)) {
            actions.push_back(Action{tok, {}, {}});
            current = &actions.back();
            continue;
        }
        if (!current) return Result<Rule>::failure("action name expected, got '" + tok + "'");
        const ActionSpec* spec = findActionSpec(current->name);
        if (spec && spec->positional && current->positional.empty() && eq == std::string::npos) {
            current->positional = tok;
            continue;
        }
        if (eq == std::string::npos)
            return Result<Rule>::failure("parameter 'key=value' expected in action '" + current->name + "', got '" + tok + "'");
        current->params[key] = tok.substr(eq + 1);
    }

    auto err = validateActions(actions);
    if (!err) {
        LOG_DEBUG("rule parse: invalid actions in: ", rule.source, ": ", err.error());
        return Result<Rule>::failure(err.error());
    }
    rule.actions = std::move(actions);
    LOG_DEBUG("rule parsed: ", rule.toString());
    return Result<Rule>(std::move(rule));
}

Result<Rule> Rule::parseLine(const std::string& line) {
    std::vector<std::string> tokens;
    try {
        tokens = str::tokenize(line);
    } catch (const Error& e) {
        LOG_DEBUG("rule parse: cannot tokenize '", log::clip(line), "': ", e.what());
        return Result<Rule>::failure(e.what());
    }
    if (tokens.empty()) return Result<Rule>::failure("empty rule line");
    size_t start = 0;
    Category defaultCat = Category::Object;
    // first token may be the word "rule"
    if (tokens[0] == "rule") start = 1;
    if (start >= tokens.size()) return Result<Rule>::failure("rule body is missing");
    std::vector<std::string> rest(tokens.begin() + (long)start, tokens.end());
    return Rule::parse(defaultCat, rest);
}

} // namespace s3mm::policy
