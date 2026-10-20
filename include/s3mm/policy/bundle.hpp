#pragma once
#include <map>
#include <string>
#include <vector>

#include "s3mm/common/result.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/policy/rule.hpp"

namespace s3mm::policy {

/// Per-bundle default routing for the three result classes.
/// `success` empty means "<replication-name>-rqueue" (the replication's own queue).
struct RouteTable {
    std::string denied = "null";
    std::string warning = "quarantine";
    std::string success; // empty => <replication>-rqueue
};

/// A named bundle of rules + defaults: this is what `s3mm policy` manages and
/// what `add replication --policy <name>` selects.
struct Bundle {
    std::string name;
    std::map<Category, Action> defaults; // default action per category
    RouteTable routes;
    std::vector<Rule> rules; // kept sorted by order

    const Rule* findRule(const std::string& nameOrNumber) const;
    const Rule* findRuleByOrder(int order) const;
    std::vector<const Rule*> rulesOf(Category c) const;
    int nextOrder() const;

    /// Insert a rule, optionally before/after an existing rule (by number or name).
    Result<void> addRule(Rule rule, const std::string& before = {}, const std::string& after = {});
    Result<void> removeRule(const std::string& nameOrNumber);
    /// Replace a rule in place (matched by name or order number).
    Result<void> replaceRule(const std::string& nameOrNumber, Rule rule);

    Action defaultAction(Category c) const;

    /// Render this bundle as an s3mm.conf block.
    std::string dump(int indent = 0) const;

    /// Parse a `policy <name> { ... }` config block.
    static Result<Bundle> fromNode(const config::Node& node);
    /// Built-in bundles that always exist: "drop-all" and "default".
    static Bundle builtin(const std::string& name);
};

} // namespace s3mm::policy
