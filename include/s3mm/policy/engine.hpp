#pragma once
#include <string>

#include "s3mm/policy/bundle.hpp"

namespace s3mm::policy {

/// Result of evaluating one entity (bucket/object/account) against a bundle.
struct Decision {
    std::string outcome;  // "success" | "denied" | "warning"
    std::string target;   // target group (basket) name; may be "null", "quarantine", <replication>-rqueue, ...
    std::vector<Action> actions;
    const Rule* rule = nullptr; // matched rule, nullptr when the default action applied
    bool viaDefault = false;

    bool accepted() const { return outcome == "success"; }
    /// Merge all `set`/`propagate` transforms into a flat key->value map.
    std::map<std::string, std::string> transforms() const;
    std::string toString() const;
};

class Engine {
public:
    /// Evaluate a context against a bundle. The first matching rule with an
    /// outcome action wins; `pass` rules are skipped. When nothing matches the
    /// bundle's default action for the category applies.
    Decision evaluate(const Bundle& bundle, Category category, const Context& ctx,
                      const std::string& replicationName) const;

    /// Derive outcome/target from a primary action (shared by rules and defaults).
    static void applyActionRouting(const Action& primary, const RouteTable& routes,
                                   const std::string& replicationName, Decision& out);
};

} // namespace s3mm::policy
