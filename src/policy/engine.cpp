#include "s3mm/policy/engine.hpp"

#include <sstream>

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::policy {

std::map<std::string, std::string> Decision::transforms() const {
    std::map<std::string, std::string> out;
    for (const auto& a : actions) {
        if (a.name == "set" || a.name == "propagate") {
            for (const auto& [k, v] : a.params) out[k] = v;
            if (!a.positional.empty()) out["propagate"] = a.positional;
        }
    }
    return out;
}

std::string Decision::toString() const {
    std::ostringstream os;
    os << outcome << "->" << (target.empty() ? std::string("-") : target);
    if (rule) os << " rule=" << (rule->name.empty() ? std::to_string(rule->order) : rule->name);
    if (viaDefault) os << " (default)";
    return os.str();
}

void Engine::applyActionRouting(const Action& primary, const RouteTable& routes, const std::string& replicationName,
                                Decision& out) {
    if (primary.name == "accept") {
        out.outcome = "success";
        out.target = routes.success.empty() ? replicationName + "-rqueue" : routes.success;
    } else if (primary.name == "drop") {
        out.outcome = "denied";
        out.target = routes.denied.empty() ? "null" : routes.denied;
    } else if (primary.name == "quarantine") {
        out.outcome = "warning";
        out.target = primary.param("name", routes.warning.empty() ? "quarantine" : routes.warning);
    } else if (primary.name == "redirect") {
        out.outcome = "success";
        out.target = primary.positional;
    } else if (primary.name == "pass") {
        out.outcome.clear();
        out.target.clear();
    }
}

Decision Engine::evaluate(const Bundle& bundle, Category category, const Context& ctx,
                          const std::string& replicationName) const {
    Decision decision;
    for (const auto& rule : bundle.rules) {
        if (rule.category != category) continue;
        if (!rule.matches(ctx)) continue;
        // find the outcome action of this rule
        const Action* primary = nullptr;
        for (const auto& a : rule.actions) {
            const ActionSpec* spec = findActionSpec(a.name);
            if (spec && spec->terminal) {
                primary = &a;
                break;
            }
        }
        if (!primary) continue; // rule without outcome action: nothing to decide
        if (primary->name == "pass") continue; // pass = fall through to the next rule
        Decision d;
        d.rule = &rule;
        d.actions = rule.actions;
        applyActionRouting(*primary, bundle.routes, replicationName, d);
        if (d.outcome.empty()) continue;
        return d;
    }

    Action def = bundle.defaultAction(category);
    Decision d;
    d.viaDefault = true;
    d.actions.push_back(def);
    applyActionRouting(def, bundle.routes, replicationName, d);
    if (d.outcome.empty()) {
        // default action pass without target: fall back to accept.
        // A `redirect` with an empty positional is a rule-authoring error —
        // never silently reroute it into the success basket.
        const bool redirectNoTarget = def.name == "redirect" && def.positional.empty();
        if (redirectNoTarget) {
            d.outcome = "denied";
            d.target = bundle.routes.denied.empty() ? std::string("null") : bundle.routes.denied;
        } else {
            d.outcome = "success";
            d.target = bundle.routes.success.empty() ? replicationName + "-rqueue" : bundle.routes.success;
        }
    }
    return d;
}

} // namespace s3mm::policy
