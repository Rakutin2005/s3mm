#include "s3mm/policy/bundle.hpp"

#include <algorithm>
#include <set>
#include <sstream>

#include "s3mm/common/str.hpp"
#include "s3mm/policy/lexer.hpp"

namespace s3mm::policy {

const Rule* Bundle::findRule(const std::string& nameOrNumber) const {
    if (auto num = str::parseInt64(nameOrNumber)) {
        for (const auto& r : rules)
            if (r.order == (int)*num) return &r;
        return nullptr;
    }
    for (const auto& r : rules)
        if (r.name == nameOrNumber) return &r;
    return nullptr;
}

const Rule* Bundle::findRuleByOrder(int order) const {
    for (const auto& r : rules)
        if (r.order == order) return &r;
    return nullptr;
}

std::vector<const Rule*> Bundle::rulesOf(Category c) const {
    std::vector<const Rule*> out;
    for (const auto& r : rules)
        if (r.category == c) out.push_back(&r);
    return out;
}

int Bundle::nextOrder() const {
    int maxOrder = 0;
    for (const auto& r : rules) maxOrder = std::max(maxOrder, r.order);
    return maxOrder + 10;
}

static void sortByOrder(std::vector<Rule>& rules) {
    std::stable_sort(rules.begin(), rules.end(), [](const Rule& a, const Rule& b) { return a.order < b.order; });
}

Result<void> Bundle::addRule(Rule rule, const std::string& before, const std::string& after) {
    if (rule.name.empty() && findRule(std::to_string(rule.order))) {
        // explicit duplicate order: move to the end
        rule.order = nextOrder();
    }
    if (!before.empty()) {
        const Rule* ref = findRule(before);
        if (!ref) return Result<void>("no rule '" + before + "' in policy '" + name + "'");
        int refOrder = ref->order;
        int prevOrder = refOrder - 10;
        auto it = std::upper_bound(rules.begin(), rules.end(), refOrder,
                                   [](int v, const Rule& r) { return v < r.order; });
        if (it != rules.begin()) prevOrder = std::prev(it)->order;
        int candidate = (prevOrder + refOrder) / 2;
        if (candidate <= prevOrder || candidate >= refOrder) {
            // no room: shift the rest
            for (auto& r : rules)
                if (r.order >= refOrder) r.order += 10;
            candidate = refOrder;
        }
        rule.order = candidate;
    } else if (!after.empty()) {
        const Rule* ref = findRule(after);
        if (!ref) return Result<void>("no rule '" + after + "' in policy '" + name + "'");
        int refOrder = ref->order;
        int nextOrderVal = refOrder + 10;
        auto it = std::upper_bound(rules.begin(), rules.end(), refOrder,
                                   [](int v, const Rule& r) { return v < r.order; });
        if (it != rules.end()) nextOrderVal = it->order;
        int candidate = (refOrder + nextOrderVal) / 2;
        if (candidate <= refOrder || candidate >= nextOrderVal) {
            for (auto& r : rules)
                if (r.order > refOrder) r.order += 10;
            candidate = refOrder + 1;
        }
        rule.order = candidate;
    } else if (rule.order == 0) {
        rule.order = nextOrder();
    } else if (findRuleByOrder(rule.order)) {
        return Result<void>("rule with number " + std::to_string(rule.order) + " already exists in policy '" + name + "'");
    }
    if (!rule.name.empty()) {
        for (const auto& r : rules)
            if (!rule.name.empty() && r.name == rule.name)
                return Result<void>("rule named '" + rule.name + "' already exists in policy '" + name + "'");
    }
    rules.push_back(std::move(rule));
    sortByOrder(rules);
    return Result<void>::success();
}

Result<void> Bundle::removeRule(const std::string& nameOrNumber) {
    const Rule* r = findRule(nameOrNumber);
    if (!r) return Result<void>("no rule '" + nameOrNumber + "' in policy '" + name + "'");
    int order = r->order;
    rules.erase(std::remove_if(rules.begin(), rules.end(),
                               [&](const Rule& x) { return x.order == order; }),
                rules.end());
    return Result<void>::success();
}

Result<void> Bundle::replaceRule(const std::string& nameOrNumber, Rule rule) {
    const Rule* r = findRule(nameOrNumber);
    if (!r) return Result<void>("no rule '" + nameOrNumber + "' in policy '" + name + "'");
    int order = r->order;
    std::string oldName = r->name;
    rule.order = order;
    if (rule.name.empty()) rule.name = oldName;
    for (auto& existing : rules)
        if (existing.order == order) existing = std::move(rule);
    sortByOrder(rules);
    return Result<void>::success();
}

Action Bundle::defaultAction(Category c) const {
    auto it = defaults.find(c);
    if (it != defaults.end()) return it->second;
    Action a;
    a.name = "accept";
    return a;
}

static Action defaultDrop() {
    Action a;
    a.name = "drop";
    return a;
}

Bundle Bundle::builtin(const std::string& name) {
    Bundle b;
    b.name = name;
    if (name == "drop-all") {
        b.defaults[Category::Access] = defaultDrop();
        b.defaults[Category::Bucket] = defaultDrop();
        b.defaults[Category::Object] = defaultDrop();
        return b;
    }
    b.defaults[Category::Access] = Action{"accept", {}, {}};
    b.defaults[Category::Bucket] = Action{"accept", {}, {}};
    b.defaults[Category::Object] = Action{"accept", {}, {}};
    return b;
}

std::string Bundle::dump(int indent) const {
    std::string pad((size_t)indent, ' ');
    std::ostringstream os;
    os << pad << "policy " << name << " {\n";
    for (const auto& [cat, action] : defaults)
        os << pad << "    default_action " << categoryName(cat) << " " << action.toString() << ";\n";
    os << pad << "    default_route denied " << str::quoteShell(routes.denied) << ";\n";
    os << pad << "    default_route warning " << str::quoteShell(routes.warning) << ";\n";
    os << pad << "    default_route success " << str::quoteShell(routes.success) << ";\n";
    for (const auto& r : rules) os << pad << "    rule " << str::quoteShell(r.toString()) << ";\n";
    os << pad << "}";
    return os.str();
}

Result<Bundle> Bundle::fromNode(const config::Node& node) {
    Bundle b;
    b.name = node.argOr(0);
    if (b.name.empty()) return Result<Bundle>::failure("policy block requires a name");
    for (const auto& c : node.children) {
        if (c.name == "default_action") {
            if (c.args.size() < 2)
                return Result<Bundle>(c.file + ":" + std::to_string(c.line) + ": default_action requires <category> <action>");
            auto cat = categoryFromString(c.args[0]);
            if (!cat)
                return Result<Bundle>(c.file + ":" + std::to_string(c.line) + ": unknown category '" + c.args[0] + "'");
            Action a;
            a.name = c.args[1];
            if (!findActionSpec(a.name))
                return Result<Bundle>(c.file + ":" + std::to_string(c.line) + ": unknown action '" + a.name + "'");
            for (size_t i = 2; i < c.args.size(); ++i) {
                auto eq = c.args[i].find('=');
                if (eq == std::string::npos) {
                    if (findActionSpec(c.args[i]) && a.positional.empty() &&
                        findActionSpec(a.name)->positional)
                        a.positional = c.args[i];
                    else
                        return Result<Bundle>(c.file + ":" + std::to_string(c.line) + ": expected key=value, got '" + c.args[i] + "'");
                } else {
                    a.params[c.args[i].substr(0, eq)] = c.args[i].substr(eq + 1);
                }
            }
            b.defaults[*cat] = std::move(a);
            continue;
        }
        if (c.name == "default_route") {
            if (c.args.size() < 2)
                return Result<Bundle>(c.file + ":" + std::to_string(c.line) + ": default_route requires <outcome> <target>");
            const std::string& outcome = c.args[0];
            const std::string& target = c.args[1];
            if (outcome == "denied") b.routes.denied = target;
            else if (outcome == "warning") b.routes.warning = target;
            else if (outcome == "success") b.routes.success = target;
            else
                return Result<Bundle>(c.file + ":" + std::to_string(c.line) + ": default_route outcome must be denied|warning|success");
            continue;
        }
        if (c.name == "rule") {
            auto parsed = Rule::parse(Category::Object, c.args);
            if (!parsed) return Result<Bundle>(c.file + ":" + std::to_string(c.line) + ": " + parsed.error());
            Rule rule = parsed.value();
            rule.file = c.file;
            rule.line = c.line;
            auto res = b.addRule(std::move(rule));
            if (!res) return Result<Bundle>(c.file + ":" + std::to_string(c.line) + ": " + res.error());
            continue;
        }
        if (c.name == "include") continue;
        return Result<Bundle>(c.file + ":" + std::to_string(c.line) + ": unknown directive '" + c.name + "' inside policy block");
    }
    for (auto cat : {Category::Access, Category::Bucket, Category::Object})
        if (!b.defaults.count(cat)) b.defaults[cat] = Action{"accept", {}, {}};
    return Result<Bundle>(std::move(b));
}

} // namespace s3mm::policy
