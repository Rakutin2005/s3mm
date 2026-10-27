#include "s3mm/policy/bundle.hpp"

#include <algorithm>
#include <set>
#include <sstream>

#include "s3mm/common/log.hpp"
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
        LOG_DEBUG("policy '", name, "': rule number ", rule.order, " taken, renumbering to ", nextOrder());
        rule.order = nextOrder();
    }
    if (!before.empty()) {
        const Rule* ref = findRule(before);
        if (!ref) {
            LOG_ERROR("policy '", name, "': add rule: no rule '", before, "' to insert before");
            return Result<void>("no rule '" + before + "' in policy '" + name + "'");
        }
        int refOrder = ref->order;
        int prevOrder = 0;
        for (const auto& r : rules)
            if (r.order < refOrder && r.order > prevOrder) prevOrder = r.order;
        int candidate;
        if (prevOrder + 1 < refOrder) {
            candidate = (prevOrder + refOrder) / 2;
            if (candidate <= prevOrder) candidate = prevOrder + 1;
        } else {
            for (auto& r : rules)
                if (r.order >= refOrder) r.order += 10;
            candidate = refOrder;
        }
        rule.order = candidate;
    } else if (!after.empty()) {
        const Rule* ref = findRule(after);
        if (!ref) {
            LOG_ERROR("policy '", name, "': add rule: no rule '", after, "' to insert after");
            return Result<void>("no rule '" + after + "' in policy '" + name + "'");
        }
        int refOrder = ref->order;
        int nextOrderVal = refOrder + 10;
        for (const auto& r : rules)
            if (r.order > refOrder && r.order < nextOrderVal) nextOrderVal = r.order;
        int candidate;
        if (refOrder + 1 < nextOrderVal) {
            candidate = (refOrder + nextOrderVal) / 2;
            if (candidate <= refOrder) candidate = refOrder + 1;
        } else {
            for (auto& r : rules)
                if (r.order > refOrder) r.order += 10;
            candidate = refOrder + 1;
        }
        rule.order = candidate;
    } else if (rule.order == 0) {
        rule.order = nextOrder();
    } else if (findRuleByOrder(rule.order)) {
        LOG_ERROR("policy '", name, "': rule number ", rule.order, " already exists");
        return Result<void>("rule with number " + std::to_string(rule.order) + " already exists in policy '" + name + "'");
    }
    if (!rule.name.empty()) {
        for (const auto& r : rules)
            if (!rule.name.empty() && r.name == rule.name) {
                LOG_ERROR("policy '", name, "': rule named '", rule.name, "' already exists");
                return Result<void>("rule named '" + rule.name + "' already exists in policy '" + name + "'");
            }
    }
    LOG_DEBUG("policy '", name, "': rule added: ", rule.toString());
    rules.push_back(std::move(rule));
    sortByOrder(rules);
    return Result<void>::success();
}

Result<void> Bundle::removeRule(const std::string& nameOrNumber) {
    const Rule* r = findRule(nameOrNumber);
    if (!r) {
        LOG_ERROR("policy '", name, "': remove rule: no rule '", nameOrNumber, "'");
        return Result<void>("no rule '" + nameOrNumber + "' in policy '" + name + "'");
    }
    int order = r->order;
    LOG_DEBUG("policy '", name, "': rule removed: ", r->toString());
    rules.erase(std::remove_if(rules.begin(), rules.end(),
                               [&](const Rule& x) { return x.order == order; }),
                rules.end());
    return Result<void>::success();
}

Result<void> Bundle::replaceRule(const std::string& nameOrNumber, Rule rule) {
    const Rule* r = findRule(nameOrNumber);
    if (!r) {
        LOG_ERROR("policy '", name, "': replace rule: no rule '", nameOrNumber, "'");
        return Result<void>("no rule '" + nameOrNumber + "' in policy '" + name + "'");
    }
    int order = r->order;
    std::string oldName = r->name;
    LOG_DEBUG("policy '", name, "': rule ", order, " replaced: ", r->toString(), " => ", rule.toString());
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
    LOG_DEBUG("using built-in policy '", name, "' (", name == "drop-all" ? "drop" : "accept", " everything)");
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
    if (b.name.empty()) {
        LOG_ERROR(node.file, ":", node.line, ": policy block requires a name");
        return Result<Bundle>::failure("policy block requires a name");
    }
    log::Stopwatch sw;
    LOG_DEBUG("compiling policy '", b.name, "' from ", node.file, ":", node.line, " (", node.children.size(),
              " directive(s))");
    auto fail = [&](const std::string& msg) {
        LOG_ERROR("policy '", b.name, "': ", msg);
        return Result<Bundle>::failure(msg);
    };
    for (const auto& c : node.children) {
        if (c.name == "default_action") {
            if (c.args.size() < 2)
                return fail(c.file + ":" + std::to_string(c.line) + ": default_action requires <category> <action>");
            auto cat = categoryFromString(c.args[0]);
            if (!cat)
                return fail(c.file + ":" + std::to_string(c.line) + ": unknown category '" + c.args[0] + "'");
            Action a;
            a.name = c.args[1];
            if (!findActionSpec(a.name))
                return fail(c.file + ":" + std::to_string(c.line) + ": unknown action '" + a.name + "'");
            for (size_t i = 2; i < c.args.size(); ++i) {
                auto eq = c.args[i].find('=');
                if (eq == std::string::npos) {
                    if (a.positional.empty() && findActionSpec(a.name)->positional)
                        a.positional = c.args[i];
                    else
                        return fail(c.file + ":" + std::to_string(c.line) + ": expected key=value, got '" + c.args[i] + "'");
                } else {
                    a.params[c.args[i].substr(0, eq)] = c.args[i].substr(eq + 1);
                }
            }
            if (a.name == "redirect" && a.positional.empty())
                return fail(c.file + ":" + std::to_string(c.line) +
                            ": default_action redirect requires a target batch name: redirect <batch>");
            LOG_DEBUG("policy '", b.name, "': default_action ", categoryName(*cat), " ", a.toString());
            b.defaults[*cat] = std::move(a);
            continue;
        }
        if (c.name == "default_route") {
            if (c.args.size() < 2)
                return fail(c.file + ":" + std::to_string(c.line) + ": default_route requires <outcome> <target>");
            const std::string& outcome = c.args[0];
            const std::string& target = c.args[1];
            if (outcome == "denied") b.routes.denied = target;
            else if (outcome == "warning") b.routes.warning = target;
            else if (outcome == "success") b.routes.success = target;
            else
                return fail(c.file + ":" + std::to_string(c.line) + ": default_route outcome must be denied|warning|success");
            LOG_DEBUG("policy '", b.name, "': default_route ", outcome, " -> ", target);
            continue;
        }
        if (c.name == "rule") {
            Result<Rule> parsed = c.args.size() == 1
                ? Rule::parseLine(c.args[0])
                : Rule::parse(Category::Object, c.args);
            if (!parsed) return fail(c.file + ":" + std::to_string(c.line) + ": " + parsed.error());
            Rule rule = parsed.value();
            rule.file = c.file;
            rule.line = c.line;
            auto res = b.addRule(std::move(rule));
            if (!res) return fail(c.file + ":" + std::to_string(c.line) + ": " + res.error());
            continue;
        }
        if (c.name == "include") continue;
        return fail(c.file + ":" + std::to_string(c.line) + ": unknown directive '" + c.name + "' inside policy block");
    }
    for (auto cat : {Category::Access, Category::Bucket, Category::Object})
        if (!b.defaults.count(cat)) {
            LOG_DEBUG("policy '", b.name, "': no default_action for ", categoryName(cat), ", using accept");
            b.defaults[cat] = Action{"accept", {}, {}};
        }
    LOG_INFO("policy '", b.name, "' compiled: ", b.rules.size(), " rule(s) (acl=", b.rulesOf(Category::Access).size(),
             " bucket=", b.rulesOf(Category::Bucket).size(), " object=", b.rulesOf(Category::Object).size(),
             "), routes success=", b.routes.success.empty() ? "<replication>-rqueue" : b.routes.success, " denied=",
             b.routes.denied, " warning=", b.routes.warning, " in ", sw.ms(), " ms");
    return Result<Bundle>(std::move(b));
}

} // namespace s3mm::policy
