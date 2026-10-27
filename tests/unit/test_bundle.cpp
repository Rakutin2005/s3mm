#include "s3mm/policy/bundle.hpp"
#include "s3mm/policy/rule.hpp"
#include "testkit.hpp"

using namespace s3mm;
using namespace s3mm::policy;

TEST(bundle_builtin) {
    Bundle d = Bundle::builtin("default");
    CHECK_EQ(d.name, std::string("default"));
    CHECK(d.defaults.count(Category::Object));
    CHECK_EQ(d.defaultAction(Category::Object).name, std::string("accept"));
    Bundle dr = Bundle::builtin("drop-all");
    CHECK_EQ(dr.defaultAction(Category::Object).name, std::string("drop"));
}

TEST(bundle_add_rule_ordering) {
    Bundle b;
    b.name = "test";
    CHECK(b.addRule(Rule::parseLine("10 object action accept").value()).ok());
    CHECK(b.addRule(Rule::parseLine("30 object action drop").value()).ok());
    CHECK(b.addRule(Rule::parseLine("20 object action quarantine").value()).ok());
    CHECK_EQ(b.rules.size(), 3u);
    CHECK_EQ(b.rules[0].order, 10);
    CHECK_EQ(b.rules[1].order, 20);
    CHECK_EQ(b.rules[2].order, 30);
}

TEST(bundle_add_before_after) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 object action accept").value());
    b.addRule(Rule::parseLine("30 object action drop").value());
    // insert 20 before order 30
    CHECK(b.addRule(Rule::parseLine("20 object action quarantine").value(), "30", "").ok());
    CHECK_EQ(b.rules[0].order, 10);
    CHECK_EQ(b.rules[1].order, 20);
    CHECK_EQ(b.rules[2].order, 30);
    // insert 25 after order 20
    CHECK(b.addRule(Rule::parseLine("25 object action log").value(), "", "20").ok());
    CHECK_EQ(b.rules.size(), 4u);
    CHECK_EQ(b.rules[2].order, 25);
}

TEST(bundle_find_rule) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 name=big object action accept").value());
    CHECK(b.findRule("big") != nullptr);
    CHECK(b.findRule("10") != nullptr);
    CHECK(b.findRule("999") == nullptr);
    CHECK(b.findRuleByOrder(10) != nullptr);
}

TEST(bundle_remove_rule) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 object action accept").value());
    b.addRule(Rule::parseLine("20 object action drop").value());
    CHECK(b.removeRule("10").ok());
    CHECK_EQ(b.rules.size(), 1u);
    CHECK(!b.removeRule("999").ok());
    CHECK(!b.removeRule("10").ok());
}

TEST(bundle_replace_rule) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 name=x object action accept").value());
    auto r = Rule::parseLine("10 name=x object action drop");
    CHECK(b.replaceRule("x", r.value()).ok());
    CHECK_EQ(b.rules[0].actions[0].name, std::string("drop"));
}

TEST(bundle_rules_of) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 object action accept").value());
    b.addRule(Rule::parseLine("20 bucket action drop").value());
    CHECK_EQ(b.rulesOf(Category::Object).size(), 1u);
    CHECK_EQ(b.rulesOf(Category::Bucket).size(), 1u);
    CHECK_EQ(b.rulesOf(Category::Access).size(), 0u);
}

TEST(bundle_next_order) {
    Bundle b;
    b.name = "test";
    CHECK_EQ(b.nextOrder(), 10);
    b.addRule(Rule::parseLine("100 object action accept").value());
    CHECK_EQ(b.nextOrder(), 110);
}

TEST(bundle_dump_fromnode_roundtrip) {
    const char* text = R"(
s3mm {
    policy p {
        default_action object accept;
        default_action bucket accept;
        default_action access accept;
        default_route denied null;
        default_route warning quarantine;
        rule '10 name=big object source.size >= 1M action accept log';
    }
}
)";
    auto cfg = config::Config::parse(text);
    CHECK(cfg);
    const auto* node = cfg.value().s3mm()->find("policy");
    CHECK(node != nullptr);
    auto bundle = Bundle::fromNode(*node);
    CHECK(bundle);
    CHECK_EQ(bundle.value().name, std::string("p"));
    CHECK_EQ(bundle.value().rules.size(), 1u);
    CHECK_EQ(bundle.value().routes.denied, std::string("null"));
    std::string dumped = bundle.value().dump();
    CHECK(dumped.find("policy p") != std::string::npos);
}

TEST(bundle_fromnode_default_redirect) {
    auto noTarget = config::Config::parse("policy p { default_action object redirect; }\n");
    CHECK(noTarget);
    auto bad = Bundle::fromNode(*noTarget.value().s3mm()->find("policy"));
    CHECK(!bad);
    CHECK(bad.error().find("redirect") != std::string::npos);

    auto withTarget = config::Config::parse("policy p { default_action object redirect special-batch; }\n");
    CHECK(withTarget);
    auto good = Bundle::fromNode(*withTarget.value().s3mm()->find("policy"));
    CHECK(good);
    CHECK_EQ(good.value().defaultAction(Category::Object).positional, std::string("special-batch"));
}
