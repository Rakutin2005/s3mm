#include "s3mm/policy/rule.hpp"
#include "testkit.hpp"

using namespace s3mm;
using namespace s3mm::policy;

TEST(rule_parse_basic) {
    auto r = Rule::parseLine("100 name=big object source.size >= 1M action accept log");
    CHECK(r);
    CHECK_EQ(r.value().order, 100);
    CHECK_EQ(r.value().name, std::string("big"));
    CHECK(r.value().category == Category::Object);
    CHECK(r.value().conditionText().find("size") != std::string::npos);
    CHECK_EQ(r.value().actions.size(), 2u);
    CHECK_EQ(r.value().actions[0].name, std::string("accept"));
    CHECK_EQ(r.value().actions[1].name, std::string("log"));
}

TEST(rule_parse_minimal) {
    auto r = Rule::parseLine("object action accept");
    CHECK(r);
    CHECK(r.value().condition == nullptr);
    CHECK_EQ(r.value().actions.size(), 1u);
    CHECK_EQ(r.value().actions[0].name, std::string("accept"));
}

TEST(rule_parse_order_and_category) {
    auto r = Rule::parseLine("42 bucket action drop");
    CHECK(r);
    CHECK_EQ(r.value().order, 42);
    CHECK(r.value().category == Category::Bucket);
}

TEST(rule_parse_actions_params) {
    auto r = Rule::parseLine("object source.size >= 1M action redirect quarantine-batch reason=too_big level=warning");
    CHECK(r);
    CHECK_EQ(r.value().actions.size(), 1u);
    CHECK_EQ(r.value().actions[0].name, std::string("redirect"));
    CHECK_EQ(r.value().actions[0].positional, std::string("quarantine-batch"));
    CHECK_EQ(r.value().actions[0].param("level"), std::string("warning"));
    CHECK_EQ(r.value().actions[0].param("reason"), std::string("too_big"));
}

TEST(rule_parse_pass_conflict) {
    auto r = Rule::parseLine("object action accept pass");
    CHECK(!r); // pass conflicts with accept
    auto r2 = Rule::parseLine("object action pass");
    CHECK(r2);
}

TEST(rule_parse_set_action) {
    auto r = Rule::parseLine("object source.size >= 1M action set storage-class=COLD log message=\"too big\"");
    CHECK(r);
    CHECK(r.value().actions.size() >= 2u);
    CHECK_EQ(r.value().actions[0].name, std::string("set"));
    CHECK_EQ(r.value().actions[0].param("storage-class"), std::string("COLD"));
    CHECK_EQ(r.value().actions[1].name, std::string("log"));
    CHECK_EQ(r.value().actions[1].param("message"), std::string("too big"));
}

TEST(rule_parse_acl_subject) {
    auto r = Rule::parseLine("100 acl source.subject = AKIA123 action accept");
    CHECK(r);
    CHECK(r.value().category == Category::Access);
    auto r2 = Rule::parseLine("acl action drop");
    CHECK(r2);
    CHECK(r2.value().category == Category::Access);
}

TEST(rule_parse_acl_rule) {
    auto r = Rule::parseLine("acl source.subject = \"*\" action accept");
    CHECK(r);
}

TEST(rule_parse_implicit_and) {
    auto r = Rule::parseLine("object source.size >= 1M source.ext in jpg,png action accept");
    CHECK(r);
    // condition should be an AllExpr with two terms
    CHECK(r.value().condition != nullptr);
}

TEST(rule_parse_infix) {
    auto r = Rule::parseLine("object (source.size >= 1M or source.size <= 100) action accept");
    CHECK(r);
}

TEST(rule_parse_not) {
    auto r = Rule::parseLine("object not source.deleted action accept");
    CHECK(r);
    CHECK(r.value().condition != nullptr);
}

TEST(rule_parse_exists) {
    auto r = Rule::parseLine("object source.versionId exists action accept");
    CHECK(r);
}

TEST(rule_to_string_roundtrip) {
    auto r = Rule::parseLine("100 name=big object source.size >= 1M action accept log");
    CHECK(r);
    std::string s = r.value().toString();
    CHECK(s.find("size") != std::string::npos);
    auto r2 = Rule::parseLine(s);
    CHECK(r2);
    CHECK_EQ(r2.value().name, std::string("big"));
}

TEST(rule_parse_errors) {
    CHECK(!Rule::parseLine(""));
    CHECK(!Rule::parseLine("object action"));
    CHECK(!Rule::parseLine("object action frobnicate"));
}
