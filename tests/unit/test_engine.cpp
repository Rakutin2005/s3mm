#include "s3mm/policy/engine.hpp"
#include "s3mm/policy/bundle.hpp"
#include "s3mm/policy/rule.hpp"
#include "s3mm/policy/attr.hpp"
#include "testkit.hpp"

using namespace s3mm;
using namespace s3mm::policy;

TEST(engine_default_bundle) {
    Bundle b = Bundle::builtin("default");
    Context ctx;
    ctx.set("size", (int64_t)100);
    Engine e;
    Decision d = e.evaluate(b, Category::Object, ctx, "rep1");
    CHECK(d.accepted());
    CHECK(d.viaDefault);
    CHECK(d.rule == nullptr);
    CHECK_EQ(d.outcome, std::string("success"));
}

TEST(engine_drop_all) {
    Bundle b = Bundle::builtin("drop-all");
    Context ctx;
    Engine e;
    Decision d = e.evaluate(b, Category::Object, ctx, "rep1");
    CHECK(!d.accepted());
    CHECK_EQ(d.outcome, std::string("denied"));
    CHECK_EQ(d.target, std::string("null"));
}

TEST(engine_first_match_wins) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 object source.size >= 1M action drop").value());
    b.addRule(Rule::parseLine("20 object action accept").value());
    Context big;
    big.set("size", (int64_t)2 * 1024 * 1024);
    Engine e;
    Decision d = e.evaluate(b, Category::Object, big, "rep1");
    CHECK(!d.accepted());
    CHECK_EQ(d.outcome, std::string("denied"));
    Context small;
    small.set("size", (int64_t)100);
    Decision d2 = e.evaluate(b, Category::Object, small, "rep1");
    CHECK(d2.accepted());
}

TEST(engine_pass_fallthrough) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 object source.size >= 1M action pass").value());
    b.addRule(Rule::parseLine("20 object action accept").value());
    Context big;
    big.set("size", (int64_t)2 * 1024 * 1024);
    Engine e;
    Decision d = e.evaluate(b, Category::Object, big, "rep1");
    CHECK(d.accepted());
    CHECK(d.rule != nullptr);
    CHECK_EQ(d.rule->order, 20);
}

TEST(engine_quarantine_routes) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 object action quarantine").value());
    Engine e;
    Context ctx;
    Decision d = e.evaluate(b, Category::Object, ctx, "rep1");
    CHECK_EQ(d.outcome, std::string("warning"));
    CHECK_EQ(d.target, std::string("quarantine"));
}

TEST(engine_redirect_target) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 object action redirect special-batch").value());
    Engine e;
    Context ctx;
    Decision d = e.evaluate(b, Category::Object, ctx, "rep1");
    CHECK(d.accepted());
    CHECK_EQ(d.target, std::string("special-batch"));
}

TEST(engine_transforms) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 object action set storage-class=COLD propagate tags=yes accept").value());
    Engine e;
    Context ctx;
    Decision d = e.evaluate(b, Category::Object, ctx, "rep1");
    auto t = d.transforms();
    CHECK(t.count("storage-class"));
    CHECK_EQ(t["storage-class"], std::string("COLD"));
    CHECK(t.count("tags"));
}

TEST(engine_routes_success_default) {
    Bundle b;
    b.name = "test";
    b.addRule(Rule::parseLine("10 object action accept").value());
    Engine e;
    Context ctx;
    Decision d = e.evaluate(b, Category::Object, ctx, "rep1");
    // empty success route => <replication>-rqueue
    CHECK_EQ(d.target, std::string("rep1-rqueue"));
}

TEST(engine_default_redirect_without_target_denied) {
    Bundle b;
    b.name = "test";
    b.defaults[Category::Object] = Action{"redirect", {}, {}};
    b.routes.denied = "deny-batch";
    Engine e;
    Context ctx;
    Decision d = e.evaluate(b, Category::Object, ctx, "rep1");
    CHECK(d.viaDefault);
    CHECK(!d.accepted());
    CHECK_EQ(d.outcome, std::string("denied"));
    CHECK_EQ(d.target, std::string("deny-batch"));

    b.routes.denied.clear();
    Decision d2 = e.evaluate(b, Category::Object, ctx, "rep1");
    CHECK_EQ(d2.outcome, std::string("denied"));
    CHECK_EQ(d2.target, std::string("null"));
}

TEST(engine_default_redirect_with_target) {
    Bundle b;
    b.name = "test";
    b.defaults[Category::Object] = Action{"redirect", "special-batch", {}};
    Engine e;
    Context ctx;
    Decision d = e.evaluate(b, Category::Object, ctx, "rep1");
    CHECK(d.viaDefault);
    CHECK_EQ(d.outcome, std::string("success"));
    CHECK_EQ(d.target, std::string("special-batch"));
}
