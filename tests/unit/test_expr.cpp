#include "s3mm/policy/expr.hpp"
#include "s3mm/policy/attr.hpp"
#include "testkit.hpp"

using namespace s3mm;
using namespace s3mm::policy;

TEST(expr_compare_numbers) {
    CHECK(compare(PValue::num((int64_t)5), Op::Eq, "5", {}));
    CHECK(!compare(PValue::num((int64_t)5), Op::Eq, "6", {}));
    CHECK(compare(PValue::num((int64_t)5), Op::Lt, "10", {}));
    CHECK(compare(PValue::num((int64_t)5), Op::Le, "5", {}));
    CHECK(compare(PValue::num((int64_t)5), Op::Gt, "3", {}));
    CHECK(compare(PValue::num((int64_t)5), Op::Ge, "5", {}));
    CHECK(compare(PValue::num((int64_t)5), Op::Ne, "3", {}));
    // size literals resolve
    CHECK(compare(PValue::num((int64_t)2048), Op::Ge, "1KiB", {}));
    CHECK(!compare(PValue::str("5"), Op::Lt, "10", {})); // string compare: "5" > "10"
}

TEST(expr_compare_strings) {
    CHECK(compare(PValue::str("abc"), Op::Eq, "abc", {}));
    CHECK(compare(PValue::str("abc"), Op::Ne, "xyz", {}));
    CHECK(compare(PValue::str("a"), Op::Lt, "b", {}));
    CHECK(!compare(PValue::str("b"), Op::Lt, "a", {}));
}

TEST(expr_compare_in) {
    CHECK(compare(PValue::str("jpg"), Op::In, "", {"jpg", "png"}));
    CHECK(compare(PValue::str("a.txt"), Op::In, "", {"*.txt"}));
    CHECK(!compare(PValue::str("jpg"), Op::In, "", {"png", "gif"}));
    CHECK(compare(PValue::list({"a", "b"}), Op::In, "", {"b"}));
}

TEST(expr_compare_regex) {
    CHECK(compare(PValue::str("abc123"), Op::Regex, "^abc[0-9]+$", {}));
    CHECK(!compare(PValue::str("abc"), Op::Regex, "^abc[0-9]+$", {}));
    CHECK(compare(PValue::str("abc"), Op::NotRegex, "^xyz", {}));
}

TEST(expr_compare_bool) {
    CHECK(compare(PValue::boolean(true), Op::Eq, "true", {}));
    CHECK(compare(PValue::boolean(true), Op::Eq, "yes", {}));
    CHECK(compare(PValue::boolean(false), Op::Eq, "0", {}));
    CHECK(compare(PValue::boolean(true), Op::Ne, "false", {}));
}

TEST(expr_eval_context) {
    Context ctx;
    ctx.set("size", (int64_t)2 * 1024 * 1024);
    ctx.set("ext", "jpg");
    ctx.setBool("deleted", false);
    ctx.set("name", "report.pdf");

    CmpExpr cmp("size", Op::Ge, "1M");
    CHECK(cmp.eval(ctx));
    CmpExpr cmp2("size", Op::Lt, "1M");
    CHECK(!cmp2.eval(ctx));
    CmpExpr cmp3("ext", Op::In, "", {"jpg", "png"});
    CHECK(cmp3.eval(ctx));
    CmpExpr cmp4("name", Op::Regex, ".*\\.pdf");
    CHECK(cmp4.eval(ctx));
    ExistsExpr ex("size", false);
    CHECK(ex.eval(ctx));
    ExistsExpr ex2("missing", false);
    CHECK(!ex2.eval(ctx));
    ExistsExpr ex3("missing", true);
    CHECK(ex3.eval(ctx));
}

TEST(expr_all_any_not) {
    Context ctx;
    ctx.set("size", (int64_t)5);
    ctx.set("ext", "jpg");

    AllExpr all({std::make_shared<CmpExpr>("size", Op::Ge, "1"),
                 std::make_shared<CmpExpr>("ext", Op::Eq, "jpg")});
    CHECK(all.eval(ctx));
    AllExpr all2({std::make_shared<CmpExpr>("size", Op::Ge, "1"),
                  std::make_shared<CmpExpr>("ext", Op::Eq, "png")});
    CHECK(!all2.eval(ctx));

    AnyExpr any({std::make_shared<CmpExpr>("size", Op::Ge, "100"),
                 std::make_shared<CmpExpr>("ext", Op::Eq, "jpg")});
    CHECK(any.eval(ctx));

    NotExpr notx(std::make_shared<CmpExpr>("ext", Op::Eq, "png"));
    CHECK(notx.eval(ctx));
    NotExpr notx2(std::make_shared<CmpExpr>("ext", Op::Eq, "jpg"));
    CHECK(!notx2.eval(ctx));
}

TEST(expr_collect_fields) {
    AllExpr all({std::make_shared<CmpExpr>("size", Op::Ge, "1"),
                 std::make_shared<CmpExpr>("ext", Op::In, "", std::vector<std::string>{"jpg"})});
    std::vector<std::string> fields;
    all.collectFields(fields);
    CHECK(fields.size() >= 2u);
}
