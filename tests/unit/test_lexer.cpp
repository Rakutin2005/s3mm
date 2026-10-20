#include "s3mm/policy/lexer.hpp"
#include "s3mm/policy/expr.hpp"
#include "testkit.hpp"

using namespace s3mm;
using namespace s3mm::policy;

TEST(lexer_parse_term_basic) {
    auto t = parseTerm("size>=50G", "");
    CHECK(t.has_value());
    CHECK_EQ(t->field, std::string("size"));
    CHECK(t->op == Op::Ge);
    CHECK_EQ(t->value, std::string("50G"));

    auto t2 = parseTerm("name=b1", "");
    CHECK(t2->op == Op::Eq);
    CHECK_EQ(t2->value, std::string("b1"));

    auto t3 = parseTerm("ext!=txt", "");
    CHECK(t3->op == Op::Ne);
    CHECK_EQ(t3->value, std::string("txt"));

    auto t4 = parseTerm("bytes<1M", "");
    CHECK(t4->op == Op::Lt);

    auto t5 = parseTerm("bytes<=1M", "");
    CHECK(t5->op == Op::Le);

    auto t6 = parseTerm("bytes>1M", "");
    CHECK(t6->op == Op::Gt);

    auto t7 = parseTerm("name~^a.*b$", "");
    CHECK(t7->op == Op::Regex);
    CHECK_EQ(t7->value, std::string("^a.*b$"));

    auto t8 = parseTerm("name!~^tmp/", "");
    CHECK(t8->op == Op::NotRegex);
    CHECK_EQ(t8->value, std::string("^tmp/"));

    // bare token -> Exists
    auto bare = parseTerm("enabled", "");
    CHECK(bare.has_value());
    CHECK(bare->op == Op::Exists);
    CHECK_EQ(bare->field, std::string("enabled"));
}

TEST(lexer_scope_prefix) {
    auto t = parseTerm("size=1", "destination.");
    CHECK_EQ(t->field, std::string("destination.size"));
    // explicit source. wins over default scope
    auto t2 = parseTerm("source.size=1", "destination.");
    CHECK_EQ(t2->field, std::string("size"));
    auto t3 = parseTerm("dest.size=1", "");
    CHECK_EQ(t3->field, std::string("destination.size"));
    auto t4 = parseTerm("src.size=1", "");
    CHECK_EQ(t4->field, std::string("size"));
}

TEST(lexer_validate_regex) {
    CHECK(!validateRegex("a(b)c").has_value());
    CHECK(validateRegex("[a-").has_value());
}

TEST(lexer_parse_expression) {
    std::vector<std::string> toks = {"source.size", ">=", "1M", "and", "source.name", "=", "data*"};
    std::string scope;
    policy::Cursor cur{toks};
    auto expr = parseExpression(cur, scope, {});
    CHECK(expr != nullptr);
    CHECK(cur.empty());
    CHECK(expr->toString().find("size") != std::string::npos);

    // stop words
    std::vector<std::string> toks2 = {"source.size", ">=", "1M", "action", "accept"};
    policy::Cursor cur2{toks2};
    std::string scope2;
    auto expr2 = parseExpression(cur2, scope2, {"action"});
    CHECK(expr2 != nullptr);
    CHECK_EQ(cur2.pos, 3u); // stopped at 'action'
}

TEST(lexer_field_exists) {
    std::vector<std::string> toks = {"source.bucket", "exists"};
    std::string scope;
    policy::Cursor cur{toks};
    auto expr = parseExpression(cur, scope, {});
    CHECK(expr != nullptr);
    CHECK(expr->kind() == Expr::Kind::Exists);
}

TEST(lexer_in_list) {
    std::vector<std::string> toks = {"source.ext", "in", "jpg,png,gif"};
    std::string scope;
    policy::Cursor cur{toks};
    auto expr = parseExpression(cur, scope, {});
    CHECK(expr != nullptr);
    CHECK(expr->kind() == Expr::Kind::Cmp);
    auto cmp = std::dynamic_pointer_cast<CmpExpr>(expr);
    CHECK(cmp != nullptr);
    CHECK(cmp->op() == Op::In);
}
