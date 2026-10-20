#include "s3mm/common/value.hpp"
#include "testkit.hpp"

using namespace s3mm;

TEST(value_types) {
    Value v;
    CHECK(v.isNull());
    CHECK(!v.isObject());
    CHECK(!v.isArray());
    CHECK(!v.isString());

    Value b = Value::boolean(true);
    CHECK(b.asBool());
    CHECK(!b.asBool(false));
    CHECK(!Value::boolean(false).asBool());
}

TEST(value_numbers) {
    Value i = Value::number((int64_t)42);
    CHECK_EQ(i.asInt(), (int64_t)42);
    CHECK(i.asDouble() == 42.0);
    Value d = Value::number(3.5);
    CHECK(d.asDouble() == 3.5);
    CHECK_EQ(d.asInt(), (int64_t)3); // truncates
    Value s = Value::str("x");
    CHECK_EQ(s.asInt((int64_t)7), (int64_t)7); // default for non-numbers
    CHECK_EQ(s.asDouble(1.5), 1.5);
}

TEST(value_object_access) {
    Value o = Value::object();
    o.set("name", Value::str("cluster-1"));
    o.set("count", Value::number((int64_t)3));
    o.set("ok", Value::boolean(true));

    CHECK(o.isObject());
    CHECK_EQ(o.getString("name"), std::string("cluster-1"));
    CHECK_EQ(o.getString("missing", "fallback"), std::string("fallback"));
    CHECK_EQ(o.asInt(), (int64_t)0); // asInt on an object -> default
    const Value* c = o.find("count");
    CHECK(c != nullptr);
    CHECK_EQ(c->asInt(), (int64_t)3);
    CHECK(o.find("nope") == nullptr);
    CHECK_EQ(o.size(), 3u);
    CHECK(o.members().size() == 3u);
}

TEST(value_array) {
    Value a = Value::array();
    a.push(Value::str("one"));
    a.push(Value::number((int64_t)2));
    CHECK(a.isArray());
    CHECK_EQ(a.size(), 2u);
    CHECK_EQ(a.items()[0].asString(), std::string("one"));
    CHECK_EQ(a.items()[1].asInt(), (int64_t)2);
}

TEST(value_json_roundtrip) {
    Value o = Value::object();
    o.set("str", Value::str("hello \"world\"\n"));
    o.set("int", Value::number((int64_t)123));
    o.set("dbl", Value::number(1.5));
    o.set("bool", Value::boolean(false));
    Value arr = Value::array();
    arr.push(Value::str("a"));
    arr.push(Value::number((int64_t)1));
    o.set("arr", arr);
    Value nested = Value::object();
    nested.set("k", Value::str("v"));
    o.set("nested", nested);

    std::string text = o.toJson();
    std::string err;
    Value parsed = Value::parseJson(text, &err);
    CHECK(parsed.isObject());
    CHECK(err.empty());
    CHECK_EQ(parsed.getString("str"), std::string("hello \"world\"\n"));
    CHECK_EQ(parsed.find("int")->asInt(), (int64_t)123);
    CHECK(parsed.find("dbl")->asDouble() == 1.5);
    CHECK(!parsed.find("bool")->asBool(true));
    CHECK_EQ(parsed.find("arr")->size(), 2u);
    CHECK_EQ(parsed.find("arr")->items()[1].asInt(), (int64_t)1);
    CHECK_EQ(parsed.find("nested")->getString("k"), std::string("v"));
}

TEST(value_parse_errors) {
    std::string err;
    Value bad = Value::parseJson("{not json", &err);
    CHECK(bad.isNull());
    CHECK(!err.empty());
    Value ok = Value::parseJson("[1,2,3]");
    CHECK(ok.isArray());
    CHECK_EQ(ok.size(), 3u);
    Value scalar = Value::parseJson("\"just a string\"");
    CHECK(scalar.isString());
    CHECK_EQ(scalar.asString(), std::string("just a string"));
}

TEST(value_yaml_smoke) {
    Value o = Value::object();
    o.set("name", Value::str("s3mm"));
    o.set("count", Value::number((int64_t)2));
    Value arr = Value::array();
    arr.push(Value::str("a"));
    o.set("items", arr);
    std::string y = o.toYaml();
    CHECK(y.find("name: s3mm") != std::string::npos);
    CHECK(y.find("count: 2") != std::string::npos);
    CHECK(y.find("- a") != std::string::npos);
}
