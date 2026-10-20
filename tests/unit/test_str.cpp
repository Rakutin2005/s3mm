#include "s3mm/common/str.hpp"
#include "testkit.hpp"

using namespace s3mm;

TEST(str_trim) {
    CHECK_EQ(str::trim("  a b  "), std::string("a b"));
    CHECK_EQ(str::trim("\t\nx\r\n"), std::string("x"));
    CHECK_EQ(str::trim(""), std::string(""));
    CHECK_EQ(str::trim("   "), std::string(""));
    CHECK_EQ(str::ltrim("  x"), std::string("x"));
    CHECK_EQ(str::rtrim("x  "), std::string("x"));
}

TEST(str_split) {
    auto parts = str::split("a,b,,c", ',', true);
    CHECK_EQ(parts.size(), 4u);
    CHECK_EQ(parts[0], std::string("a"));
    CHECK_EQ(parts[2], std::string(""));
    auto noEmpty = str::split("a,b,,c", ',', false);
    CHECK_EQ(noEmpty.size(), 3u);
    auto ws = str::split("one   two\tthree", ' ', false);
    CHECK_EQ(ws.size(), 3u);
}

TEST(str_splitWS_quotes) {
    auto toks = str::splitWS("name='a b' value=\"c d\" bare");
    CHECK_EQ(toks.size(), 3u);
    CHECK_EQ(toks[0], std::string("name=a b"));
    CHECK_EQ(toks[1], std::string("value=c d"));
    CHECK_EQ(toks[2], std::string("bare"));
}

TEST(str_splitList) {
    auto list = str::splitList("a, b,!c*");
    CHECK_EQ(list.size(), 3u);
    CHECK_EQ(list[1], std::string("b"));
    CHECK_EQ(list[2], std::string("!c*"));
}

TEST(str_tokenize) {
    auto toks = str::tokenize("rule add '100 name=big object size >= 1M action accept'");
    CHECK_EQ(toks.size(), 3u);
    CHECK_EQ(toks[2], std::string("100 name=big object size >= 1M action accept"));
    auto esc = str::tokenize("a\\ b \"c d\"");
    CHECK_EQ(esc.size(), 3u);
    CHECK_EQ(esc[0], std::string("a b"));
    CHECK_EQ(esc[2], std::string("c d"));
}

TEST(str_join_lower_upper) {
    CHECK_EQ(str::join({"a", "b", "c"}, ","), std::string("a,b,c"));
    CHECK_EQ(str::join({}, ","), std::string(""));
    CHECK_EQ(str::toLower("AbC"), std::string("abc"));
    CHECK_EQ(str::toUpper("AbC"), std::string("ABC"));
}

TEST(str_prefix_suffix) {
    CHECK(str::startsWith("replication", "replic"));
    CHECK(!str::startsWith("replication", "lication"));
    CHECK(str::endsWith("file.conf", ".conf"));
    CHECK(!str::endsWith("file.conf", ".cf"));
    CHECK(str::iequals("GET", "get"));
    CHECK(!str::iequals("GET", "getx"));
}

TEST(str_replace_all) {
    CHECK_EQ(str::replaceAll("a/b/c", "/", "_"), std::string("a_b_c"));
    CHECK_EQ(str::replaceAll("aaa", "a", "b"), std::string("bbb"));
    CHECK_EQ(str::replaceAll("none", "x", "y"), std::string("none"));
}

TEST(str_escape_json) {
    CHECK_EQ(str::escapeJson("a\"b"), std::string("a\\\"b"));
    CHECK_EQ(str::escapeJson("line\nbreak"), std::string("line\\nbreak"));
    CHECK_EQ(str::escapeJson("back\\slash"), std::string("back\\\\slash"));
}

TEST(str_quote_shell_roundtrip) {
    auto toks = str::tokenize(str::quoteShell("plain"));
    CHECK_EQ(toks.size(), 1u);
    CHECK_EQ(toks[0], std::string("plain"));
    toks = str::tokenize(str::quoteShell("with spaces"));
    CHECK_EQ(toks.size(), 1u);
    CHECK_EQ(toks[0], std::string("with spaces"));
    toks = str::tokenize(str::quoteShell(""));
    CHECK_EQ(toks.size(), 1u);
    CHECK_EQ(toks[0], std::string(""));
    toks = str::tokenize(str::quoteShell("it's"));
    CHECK_EQ(toks.size(), 1u);
    CHECK_EQ(toks[0], std::string("it's"));
}

TEST(str_parse_numbers) {
    CHECK_EQ(str::parseInt64("-42").value_or(0), -42);
    CHECK_EQ(str::parseInt64("42x").value_or(0), 0); // must consume the whole string
    CHECK(!str::parseInt64("x42"));
    CHECK(!str::parseInt64(""));
    CHECK(str::parseDouble("3.5").value_or(0) == 3.5);
    CHECK(!str::parseDouble("3.5x"));
}

TEST(str_pad) {
    CHECK_EQ(str::padRight("ab", 4), std::string("ab  "));
    CHECK_EQ(str::padRight("abcd", 2), std::string("abcd"));
    CHECK_EQ(str::padLeft("ab", 4), std::string("  ab"));
}
