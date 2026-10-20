#include "s3mm/common/glob.hpp"
#include "testkit.hpp"

using namespace s3mm;

TEST(glob_match) {
    CHECK(glob::match("*.txt", "notes.txt"));
    CHECK(!glob::match("*.txt", "notes.log"));
    CHECK(glob::match("*text*", "some-text-file"));
    CHECK(glob::match("img-?.png", "img-1.png"));
    CHECK(!glob::match("img-?.png", "img-12.png"));
    CHECK(glob::match("exact", "exact"));
    CHECK(!glob::match("exact", "exactly"));
    CHECK(glob::match("*", "anything"));
    CHECK(glob::match("data/2024/*.csv", "data/2024/jan.csv"));
    CHECK(!glob::match("data/2024/*.csv", "data/2025/jan.csv"));
}

TEST(glob_match_filter) {
    std::vector<std::string> patterns = {"logs/*", "*.log"};
    CHECK(glob::matchFilter(patterns, "logs/a.txt"));
    CHECK(glob::matchFilter(patterns, "root.log"));
    CHECK(!glob::matchFilter(patterns, "data/a.txt"));
    // No positive patterns at all -> everything passes (except negations).
    CHECK(glob::matchFilter({}, "anything"));
    // Negation beats a positive match.
    std::vector<std::string> neg = {"logs/*", "!logs/tmp/*"};
    CHECK(glob::matchFilter(neg, "logs/a.txt"));
    CHECK(!glob::matchFilter(neg, "logs/tmp/x.bin"));
    // Negation-only filter: everything not matching the negation passes.
    CHECK(glob::matchFilter({"!secret*"}, "public"));
    CHECK(!glob::matchFilter({"!secret*"}, "secret-key"));
}

TEST(glob_match_filter_list) {
    CHECK(glob::matchFilterList("logs/*,*.log", "logs/x"));
    CHECK(glob::matchFilterList("logs/*,!logs/tmp/*", "logs/tmp/x"));
    CHECK(!glob::matchFilterList("logs/*,!logs/tmp/*", "nope"));
}
