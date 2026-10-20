#include "s3mm/common/units.hpp"
#include "testkit.hpp"

using namespace s3mm;

TEST(units_parse_size) {
    CHECK_EQ(units::tryParseSize("1024").value_or(0), 1024u);
    CHECK_EQ(units::tryParseSize("16MiB").value_or(0), 16ull * 1024 * 1024);
    CHECK_EQ(units::tryParseSize("16MB").value_or(0), 16000000ull);
    CHECK_EQ(units::tryParseSize("1m").value_or(0), 1000000ull);
    CHECK_EQ(units::tryParseSize("1mi").value_or(0), 1048576ull);
    CHECK_EQ(units::tryParseSize("1GiB").value_or(0), 1024ull * 1024 * 1024);
    CHECK_EQ(units::tryParseSize("2kib").value_or(0), 2048u);
    CHECK_EQ(units::tryParseSize("512B").value_or(0), 512u);
    CHECK_EQ(units::tryParseSize("1.5KiB").value_or(0), 1536u);
    CHECK_EQ(units::tryParseSize("1M").value_or(0), 1000000ull);
    CHECK_EQ(units::tryParseSize("1G").value_or(0), 1000000000ull);
    CHECK(!units::tryParseSize("abc"));
    CHECK(!units::tryParseSize(""));
    CHECK(!units::tryParseSize("12quux"));
    CHECK(!units::tryParseSize("-5"));
}

TEST(units_parse_size_throws) {
    bool threw = false;
    try {
        units::parseSize("nonsense");
    } catch (...) {
        threw = true;
    }
    CHECK(threw);
}

TEST(units_format_size_roundtrip) {
    // formatSize uses binary suffixes; parseSize must accept them back as binary.
    CHECK_EQ(units::formatSize(0), std::string("0B"));
    CHECK_EQ(units::formatSize(1024), std::string("1.0KiB"));
    CHECK_EQ(units::formatSize(16ull * 1024 * 1024), std::string("16.0MiB"));
    CHECK_EQ(units::tryParseSize(units::formatSize(1572864)).value_or(0), 1572864u);
    CHECK_EQ(units::tryParseSize(units::formatSize(3221225472ull)).value_or(0),
             3221225472ull);
}

TEST(units_parse_duration) {
    CHECK_EQ(units::tryParseDuration("30s").value_or(0), 30000);
    CHECK_EQ(units::tryParseDuration("500ms").value_or(0), 500);
    CHECK_EQ(units::tryParseDuration("2m").value_or(0), 120000);
    CHECK_EQ(units::tryParseDuration("1h").value_or(0), 3600000);
    CHECK_EQ(units::tryParseDuration("1d").value_or(0), 86400000);
    CHECK_EQ(units::tryParseDuration("1w").value_or(0), 7ll * 86400000);
    CHECK_EQ(units::tryParseDuration("45").value_or(0), 45000); // bare number = seconds
    CHECK_EQ(units::tryParseDuration("1d2h3m4s").value_or(0),
             (24 + 2) * 3600000 + 3 * 60000 + 4000);
    CHECK(!units::tryParseDuration(""));
    CHECK(!units::tryParseDuration("abc"));
    CHECK(!units::tryParseDuration("5x"));
}

TEST(units_format_duration) {
    CHECK_EQ(units::formatDuration(500), std::string("500ms"));
    CHECK_EQ(units::formatDuration(30000), std::string("30s"));
    CHECK_EQ(units::formatDuration(120000), std::string("2m0s"));
    CHECK_EQ(units::formatDuration(3600000), std::string("1h0m"));
    CHECK_EQ(units::formatDuration(90000000), std::string("1d1h"));
    CHECK_EQ(units::formatDuration(-5), std::string("0ms"));
}

TEST(units_parse_duration_seconds) {
    CHECK_EQ(units::parseDurationSeconds("90s"), 90);
    CHECK_EQ(units::parseDurationSeconds("1m30s"), 90);
    CHECK_EQ(units::parseDurationSeconds("1500ms"), 2); // rounds up
}
