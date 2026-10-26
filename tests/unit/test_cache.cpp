#include "testkit.hpp"

#include <cstdio>
#include <map>
#include <string>

#include "s3mm/common/fs.hpp"
#include "s3mm/replication/cache.hpp"
#include "s3mm/s3/client.hpp"

namespace {

std::string tempDir(const char* tag) {
    return std::string("/tmp/s3mm-test-cache-") + tag + "-" + std::to_string(::getpid());
}

void cleanupDir(const std::string& p) {
    std::string cmd = "rm -rf '" + p + "'";
    if (::system(cmd.c_str()) != 0) { /* best effort */ }
}

s3mm::s3::ObjectInfo makeInfo(const std::string& key, uint64_t size, const std::string& etag) {
    s3mm::s3::ObjectInfo o;
    o.key = key;
    o.size = size;
    o.etag = etag;
    o.lastModified = s3mm::tm::now();
    return o;
}

} // namespace

TEST(cache_changed_detects_new_and_modified) {
    const std::string dir = tempDir("changed");
    cleanupDir(dir);
    s3mm::repl::BucketCache cache(dir + "/cache.tsv");
    CHECK(bool(cache.load()));

    auto a = makeInfo("a.txt", 10, "etag-a");
    // Unknown object => changed (must be replicated).
    CHECK(cache.changed(a));

    cache.observe(a);
    // Same state => not changed.
    CHECK(!cache.changed(a));

    // Different etag => changed.
    auto a2 = makeInfo("a.txt", 10, "etag-b");
    CHECK(cache.changed(a2));

    // Different size => changed.
    auto a3 = makeInfo("a.txt", 11, "etag-a");
    CHECK(cache.changed(a3));
    cleanupDir(dir);
}

TEST(cache_observe_without_ship_keeps_eligible) {
    const std::string dir = tempDir("eligible");
    cleanupDir(dir);
    s3mm::repl::BucketCache cache(dir + "/cache.tsv");
    CHECK(bool(cache.load()));

    auto a = makeInfo("k", 5, "e");
    // Observe-only bookkeeping (no delivery yet): the object stays eligible.
    cache.noteMetadata("k", "hash1", "tags1", s3mm::tm::now());
    CHECK(cache.changed(a));

    cache.markShipped(a);
    CHECK(!cache.changed(a));
    cleanupDir(dir);
}

TEST(cache_missing_since_reports_deletions) {
    const std::string dir = tempDir("missing");
    cleanupDir(dir);
    s3mm::repl::BucketCache cache(dir + "/cache.tsv");
    CHECK(bool(cache.load()));

    cache.observe(makeInfo("keep", 1, "e1"));
    cache.observe(makeInfo("gone", 2, "e2"));
    cache.markShipped(makeInfo("gone", 2, "e2"));

    std::map<std::string, s3mm::s3::ObjectInfo> current;
    current["keep"] = makeInfo("keep", 1, "e1");
    auto missing = cache.missingSince(current);
    CHECK(missing.size() == 1);
    if (!missing.empty()) CHECK(missing.front().key == "gone");
    cleanupDir(dir);
}

TEST(cache_metadata_due_and_hash_change) {
    const std::string dir = tempDir("meta");
    cleanupDir(dir);
    s3mm::repl::BucketCache cache(dir + "/cache.tsv");
    CHECK(bool(cache.load()));

    auto a = makeInfo("m", 1, "e");
    cache.observe(a);
    cache.markShipped(a);

    // Never checked => due.
    CHECK(cache.metadataDue("m", s3mm::tm::now(), 300));
    cache.noteMetadata("m", "hash1", "tags1", s3mm::tm::now());
    // Just checked => not due yet.
    CHECK(!cache.metadataDue("m", s3mm::tm::now(), 300));
    // Past the period => due again.
    CHECK(cache.metadataDue("m", s3mm::tm::now() + std::chrono::seconds(301), 300));

    CHECK(!cache.metadataChanged("m", "hash1", "tags1"));
    CHECK(cache.metadataChanged("m", "hash2", "tags1"));
    CHECK(cache.metadataChanged("m", "hash1", "tags2"));
    cleanupDir(dir);
}

TEST(cache_persistence_roundtrip) {
    const std::string dir = tempDir("persist");
    cleanupDir(dir);
    {
        s3mm::repl::BucketCache cache(dir + "/cache.tsv");
        CHECK(bool(cache.load()));
        auto a = makeInfo("p/k", 7, "pe");
        cache.markShipped(a);
        CHECK(bool(cache.save()));
        CHECK_EQ(cache.size(), size_t(1));
    }
    {
        s3mm::repl::BucketCache re(dir + "/cache.tsv");
        CHECK(bool(re.load()));
        CHECK_EQ(re.size(), size_t(1));
        // Shipped objects must load back as shipped (not re-replicated).
        CHECK(!re.changed(makeInfo("p/k", 7, "pe")));
    }
    cleanupDir(dir);
}

TEST(cache_mark_deleted_and_forget) {
    const std::string dir = tempDir("del");
    cleanupDir(dir);
    s3mm::repl::BucketCache cache(dir + "/cache.tsv");
    CHECK(bool(cache.load()));

    cache.observe(makeInfo("d", 1, "e"));
    cache.markDeleted("d", s3mm::tm::now());
    // Deleted entries stay known until forgotten (tombstone semantics).
    CHECK_EQ(cache.size(), size_t(1));
    cache.forget("d");
    CHECK_EQ(cache.size(), size_t(0));
    cleanupDir(dir);
}
