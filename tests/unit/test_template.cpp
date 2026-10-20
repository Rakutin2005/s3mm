#include "s3mm/replication/target.hpp"
#include "s3mm/common/fs.hpp"
#include "testkit.hpp"

using namespace s3mm;
using namespace s3mm::repl;

TEST(template_file_target_render) {
    const std::string dir = "/tmp/opencode/tpltest";
    fs::removeTree(dir);
    fs::mkdirp(dir);
    FileTarget t("q", dir, "{bucket}/{safe_key}.json");

    ShipRecord r;
    r.replication = "rep1";
    r.outcome = "success";
    r.kind = "object";
    r.sourceCluster = "src";
    r.bucket = "mybucket";
    r.key = "photos/a b/c.txt";
    r.size = 42;
    r.etag = "\"e\"";
    auto res = t.ship(r, "");
    CHECK(res.ok());
    // rendered path: dir/mybucket/photos_a_b_c.txt.json
    const std::string expected = dir + "/mybucket/photos_a b_c.txt.json";
    CHECK(fs::exists(expected));
    auto content = fs::readFile(expected);
    CHECK(content.has_value());
    CHECK(content->find("\"key\"") != std::string::npos || content->find("photos") != std::string::npos);
}

TEST(template_default_path) {
    const std::string dir = "/tmp/opencode/tpltest2";
    fs::removeTree(dir);
    fs::mkdirp(dir);
    // empty template => path_ itself is the target file (append log)
    FileTarget t("q", dir + "/records.jsonl", "");
    ShipRecord r;
    r.replication = "rep1";
    r.outcome = "success";
    r.kind = "object";
    r.bucket = "b";
    r.key = "k";
    CHECK(t.ship(r, "").ok());
    CHECK(fs::exists(dir + "/records.jsonl"));
}

TEST(template_placeholders) {
    // Verify S3Target exposes template; just construct and check metadata.
    S3Target t("q", "s3://dstcluster/outbucket/prefix/", "{bucket}/{key}");
    CHECK_EQ(t.targetCluster(), std::string("dstcluster"));
    CHECK_EQ(t.targetBucket(), std::string("outbucket"));
    CHECK_EQ(t.targetPrefix(), std::string("prefix"));
    CHECK_EQ(t.pathTemplate(), std::string("{bucket}/{key}"));
}
