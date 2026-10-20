#include "s3mm/s3/xml.hpp"
#include "testkit.hpp"

using namespace s3mm;

TEST(xml_parse_basic) {
    std::string doc = R"(<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix></Prefix>
  <KeyCount>2</KeyCount>
  <Contents>
    <Key>a.txt</Key>
    <Size>10</Size>
    <ETag>&quot;abc&quot;</ETag>
    <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>sub/b.txt</Key>
    <Size>20</Size>
  </Contents>
  <CommonPrefixes><Prefix>sub/</Prefix></CommonPrefixes>
  <IsTruncated>false</IsTruncated>
  <NextContinuationToken>tok123</NextContinuationToken>
</ListBucketResult>)";
    auto r = xml::parse(doc);
    CHECK(r);
    const auto& el = r.value();
    CHECK_EQ(el.localName(), std::string("ListBucketResult"));
    CHECK_EQ(el.childText("Name"), std::string("bucket"));
    CHECK_EQ(el.childText("KeyCount"), std::string("2"));
    CHECK_EQ(el.childText("IsTruncated"), std::string("false"));
    CHECK_EQ(el.childText("NextContinuationToken"), std::string("tok123"));
    auto contents = el.childrenNamed("Contents");
    CHECK_EQ(contents.size(), 2u);
    CHECK_EQ(contents[0]->childText("Key"), std::string("a.txt"));
    CHECK_EQ(contents[0]->childText("Size"), std::string("10"));
    CHECK_EQ(contents[0]->childText("StorageClass"), std::string("STANDARD"));
    CHECK_EQ(contents[1]->childText("Key"), std::string("sub/b.txt"));
    auto cp = el.childrenNamed("CommonPrefixes");
    CHECK_EQ(cp.size(), 1u);
    CHECK_EQ(cp[0]->childText("Prefix"), std::string("sub/"));
}

TEST(xml_escape) {
    CHECK_EQ(xml::escape("a<b&c"), std::string("a&lt;b&amp;c"));
    CHECK_EQ(xml::escape("\"q\""), std::string("&quot;q&quot;"));
    std::string t = xml::tag("Name", "bucket");
    CHECK(t.find("<Name>bucket</Name>") != std::string::npos);
}

TEST(xml_parse_error) {
    auto r = xml::parse("<a><b></a>");
    CHECK(!r);
    auto r2 = xml::parse("");
    CHECK(!r2);
}

TEST(xml_namespaced) {
    std::string doc = R"(<s3:ListBucketResult><s3:Name>x</s3:Name></s3:ListBucketResult>)";
    auto r = xml::parse(doc);
    CHECK(r);
    CHECK_EQ(r.value().localName(), std::string("ListBucketResult"));
    CHECK_EQ(r.value().childText("Name"), std::string("x"));
}
