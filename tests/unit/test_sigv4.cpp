#include "s3mm/s3/sigv4.hpp"
#include "s3mm/s3/http.hpp"
#include "s3mm/common/crypto.hpp"
#include "s3mm/common/str.hpp"
#include "testkit.hpp"

using namespace s3mm;

TEST(sigv4_golden_request) {
    http::Request req;
    req.method = "GET";
    req.url = "https://s3.example.com/bucket/dir/file.txt";
    req.query["list-type"] = "2";
    req.headers["Content-Type"] = "application/json";
    sigv4::Credentials creds;
    creds.accessKey = "AKIDEXAMPLE";
    creds.secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    creds.region = "eu-west-1";

    sigv4::SigningResult res = sigv4::signAt(req, creds, "s3", "20240101T120000Z");

    std::string expectedCr =
        "GET\n/bucket/dir/file.txt\nlist-type=2\n"
        "content-type:application/json\nhost:s3.example.com\n"
        "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "x-amz-date:20240101T120000Z\n\n"
        "content-type;host;x-amz-content-sha256;x-amz-date\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    CHECK_EQ(res.canonicalRequest, expectedCr);
    CHECK_EQ(res.signedHeaders, std::string("content-type;host;x-amz-content-sha256;x-amz-date"));
    CHECK_EQ(res.payloadHash, std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    std::string expectedSts =
        "AWS4-HMAC-SHA256\n20240101T120000Z\n20240101/eu-west-1/s3/aws4_request\n"
        "7130f0c79f68dcc3437d6356bb53c8ebf7caff8c26cf2df14e649080eb3385bd";
    CHECK_EQ(res.stringToSign, expectedSts);
    CHECK_EQ(res.signature, std::string("6b66807a8390038987128884834968972951866f8fc5f1df7b76965136ccc1e0"));
    CHECK_EQ(res.amzDate, std::string("20240101T120000Z"));
    CHECK(req.headers.count("Authorization"));
    CHECK(req.headers.count("x-amz-content-sha256"));
    CHECK(req.headers.count("x-amz-date"));
}

TEST(sigv4_aws_docs_listusers_vector) {
    // Independent reproduction of the published AWS Signature Version 4
    // (ListUsers) example — validates the HMAC key derivation against the
    // canonical request hash and signature published in the AWS docs.
    std::string cr =
        "GET\n/\nAction=ListUsers&Version=2010-05-08\n"
        "content-type:application/x-www-form-urlencoded; charset=utf-8\n"
        "host:iam.amazonaws.com\nx-amz-date:20150830T123600Z\n\n"
        "content-type;host;x-amz-date\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    CHECK_EQ(crypto::sha256Hex(cr), std::string("f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"));
    std::string secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    // HMAC chain
    auto hmac = [](const std::string& key, const std::string& msg) {
        return crypto::hmacSha256(key, msg);
    };
    auto k1 = hmac("AWS4" + secret, "20150830");
    std::string k1s(reinterpret_cast<const char*>(k1.data()), k1.size());
    auto k2 = hmac(k1s, "us-east-1");
    std::string k2s(reinterpret_cast<const char*>(k2.data()), k2.size());
    auto k3 = hmac(k2s, "iam");
    std::string k3s(reinterpret_cast<const char*>(k3.data()), k3.size());
    auto k4 = hmac(k3s, "aws4_request");
    std::string k4s(reinterpret_cast<const char*>(k4.data()), k4.size());
    std::string sts = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\n"
                      "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
    auto sig = hmac(k4s, sts);
    std::string sigHex = crypto::toHex(sig.data(), sig.size());
    CHECK_EQ(sigHex, std::string("5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"));
}

TEST(sigv4_session_token) {
    http::Request req;
    req.method = "GET";
    req.url = "https://s3.example.com/bucket/key";
    sigv4::Credentials creds;
    creds.accessKey = "AKIA";
    creds.secretKey = "secret";
    creds.sessionToken = "TOKEN123";
    creds.region = "us-east-1";
    sigv4::SigningResult res = sigv4::signAt(req, creds, "s3", "20240101T000000Z");
    CHECK(res.signedHeaders.find("x-amz-security-token") != std::string::npos);
    CHECK(req.headers.count("x-amz-security-token"));
    CHECK_EQ(req.headers["x-amz-security-token"], std::string("TOKEN123"));
}
