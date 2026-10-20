#include "s3mm/common/secret.hpp"
#include "s3mm/common/fs.hpp"
#include "testkit.hpp"

using namespace s3mm;

TEST(secrets_roundtrip) {
    const std::string pass = "correct horse battery staple";
    const std::string plain = "super-secret-access-key";
    std::string pem = secret::seal(plain, pass);
    CHECK(secret::isPemBlock(pem));
    CHECK(pem.find("-----BEGIN S3MM SECRET-----") != std::string::npos);
    CHECK(pem.find("-----END S3MM SECRET-----") != std::string::npos);
    auto opened = secret::open(pem, pass);
    CHECK(opened.ok());
    CHECK_EQ(opened.value(), plain);
}

TEST(secrets_wrong_passphrase) {
    const std::string pass = "right";
    std::string pem = secret::seal("data", pass);
    auto opened = secret::open(pem, "wrong");
    CHECK(!opened.ok());
}

TEST(secrets_not_pem) {
    CHECK(!secret::isPemBlock("plain text secret"));
    CHECK(!secret::isPemBlock(""));
}

TEST(secrets_open_maybe) {
    const std::string pass = "p";
    std::string pem = secret::seal("sealed-value", pass);
    // PEM block -> decrypted
    CHECK_EQ(secret::openMaybe(pem, pass), std::string("sealed-value"));
    // plain string -> returned as-is
    CHECK_EQ(secret::openMaybe("plain-value", pass), std::string("plain-value"));
}

TEST(secrets_open_invalid_block) {
    auto r = secret::open("-----BEGIN S3MM SECRET-----\nAAAA\n-----END S3MM SECRET-----", "p");
    CHECK(!r.ok());
}
