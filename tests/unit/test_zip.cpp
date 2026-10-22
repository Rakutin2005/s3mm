#include "s3mm/common/zip.hpp"

#include <cstdint>
#include <string>
#include <vector>

#include <zlib.h>

#include "testkit.hpp"

using namespace s3mm;

namespace {

void put16(std::string& out, uint16_t v) {
    out += (char)(v & 0xff);
    out += (char)((v >> 8) & 0xff);
}

void put32(std::string& out, uint32_t v) {
    out += (char)(v & 0xff);
    out += (char)((v >> 8) & 0xff);
    out += (char)((v >> 16) & 0xff);
    out += (char)((v >> 24) & 0xff);
}

std::string rawDeflate(const std::string& input) {
    z_stream zs{};
    deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    std::string out;
    out.resize(deflateBound(&zs, (uLong)input.size()));
    zs.next_in = (Bytef*)input.data();
    zs.avail_in = (uInt)input.size();
    zs.next_out = (Bytef*)out.data();
    zs.avail_out = (uInt)out.size();
    int rc = deflate(&zs, Z_FINISH);
    out.resize(zs.total_out);
    deflateEnd(&zs);
    return rc == Z_STREAM_END ? out : std::string();
}

struct Entry {
    std::string name;
    std::string data;
    uint16_t method = 0;
    uint32_t crc = 0;
    uint32_t compressedSize = 0;
    uint32_t localOffset = 0;
};

std::string makeZip(std::vector<Entry> entries) {
    std::string out;
    for (auto& e : entries) {
        std::string stored = e.method == 8 ? rawDeflate(e.data) : e.data;
        e.compressedSize = (uint32_t)stored.size();
        e.crc = (uint32_t)crc32(0L, (const Bytef*)e.data.data(), (uInt)e.data.size());
        e.localOffset = (uint32_t)out.size();
        put32(out, 0x04034b50);
        put16(out, 20);
        put16(out, 0);
        put16(out, e.method);
        put16(out, 0);
        put16(out, 0);
        put32(out, e.crc);
        put32(out, e.compressedSize);
        put32(out, (uint32_t)e.data.size());
        put16(out, (uint16_t)e.name.size());
        put16(out, 0);
        out += e.name;
        out += stored;
    }
    uint32_t cdOffset = (uint32_t)out.size();
    for (const auto& e : entries) {
        put32(out, 0x02014b50);
        put16(out, 20);
        put16(out, 20);
        put16(out, 0);
        put16(out, e.method);
        put16(out, 0);
        put16(out, 0);
        put32(out, e.crc);
        put32(out, e.compressedSize);
        put32(out, (uint32_t)e.data.size());
        put16(out, (uint16_t)e.name.size());
        put16(out, 0);
        put16(out, 0);
        put16(out, 0);
        put16(out, 0);
        put32(out, 0);
        put32(out, e.localOffset);
        out += e.name;
    }
    uint32_t cdSize = (uint32_t)out.size() - cdOffset;
    put32(out, 0x06054b50);
    put16(out, 0);
    put16(out, 0);
    put16(out, (uint16_t)entries.size());
    put16(out, (uint16_t)entries.size());
    put32(out, cdSize);
    put32(out, cdOffset);
    put16(out, 0);
    return out;
}

} // namespace

TEST(zip_extract_stored_and_deflated) {
    const std::string payload = "iam-assets/users.json";
    auto storedZip = makeZip({{payload, "hello zip", 0}});
    auto a = zip::extractFile(storedZip, payload);
    CHECK(a);
    CHECK_EQ(a.value(), std::string("hello zip"));

    auto deflatedZip = makeZip({{payload, std::string(4096, 'x'), 8}});
    auto b = zip::extractFile(deflatedZip, payload);
    CHECK(b);
    CHECK_EQ(b.value(), std::string(4096, 'x'));

    auto missing = zip::extractFile(deflatedZip, "nope");
    CHECK(!missing);
}
