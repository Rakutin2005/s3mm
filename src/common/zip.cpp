#include "s3mm/common/zip.hpp"

#include <cstring>
#include <cstdint>
#include <vector>

#include <zlib.h>

namespace s3mm::zip {
namespace {

constexpr uint32_t kEocd = 0x06054b50;
constexpr uint32_t kCentral = 0x02014b50;
constexpr uint32_t kLocal = 0x04034b50;
constexpr uint64_t kMaxEntry = 64ull * 1024 * 1024;

uint16_t rd16(std::string_view d, size_t off) {
    return (uint16_t)((unsigned char)d[off] | ((unsigned char)d[off + 1] << 8));
}

uint32_t rd32(std::string_view d, size_t off) {
    return (uint32_t)((unsigned char)d[off] | ((unsigned char)d[off + 1] << 8) |
                      ((unsigned char)d[off + 2] << 16) | ((unsigned char)d[off + 3] << 24));
}

Result<std::string> inflateEntry(std::string_view source, size_t offset, uint32_t compressed,
                                 uint32_t uncompressed) {
    if (uncompressed > kMaxEntry) return Result<std::string>::failure("ZIP entry is too large");
    z_stream zs{};
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return Result<std::string>::failure("zlib inflateInit failed");
    zs.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(source.data() + offset));
    zs.avail_in = compressed;

    std::string out;
    out.reserve(uncompressed);
    unsigned char buffer[64 * 1024];
    int rc = Z_OK;
    while (rc == Z_OK) {
        zs.next_out = buffer;
        zs.avail_out = sizeof buffer;
        rc = inflate(&zs, Z_NO_FLUSH);
        size_t produced = sizeof buffer - zs.avail_out;
        if (out.size() + produced > kMaxEntry) {
            inflateEnd(&zs);
            return Result<std::string>::failure("ZIP entry expands beyond the limit");
        }
        out.append(reinterpret_cast<const char*>(buffer), produced);
        if (rc == Z_BUF_ERROR && zs.avail_in == 0) break;
    }
    inflateEnd(&zs);
    if (rc != Z_STREAM_END) return Result<std::string>::failure("corrupt deflate stream in ZIP");
    return Result<std::string>(std::move(out));
}

} // namespace

Result<std::string> extractFile(std::string_view archive, std::string_view name) {
    if (archive.size() < 22) return Result<std::string>::failure("not a ZIP archive");
    size_t eocd = std::string_view::npos;
    const size_t minPos = archive.size() > 22 + 65535 ? archive.size() - 22 - 65535 : 0;
    for (size_t i = archive.size() - 22 + 1; i-- > minPos;) {
        if (rd32(archive, i) == kEocd) {
            eocd = i;
            break;
        }
    }
    if (eocd == std::string_view::npos) return Result<std::string>::failure("ZIP end record not found");

    uint16_t entries = rd16(archive, eocd + 10);
    uint32_t cdOffset = rd32(archive, eocd + 16);
    uint32_t cdSize = rd32(archive, eocd + 12);
    if (entries == 0xffff || cdOffset == 0xffffffff || cdSize == 0xffffffff)
        return Result<std::string>::failure("ZIP64 archives are not supported");
    if ((size_t)cdOffset + cdSize > archive.size()) return Result<std::string>::failure("truncated ZIP directory");

    size_t p = cdOffset;
    for (uint16_t i = 0; i < entries; ++i) {
        if (p + 46 > archive.size() || rd32(archive, p) != kCentral)
            return Result<std::string>::failure("corrupt ZIP central directory");
        uint16_t method = rd16(archive, p + 10);
        uint32_t compressed = rd32(archive, p + 20);
        uint32_t uncompressed = rd32(archive, p + 24);
        uint16_t nameLen = rd16(archive, p + 28);
        uint16_t extraLen = rd16(archive, p + 30);
        uint16_t commentLen = rd16(archive, p + 32);
        uint32_t localOffset = rd32(archive, p + 42);
        if (p + 46 + nameLen > archive.size()) return Result<std::string>::failure("truncated ZIP name");
        std::string_view entryName = archive.substr(p + 46, nameLen);
        if (entryName == name) {
            if ((size_t)localOffset + 30 > archive.size() || rd32(archive, localOffset) != kLocal)
                return Result<std::string>::failure("corrupt ZIP local header");
            uint16_t localNameLen = rd16(archive, localOffset + 26);
            uint16_t localExtraLen = rd16(archive, localOffset + 28);
            size_t dataOffset = (size_t)localOffset + 30 + localNameLen + localExtraLen;
            if (dataOffset + compressed > archive.size())
                return Result<std::string>::failure("truncated ZIP entry");
            if (method == 0) {
                if (uncompressed > kMaxEntry)
                    return Result<std::string>::failure("ZIP entry is too large");
                return Result<std::string>(std::string(archive.substr(dataOffset, compressed)));
            }
            if (method == 8) return inflateEntry(archive, dataOffset, compressed, uncompressed);
            return Result<std::string>::failure("unsupported ZIP compression method " + std::to_string(method));
        }
        p += 46 + nameLen + extraLen + commentLen;
    }
    return Result<std::string>::failure("ZIP entry '" + std::string(name) + "' not found");
}

} // namespace s3mm::zip
