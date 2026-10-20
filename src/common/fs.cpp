#include "s3mm/common/fs.hpp"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace s3mm::fs {
namespace nfs = std::filesystem;

std::optional<std::string> readFile(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return std::nullopt;
    std::string out;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
    bool ok = !std::ferror(f);
    std::fclose(f);
    if (!ok) return std::nullopt;
    return out;
}

bool writeFileAtomic(const std::string& path, std::string_view content, bool fsyncDir) {
    std::error_code ec;
    nfs::path p(path);
    nfs::path dir = p.parent_path();
    if (dir.empty()) dir = ".";
    nfs::create_directories(dir, ec);
    nfs::path tmp = dir / ("." + p.filename().string() + ".tmp." + std::to_string(::getpid()));
    {
        std::FILE* f = std::fopen(tmp.string().c_str(), "wb");
        if (!f) return false;
        size_t written = content.empty() ? 0 : std::fwrite(content.data(), 1, content.size(), f);
        if (written != content.size()) { std::fclose(f); ::unlink(tmp.string().c_str()); return false; }
        std::fflush(f);
        if (fsyncDir) ::fsync(fileno(f));
        std::fclose(f);
    }
    if (::rename(tmp.string().c_str(), p.string().c_str()) != 0) {
        ::unlink(tmp.string().c_str());
        return false;
    }
    if (fsyncDir) {
        int dfd = ::open(dir.string().c_str(), O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) {
            ::fsync(dfd);
            ::close(dfd);
        }
    }
    return true;
}

bool appendFile(const std::string& path, std::string_view content) {
    std::error_code ec;
    nfs::path p(path);
    if (p.has_parent_path()) nfs::create_directories(p.parent_path(), ec);
    std::FILE* f = std::fopen(path.c_str(), "ab");
    if (!f) return false;
    bool ok = content.empty() || std::fwrite(content.data(), 1, content.size(), f) == content.size();
    ok = std::fflush(f) == 0 && ok;
    std::fclose(f);
    return ok;
}

bool exists(const std::string& path) {
    std::error_code ec;
    return nfs::exists(path, ec);
}

bool isDir(const std::string& path) {
    std::error_code ec;
    return nfs::is_directory(path, ec);
}

bool isRegular(const std::string& path) {
    std::error_code ec;
    return nfs::is_regular_file(path, ec);
}

std::optional<uint64_t> fileSize(const std::string& path) {
    std::error_code ec;
    auto sz = nfs::file_size(path, ec);
    if (ec) return std::nullopt;
    return (uint64_t)sz;
}

bool mkdirp(const std::string& path) {
    std::error_code ec;
    nfs::create_directories(path, ec);
    return !ec && nfs::is_directory(path, ec);
}

bool removeFile(const std::string& path) {
    std::error_code ec;
    return nfs::remove(path, ec) || !ec;
}

bool removeTree(const std::string& path) {
    std::error_code ec;
    nfs::remove_all(path, ec);
    return !ec;
}

std::vector<std::string> listDir(const std::string& path) {
    std::vector<std::string> out;
    std::error_code ec;
    if (!nfs::is_directory(path, ec)) return out;
    for (const auto& e : nfs::directory_iterator(path, ec)) out.push_back(e.path().filename().string());
    std::sort(out.begin(), out.end());
    return out;
}

std::optional<unsigned> permissions(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return std::nullopt;
    return (unsigned)(st.st_mode & 0777);
}

bool setPermissions(const std::string& path, unsigned mode) { return ::chmod(path.c_str(), mode) == 0; }

std::optional<std::string> readSecretFile(const std::string& path) {
    auto mode = permissions(path);
    if (!mode) return "cannot stat secret file: " + path;
    if (*mode & 0077) return "secret file " + path + " must not be readable by group/others (mode " + std::to_string(*mode) + ")";
    return readFile(path);
}

std::string joinPath(std::string_view a, std::string_view b) {
    if (a.empty()) return std::string(b);
    if (b.empty()) return std::string(a);
    std::string out(a);
    if (out.back() != '/') out += '/';
    out.append(b);
    return out;
}

std::string dirname(const std::string& path) {
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

std::string basename(const std::string& path) {
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

} // namespace s3mm::fs
