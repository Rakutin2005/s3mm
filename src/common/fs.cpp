#include "s3mm/common/fs.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include <system_error>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "s3mm/common/log.hpp"

namespace s3mm::fs {
namespace nfs = std::filesystem;

std::optional<std::string> readFile(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        int err = errno;
        if (err == ENOENT) LOG_DEBUG("fs: ", path, " does not exist");
        else if (err == EACCES || err == EPERM) LOG_ERROR("fs: permission denied opening ", path, ": ", std::strerror(err));
        else LOG_WARN("fs: cannot open ", path, ": ", std::strerror(err));
        return std::nullopt;
    }
    std::string out;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) out.append(buf, n);
    bool ok = !std::ferror(f);
    int err = errno;
    std::fclose(f);
    if (!ok) {
        LOG_ERROR("fs: read error on ", path, ": ", std::strerror(err));
        return std::nullopt;
    }
    LOG_DEBUG("fs: read ", path, " (", out.size(), " bytes)");
    return out;
}

bool writeFileAtomic(const std::string& path, std::string_view content, bool fsyncDir) {
    std::error_code ec;
    nfs::path p(path);
    nfs::path dir = p.parent_path();
    if (dir.empty()) dir = ".";
    nfs::create_directories(dir, ec);
    if (ec) LOG_WARN("fs: cannot create directory ", dir.string(), ": ", ec.message());
    nfs::path tmp = dir / ("." + p.filename().string() + ".tmp." + std::to_string(::getpid()));
    {
        std::FILE* f = std::fopen(tmp.string().c_str(), "wb");
        if (!f) {
            LOG_ERROR("fs: cannot create ", tmp.string(), " for atomic write of ", path, ": ", std::strerror(errno));
            return false;
        }
        size_t written = content.empty() ? 0 : std::fwrite(content.data(), 1, content.size(), f);
        if (written != content.size()) {
            LOG_ERROR("fs: short write to ", tmp.string(), " (", written, "/", content.size(), " bytes): ", std::strerror(errno));
            std::fclose(f); ::unlink(tmp.string().c_str()); return false;
        }
        if (std::fflush(f) != 0) LOG_WARN("fs: fflush ", tmp.string(), " failed: ", std::strerror(errno));
        if (fsyncDir && ::fsync(fileno(f)) != 0) LOG_WARN("fs: fsync ", tmp.string(), " failed: ", std::strerror(errno));
        std::fclose(f);
    }
    if (::rename(tmp.string().c_str(), p.string().c_str()) != 0) {
        LOG_ERROR("fs: cannot rename ", tmp.string(), " -> ", path, ": ", std::strerror(errno));
        ::unlink(tmp.string().c_str());
        return false;
    }
    if (fsyncDir) {
        int dfd = ::open(dir.string().c_str(), O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) {
            ::fsync(dfd);
            ::close(dfd);
        } else {
            LOG_WARN("fs: cannot open directory ", dir.string(), " for fsync: ", std::strerror(errno));
        }
    }
    LOG_DEBUG("fs: wrote ", path, " (", content.size(), " bytes, atomic)");
    return true;
}

bool appendFile(const std::string& path, std::string_view content) {
    std::error_code ec;
    nfs::path p(path);
    if (p.has_parent_path()) nfs::create_directories(p.parent_path(), ec);
    if (ec) LOG_WARN("fs: cannot create directory ", p.parent_path().string(), ": ", ec.message());
    std::FILE* f = std::fopen(path.c_str(), "ab");
    if (!f) {
        LOG_ERROR("fs: cannot open ", path, " for append: ", std::strerror(errno));
        return false;
    }
    bool ok = content.empty() || std::fwrite(content.data(), 1, content.size(), f) == content.size();
    ok = std::fflush(f) == 0 && ok;
    if (!ok) LOG_ERROR("fs: append of ", content.size(), " bytes to ", path, " failed: ", std::strerror(errno));
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
    if (ec) {
        LOG_ERROR("fs: cannot create directory ", path, ": ", ec.message());
        return false;
    }
    if (!nfs::is_directory(path, ec)) {
        LOG_ERROR("fs: ", path, " exists but is not a directory");
        return false;
    }
    return true;
}

bool removeFile(const std::string& path) {
    std::error_code ec;
    bool removed = nfs::remove(path, ec);
    if (ec) LOG_WARN("fs: cannot remove ", path, ": ", ec.message());
    else if (removed) LOG_DEBUG("fs: removed ", path);
    return removed || !ec;
}

bool removeTree(const std::string& path) {
    std::error_code ec;
    auto count = nfs::remove_all(path, ec);
    if (ec) LOG_WARN("fs: cannot remove tree ", path, ": ", ec.message());
    else LOG_DEBUG("fs: removed tree ", path, " (", (unsigned long long)count, " entries)");
    return !ec;
}

std::vector<std::string> listDir(const std::string& path) {
    std::vector<std::string> out;
    std::error_code ec;
    if (!nfs::is_directory(path, ec)) return out;
    for (const auto& e : nfs::directory_iterator(path, ec)) out.push_back(e.path().filename().string());
    if (ec) LOG_WARN("fs: cannot list directory ", path, ": ", ec.message());
    std::sort(out.begin(), out.end());
    return out;
}

std::optional<unsigned> permissions(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) {
        LOG_DEBUG("fs: stat ", path, " failed: ", std::strerror(errno));
        return std::nullopt;
    }
    return (unsigned)(st.st_mode & 0777);
}

bool setPermissions(const std::string& path, unsigned mode) {
    if (::chmod(path.c_str(), mode) != 0) {
        LOG_WARN("fs: chmod ", path, " to ", std::oct, mode, std::dec, " failed: ", std::strerror(errno));
        return false;
    }
    return true;
}

Result<std::string> readSecretFile(const std::string& path) {
    LOG_DEBUG("fs: reading secret file ", path);
    auto mode = permissions(path);
    if (!mode) {
        LOG_ERROR("fs: cannot stat secret file ", path);
        return Result<std::string>::failure("cannot stat secret file: " + path);
    }
    if (*mode & 0077) {
        LOG_ERROR("fs: secret file ", path, " must not be readable by group/others (mode ", std::oct, *mode, std::dec, ")");
        char octal[8];
        std::snprintf(octal, sizeof octal, "%03o", *mode & 0777);
        return Result<std::string>::failure("secret file " + path + " must not be readable by group/others (mode " +
                                            octal + ")");
    }
    auto content = readFile(path);
    if (!content) {
        LOG_ERROR("fs: cannot read secret file ", path);
        return Result<std::string>::failure("cannot read secret file: " + path);
    }
    LOG_DEBUG("fs: secret file ", path, " read: ", log::redact(*content));
    return *content;
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
