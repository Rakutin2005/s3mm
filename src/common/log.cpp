#include "s3mm/common/error.hpp"
#include "s3mm/common/log.hpp"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <vector>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace s3mm::log {

static Options g_options;
static std::atomic<bool> g_initialized{false};
static int g_fd = -1;
static std::mutex g_mutex;

Level levelFromString(const std::string& s) {
    if (s == "debug") return Level::Debug;
    if (s == "info") return Level::Info;
    if (s == "notice") return Level::Notice;
    if (s == "warn" || s == "warning") return Level::Warning;
    if (s == "error" || s == "err") return Level::Error;
    if (s == "critical" || s == "crit") return Level::Critical;
    if (s == "alert") return Level::Alert;
    if (s == "emergency") return Level::Emergency;
    throw Error("unknown log level: " + s);
}

const char* levelName(Level l) {
    switch (l) {
        case Level::Debug: return "debug";
        case Level::Info: return "info";
        case Level::Notice: return "notice";
        case Level::Warning: return "warning";
        case Level::Error: return "error";
        case Level::Critical: return "critical";
        case Level::Alert: return "alert";
        case Level::Emergency: return "emergency";
    }
    return "info";
}

static const std::pair<const char*, Facility> kFacilities[] = {
    {"kern", Facility::Kern},       {"user", Facility::User},     {"mail", Facility::Mail},
    {"daemon", Facility::Daemon},   {"auth", Facility::Auth},     {"syslog", Facility::Syslog},
    {"lpr", Facility::Lpr},         {"news", Facility::News},     {"uucp", Facility::Uucp},
    {"cron", Facility::Cron},       {"authpriv", Facility::Authpriv}, {"ftp", Facility::Ftp},
    {"local0", Facility::Local0},   {"local1", Facility::Local1}, {"local2", Facility::Local2},
    {"local3", Facility::Local3},   {"local4", Facility::Local4}, {"local5", Facility::Local5},
    {"local6", Facility::Local6},   {"local7", Facility::Local7},
};

bool facilityFromString(const std::string& s, Facility& out) {
    for (auto& [name, f] : kFacilities)
        if (s == name) { out = f; return true; }
    return false;
}

const char* facilityName(Facility f) {
    for (auto& [name, kf] : kFacilities)
        if (kf == f) return name;
    return "daemon";
}

static int facilityNumber(Facility f) { return (int)f * 8; }

static std::string g_hostname = "localhost";

// Caller holds g_mutex.
static void closeSyslogSocket() {
    if (g_fd >= 0) {
        ::close(g_fd);
        g_fd = -1;
    }
}

// Caller holds g_mutex.
static bool openSyslogSocket() {
    if (g_fd >= 0) return true;
    struct sockaddr_un addr{};
    int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    std::memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof addr.sun_path, "%s", g_options.socketPath.c_str());
    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof addr) != 0) {
        ::close(fd);
        return false;
    }
    g_fd = fd;
    return true;
}

void init(const Options& options) {
    std::lock_guard<std::mutex> lock(g_mutex);
    closeSyslogSocket();
    g_options = options;
    char host[256] = "localhost";
    if (::gethostname(host, sizeof host - 1) == 0) {
        host[sizeof host - 1] = '\0';
        g_hostname = host;
    }
    g_initialized = true;
    openSyslogSocket();
}

void shutdown() {
    std::lock_guard<std::mutex> lock(g_mutex);
    closeSyslogSocket();
    g_initialized = false;
}

bool initialized() { return g_initialized; }
const Options& options() { return g_options; }
bool enabled(Level l) { return (int)l <= (int)g_options.level; }

std::string redact(const std::string& secret) {
    if (secret.empty()) return "<empty>";
    return "***(" + std::to_string(secret.size()) + " bytes)";
}

std::string clip(const std::string& s, size_t max) {
    if (s.size() <= max) return s;
    return s.substr(0, max) + "...(" + std::to_string(s.size()) + " bytes)";
}

static std::string escapeSd(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\\' || c == '"' || c == ']') out += '\\';
        out += c;
    }
    return out;
}

static std::string baseName(const std::string& path) {
    size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

// Upper bound for one datagram; larger messages are truncated.
static constexpr size_t kMaxMessage = 16 * 1024;

void write(Level l, const std::string& message, std::initializer_list<std::pair<std::string, std::string>> sd) {
    if (!g_initialized || !enabled(l)) return;

    struct timespec ts{};
    ::clock_gettime(CLOCK_REALTIME, &ts);
    std::tm tm{};
    gmtime_r(&ts.tv_sec, &tm);
    char stamp[48];
    size_t n = std::strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%S", &tm);
    std::snprintf(stamp + n, sizeof stamp - n, ".%06ldZ", ts.tv_nsec / 1000);

    std::string sdStr;
    std::string file, line;
    for (const auto& [k, v] : sd) {
        if (k == "file") file = baseName(v);
        else if (k == "line") line = v;
        else sdStr += "[" + k + "=\"" + escapeSd(v) + "\"]";
    }
    if (!file.empty())
        sdStr = "[s3mm@3247 file=\"" + escapeSd(file) + "\" line=\"" + escapeSd(line) + "\"]" + sdStr;
    if (sdStr.empty()) sdStr = "-";

    // One record per line: fold embedded newlines.
    std::string body = message.size() > kMaxMessage ? clip(message, kMaxMessage) : message;
    for (char& c : body)
        if (c == '\n' || c == '\r') c = ' ';

    std::lock_guard<std::mutex> lock(g_mutex);
    std::string msg = "<" + std::to_string(facilityNumber(g_options.facility) + (int)l) + ">1 " + stamp + " " +
                      g_hostname + " " + g_options.ident + " " + std::to_string(::getpid()) + " - " + sdStr + " " +
                      body;

    // Second attempt reconnects: syslog may have been restarted under us.
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!openSyslogSocket()) continue;
        ssize_t sent = ::send(g_fd, msg.data(), msg.size(), MSG_NOSIGNAL);
        if (sent == (ssize_t)msg.size()) return;
        int err = errno;
        if (err == EMSGSIZE && msg.size() > 2048) {
            msg = clip(msg, 2048);
            continue;
        }
        closeSyslogSocket();
    }
}

} // namespace s3mm::log
