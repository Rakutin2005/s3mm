#pragma once
#include <initializer_list>
#include <sstream>
#include <string>
#include <utility>

namespace s3mm::log {

/// RFC 5424 severities.
enum class Level { Emergency = 0, Alert = 1, Critical = 2, Error = 3, Warning = 4, Notice = 5, Info = 6, Debug = 7 };

/// RFC 5424 facilities.
enum class Facility {
    Kern, User, Mail, Daemon, Auth, Syslog, Lpr, News, Uucp, Cron, Authpriv, Ftp,
    Local0, Local1, Local2, Local3, Local4, Local5, Local6, Local7
};

Level levelFromString(const std::string& s); // "debug"|"info"|... (throws)
const char* levelName(Level l);
bool facilityFromString(const std::string& s, Facility& out);
const char* facilityName(Facility f);

struct Options {
    std::string ident = "s3mm";
    Level level = Level::Info;
    Facility facility = Facility::Daemon;
    bool toStderr = true; // used when syslog is unavailable (dev/tests)
    std::string socketPath = "/dev/log";
};

void init(const Options& options);
void shutdown();
bool initialized();
const Options& options();
bool enabled(Level l);

/// Write one RFC 5424 message to syslog (SOCK_DGRAM /dev/log) with a stderr fallback.
void write(Level l, const std::string& message,
           std::initializer_list<std::pair<std::string, std::string>> sd = {});

template <class... Args>
std::string fmtstr(Args&&... args) {
    std::ostringstream os;
    (os << ... << args);
    return os.str();
}

template <class... Args>
void emit(Level l, Args&&... args) {
    if (!enabled(l)) return;
    write(l, fmtstr(std::forward<Args>(args)...));
}

template <class... Args> void debug(Args&&... a)    { emit(Level::Debug, std::forward<Args>(a)...); }
template <class... Args> void info(Args&&... a)     { emit(Level::Info, std::forward<Args>(a)...); }
template <class... Args> void notice(Args&&... a)   { emit(Level::Notice, std::forward<Args>(a)...); }
template <class... Args> void warn(Args&&... a)     { emit(Level::Warning, std::forward<Args>(a)...); }
template <class... Args> void error(Args&&... a)    { emit(Level::Error, std::forward<Args>(a)...); }
template <class... Args> void critical(Args&&... a) { emit(Level::Critical, std::forward<Args>(a)...); }

} // namespace s3mm::log

#define S3MM_LOG_AT(lvl, ...) \
    ::s3mm::log::write(lvl, ::s3mm::log::fmtstr(__VA_ARGS__), {{"file", __FILE__}, {"line", std::to_string(__LINE__)}})

#define LOG_DEBUG(...)    S3MM_LOG_AT(::s3mm::log::Level::Debug, __VA_ARGS__)
#define LOG_INFO(...)     S3MM_LOG_AT(::s3mm::log::Level::Info, __VA_ARGS__)
#define LOG_NOTICE(...)   S3MM_LOG_AT(::s3mm::log::Level::Notice, __VA_ARGS__)
#define LOG_WARN(...)     S3MM_LOG_AT(::s3mm::log::Level::Warning, __VA_ARGS__)
#define LOG_ERROR(...)    S3MM_LOG_AT(::s3mm::log::Level::Error, __VA_ARGS__)
#define LOG_CRITICAL(...) S3MM_LOG_AT(::s3mm::log::Level::Critical, __VA_ARGS__)
