#pragma once
#include <stdexcept>
#include <string>

namespace s3mm {

/// Base class for all s3mm errors.
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

/// Usage / CLI syntax error.
class UsageError : public Error {
public:
    explicit UsageError(const std::string& message) : Error(message) {}
};

/// Configuration file error (syntax or semantics) with location.
class ConfigError : public Error {
public:
    std::string file;
    int line = 0;
    ConfigError(const std::string& message, std::string f = {}, int l = 0)
        : Error(l ? (f + ":" + std::to_string(l) + ": " + message) : message), file(std::move(f)), line(l) {}
};

} // namespace s3mm
