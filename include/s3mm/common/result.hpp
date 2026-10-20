#pragma once
#include <utility>
#include "s3mm/common/error.hpp"

namespace s3mm {

/// Lightweight Result<T> without exceptions for API boundaries (S3 calls, module calls).
template <class T>
class Result {
public:
    Result(T value) : ok_(true), value_(std::move(value)) {}

    /// Error result. Use the factory so that Result<std::string> stays unambiguous.
    static Result failure(std::string error) {
        Result r;
        r.ok_ = false;
        r.error_ = std::move(error);
        return r;
    }

    bool ok() const { return ok_; }
    explicit operator bool() const { return ok_; }

    T& value() {
        if (!ok_) throw Error(error_);
        return value_;
    }
    const T& value() const {
        if (!ok_) throw Error(error_);
        return value_;
    }
    T valueOr(T fallback) const { return ok_ ? value_ : std::move(fallback); }
    const std::string& error() const { return error_; }

private:
    Result() = default;
    bool ok_ = true;
    T value_{};
    std::string error_;
};

template <>
class Result<void> {
public:
    Result() : ok_(true) {}
    Result(std::string error) : ok_(false), error_(std::move(error)) {}

    static Result failure(std::string error) { return Result(std::move(error)); }
    static Result success() { return Result(); }

    bool ok() const { return ok_; }
    explicit operator bool() const { return ok_; }
    const std::string& error() const { return error_; }

private:
    bool ok_;
    std::string error_;
};

} // namespace s3mm
