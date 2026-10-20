#pragma once
// Minimal self-registering test framework (no external dependencies).
#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace testkit {

struct Case {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<Case>& cases() {
    static std::vector<Case> v;
    return v;
}

inline int& currentFailures() {
    static int n = 0;
    return n;
}

struct Registrar {
    Registrar(std::string name, std::function<void()> fn) {
        cases().push_back({std::move(name), std::move(fn)});
    }
};

inline void report(const char* file, int line, const std::string& what) {
    ++currentFailures();
    std::fprintf(stderr, "    %s:%d: %s\n", file, line, what.c_str());
}

} // namespace testkit

#define TEST(name)                                                              \
    static void test_fn_##name();                                               \
    static ::testkit::Registrar test_reg_##name(#name, test_fn_##name);         \
    static void test_fn_##name()

#define CHECK(cond)                                                             \
    do {                                                                        \
        if (!(cond)) ::testkit::report(__FILE__, __LINE__, "CHECK failed: " #cond); \
    } while (0)

#define CHECK_FALSE(cond) CHECK(!(cond))

#define CHECK_EQ(a, b)                                                          \
    do {                                                                        \
        auto va_ = (a);                                                         \
        auto vb_ = (b);                                                         \
        if (!(va_ == vb_)) {                                                    \
            std::ostringstream os_;                                             \
            os_ << "CHECK_EQ failed: " #a " == " #b " (" << va_ << " != " << vb_ << ")"; \
            ::testkit::report(__FILE__, __LINE__, os_.str());                   \
        }                                                                       \
    } while (0)

// For values without operator<< (PValue, Value, Result, ...): compare silently.
#define CHECK_TRUE(expr)                                                        \
    do {                                                                        \
        if (!(expr)) ::testkit::report(__FILE__, __LINE__, "expected true: " #expr); \
    } while (0)
