#include <exception>
#include <string>

#include "testkit.hpp"

int main(int argc, char** argv) {
    const std::string filter = argc > 1 ? argv[1] : "";
    int ran = 0;
    int failed = 0;

    for (const auto& c : testkit::cases()) {
        if (!filter.empty() && c.name.find(filter) == std::string::npos) continue;
        ++ran;
        testkit::currentFailures() = 0;
        std::printf("[ RUN  ] %s\n", c.name.c_str());
        try {
            c.fn();
        } catch (const std::exception& e) {
            testkit::report("<test>", 0, std::string("unexpected exception: ") + e.what());
        } catch (...) {
            testkit::report("<test>", 0, "unexpected non-standard exception");
        }
        if (testkit::currentFailures()) {
            std::printf("[ FAIL ] %s (%d check(s) failed)\n", c.name.c_str(),
                        testkit::currentFailures());
            ++failed;
        } else {
            std::printf("[  OK  ] %s\n", c.name.c_str());
        }
    }

    std::printf("%d test(s) run, %d failed\n", ran, failed);
    return failed ? 1 : 0;
}
