#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "s3mm/cli/commands.hpp"
#include "s3mm/cli/render.hpp"
#include "s3mm/common/error.hpp"

#ifndef S3MM_VERSION
#define S3MM_VERSION "0.0.0"
#endif

namespace {

/// Global options may appear anywhere on the line; everything else is
/// collected, in order, as the command line proper.
struct Parsed {
    s3mm::cli::Options opts;
    std::vector<std::string> rest;
    bool failed = false;
};

Parsed parseGlobal(int argc, char** argv) {
    Parsed p;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&](const std::string& opt) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "s3mm: option %s requires an argument\n", opt.c_str());
                p.failed = true;
                return {};
            }
            return argv[++i];
        };
        if (a == "-h" || a == "--help") {
            std::fputs(s3mm::cli::usage().c_str(), stdout);
            std::exit(0);
        } else if (a == "-V" || a == "--version") {
            std::printf("s3mm %s\n", S3MM_VERSION);
            std::exit(0);
        } else if (a == "-c" || a == "--config") {
            p.opts.config = value(a);
        } else if (a == "-s" || a == "--socket") {
            p.opts.socket = value(a);
        } else if (a == "-o" || a == "--output") {
            try {
                p.opts.format = s3mm::cli::formatFromString(value(a));
            } catch (const s3mm::Error& e) {
                std::fprintf(stderr, "s3mm: %s\n", e.what());
                p.failed = true;
            }
        } else if (a == "--json") {
            p.opts.format = s3mm::cli::Format::Json;
        } else if (a == "--yaml") {
            p.opts.format = s3mm::cli::Format::Yaml;
        } else if (a == "--permanent") {
            p.opts.permanent = true;
        } else if (a == "-t" || a == "--test") {
            p.opts.test = true;
        } else {
            p.rest.push_back(a);
        }
    }
    return p;
}

} // namespace

int main(int argc, char** argv) {
    Parsed p = parseGlobal(argc, argv);
    if (p.failed) return 2;
    try {
        return s3mm::cli::runCommand(p.opts, p.rest);
    } catch (const s3mm::UsageError& e) {
        std::fprintf(stderr, "s3mm: %s\n", e.what());
        std::fprintf(stderr, "Try 's3mm --help' for more information.\n");
        return 2;
    } catch (const s3mm::Error& e) {
        std::fprintf(stderr, "s3mm: %s\n", e.what());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "s3mm: %s\n", e.what());
        return 1;
    }
}
