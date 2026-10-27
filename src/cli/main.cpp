#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "s3mm/cli/commands.hpp"
#include "s3mm/cli/render.hpp"
#include "s3mm/common/error.hpp"
#include "s3mm/common/log.hpp"

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
                LOG_ERROR("option ", opt, " requires an argument");
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
    s3mm::log::Options logOptions;
    logOptions.ident = "s3mm";
    logOptions.facility = s3mm::log::Facility::User;
    s3mm::log::init(logOptions);

    Parsed p = parseGlobal(argc, argv);
    if (p.failed) {
        LOG_ERROR("invalid command line, exiting with status 2");
        return 2;
    }
    try {
        int rc = s3mm::cli::runCommand(p.opts, p.rest);
        LOG_INFO("exiting with status ", rc);
        return rc;
    } catch (const s3mm::UsageError& e) {
        LOG_ERROR("usage error: ", e.what());
        std::fprintf(stderr, "s3mm: %s\n", e.what());
        std::fprintf(stderr, "Try 's3mm --help' for more information.\n");
        return 2;
    } catch (const s3mm::Error& e) {
        LOG_ERROR("command failed: ", e.what());
        std::fprintf(stderr, "s3mm: %s\n", e.what());
        return 1;
    } catch (const std::exception& e) {
        LOG_ERROR("command failed with exception: ", e.what());
        std::fprintf(stderr, "s3mm: %s\n", e.what());
        return 1;
    }
}
