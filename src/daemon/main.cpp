#include <cstdio>
#include <cstring>
#include <getopt.h>
#include <string>

#include "s3mm/common/log.hpp"
#include "s3mm/daemon/daemon.hpp"

namespace {

void usage(std::FILE* out) {
    std::fprintf(out,
                 "Usage: s3mmd [options]\n"
                 "\n"
                 "  -c, --config <file>   configuration file (default /etc/s3mm/s3mmd.conf)\n"
                 "  -d, --daemonize       run in the background\n"
                 "  -t, --test            validate the configuration and exit\n"
                 "      --run-once        single replication cycle and exit\n"
                 "  -h, --help            show this help\n"
                 "  -V, --version         show version\n");
}

} // namespace

int main(int argc, char** argv) {
    s3mm::log::Options logOptions;
    logOptions.ident = "s3mmd";
    s3mm::log::init(logOptions);

    s3mm::daemon::Options options;

    static const option longOptions[] = {
        {"config", required_argument, nullptr, 'c'},
        {"daemonize", no_argument, nullptr, 'd'},
        {"test", no_argument, nullptr, 't'},
        {"run-once", no_argument, nullptr, 'R'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {nullptr, 0, nullptr, 0},
    };

    int opt;
    while ((opt = ::getopt_long(argc, argv, "c:dthV", longOptions, nullptr)) != -1) {
        switch (opt) {
            case 'c': options.config = optarg; break;
            case 'd': options.daemonize = true; break;
            case 't': options.validateOnly = true; break;
            case 'R': options.runOnce = true; break;
            case 'h': usage(stdout); return 0;
            case 'V':
#ifdef S3MM_VERSION
                std::printf("s3mmd %s\n", S3MM_VERSION);
#else
                std::printf("s3mmd\n");
#endif
                return 0;
            default:
                LOG_ERROR("invalid command line option (", argv[optind > 0 ? optind - 1 : 0], ")");
                usage(stderr);
                return 2;
        }
    }
    if (optind < argc) {
        LOG_ERROR("unexpected command line argument '", argv[optind], "'");
        std::fprintf(stderr, "s3mmd: unexpected argument '%s'\n", argv[optind]);
        usage(stderr);
        return 2;
    }

    LOG_DEBUG("command line parsed: config=", options.config, " daemonize=", options.daemonize ? "yes" : "no",
              " validate=", options.validateOnly ? "yes" : "no", " run_once=", options.runOnce ? "yes" : "no");
    s3mm::daemon::Daemon daemon(std::move(options));
    int rc = daemon.run();
    LOG_INFO("s3mmd exiting with status ", rc);
    return rc;
}
