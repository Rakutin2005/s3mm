#include <cstdio>
#include <cstring>
#include <getopt.h>
#include <string>

#include "s3mm/rest/daemon.hpp"

namespace {
void usage(std::FILE* out) {
    std::fprintf(out,
                 "Usage: s3mm-rest [options]\n"
                 "\n"
                 "  -c, --config <file>     configuration file\n"
                 "  -s, --socket <path>     main daemon UNIX socket\n"
                 "  -l, --listen <addr>     HTTP listen address (default 127.0.0.1)\n"
                 "  -p, --port <port>       HTTP listen port (default 8080)\n"
                 "  -m, --modules-dir <dir> REST modules directory\n"
                 "  -d, --daemonize         run in the background\n"
                 "  -t, --test              validate and exit\n"
                 "  -h, --help              show this help\n");
}
}

int main(int argc, char** argv) {
    s3mm::rest::Options options;
    static const option longOptions[] = {
        {"config", required_argument, nullptr, 'c'},
        {"socket", required_argument, nullptr, 's'},
        {"listen", required_argument, nullptr, 'l'},
        {"port", required_argument, nullptr, 'p'},
        {"modules-dir", required_argument, nullptr, 'm'},
        {"daemonize", no_argument, nullptr, 'd'},
        {"test", no_argument, nullptr, 't'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "c:s:l:p:m:dth", longOptions, nullptr)) != -1) {
        switch (opt) {
            case 'c': options.config = optarg; break;
            case 's': options.socket = optarg; break;
            case 'l': options.listen = optarg; break;
            case 'p': options.port = std::stoi(optarg); break;
            case 'm': options.modulesDir = optarg; break;
            case 'd': options.daemonize = true; break;
            case 't': options.validateOnly = true; break;
            case 'h': usage(stdout); return 0;
            default: usage(stderr); return 2;
        }
    }
    s3mm::rest::RestDaemon daemon(std::move(options));
    return daemon.run();
}
