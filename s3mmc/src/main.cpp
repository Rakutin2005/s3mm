// s3mmc — cluster client daemon for s3mmd.
//
//   s3mmc [-c /etc/s3mmc/s3mmc.conf]            run the cluster client
//   s3mmc status [--json]                        query the running instance
//
// One s3mmc fronts one s3mmd node. It exposes a UNIX socket per remote
// destination (remote-<id>.sock) that the core treats as an ordinary S3
// endpoint, and speaks mTLS to its peers over TCP. All nodes are equal:
// there are no roles in the cluster, only local and remote[id], where id is
// simultaneously the peer name and the remote cluster namespace it serves.
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "configfile.hpp"
#include "s3mm/clusterclient.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/value.hpp"

namespace {

void usage(std::FILE* out) {
    std::fprintf(out,
                 "Usage: s3mmc [command] [options]\n"
                 "\n"
                 "Commands:\n"
                 "  (default)             run the cluster client daemon\n"
                 "  status                print link/route state of the running instance\n"
                 "\n"
                 "Options:\n"
                 "  -c, --config <file>   configuration file (default /etc/s3mmc/s3mmc.conf)\n"
                 "      --json            machine-readable output for status\n"
                 "  -h, --help            show this help\n"
                 "  -V, --version         show version\n");
}

/// Send one control frame to the running instance and print the reply.
int runStatus(const std::string& runDir, const std::string& nodeId, bool json) {
    std::string path = runDir + "/" + nodeId + "/s3mmc.sock";
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { std::perror("s3mmc status: socket"); return 1; }
    sockaddr_un un{};
    un.sun_family = AF_UNIX;
    std::strncpy(un.sun_path, path.c_str(), sizeof(un.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) {
        std::fprintf(stderr, "s3mmc: cannot reach %s: %s\n", path.c_str(), strerror(errno));
        ::close(fd);
        return 1;
    }
    std::string req = "{\"cmd\":\"status\"}\n";
    if (::send(fd, req.data(), req.size(), MSG_NOSIGNAL) != (ssize_t)req.size()) {
        std::fprintf(stderr, "s3mmc: send failed\n");
        ::close(fd);
        return 1;
    }
    std::string line;
    char c;
    while (::recv(fd, &c, 1, 0) == 1) {
        if (c == '\n') break;
        line.push_back(c);
    }
    ::close(fd);
    auto v = s3mm::Value::parseJson(line);
    if (json) {
        std::printf("%s\n", line.c_str());
        return 0;
    }
    std::printf("node: %s\n", v.getString("node").c_str());
    std::printf("poll: %s every %llds\n", v.getString("poll_model").c_str(),
                (long long)v.find("poll_interval_sec")->asInt(0));
    if (const s3mm::Value* links = v.find("links"); links && links->isArray()) {
        std::printf("peers:\n");
        for (const auto& l : links->items())
            std::printf("  %-20s %-22s %-4s %-9s inv-rev %lld%s%s\n",
                        l.getString("id").c_str(), l.getString("address").c_str(),
                        l.getString("direction").c_str(),
                        l.asBool(false) || (l.find("connected") && l.find("connected")->asBool()) ? "up" : "down",
                        (long long)(l.find("inventory_revision") ? l.find("inventory_revision")->asInt(0) : 0),
                        "", "");
    }
    if (const s3mm::Value* routes = v.find("routes"); routes && routes->isArray()) {
        std::printf("routes:\n");
        for (const auto& r : routes->items())
            std::printf("  remote[%-20s] via %s\n", r.getString("cluster").c_str(),
                        r.getString("via").c_str());
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::string configPath = "/etc/s3mmc/s3mmc.conf";
    bool jsonOut = false;
    std::string command;

    static const option longOptions[] = {
        {"config", required_argument, nullptr, 'c'},
        {"json", no_argument, nullptr, 1},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {nullptr, 0, nullptr, 0},
    };
    int opt;
    while ((opt = ::getopt_long(argc, argv, "c:hV", longOptions, nullptr)) != -1) {
        switch (opt) {
            case 'c': configPath = optarg; break;
            case 1: jsonOut = true; break;
            case 'h': usage(stdout); return 0;
            case 'V':
#ifdef S3MM_VERSION
                std::printf("s3mmc %s\n", S3MM_VERSION);
#else
                std::printf("s3mmc\n");
#endif
                return 0;
            default: usage(stderr); return 2;
        }
    }
    if (optind < argc) command = argv[optind++];

    using namespace s3mm::s3mmc;

    ClusterClient::Options opts;
    TlsConfig tls;
    ClusterClient client(opts, tls);

    if (auto r = applyConfigFile(client, configPath); !r) {
        std::fprintf(stderr, "s3mmc: %s\n", r.error().c_str());
        return 1;
    }

    if (command == "status") {
        auto cur = client.options();
        return runStatus(cur.runDir, cur.nodeId, jsonOut);
    }
    if (!command.empty()) {
        std::fprintf(stderr, "s3mmc: unknown command '%s'\n", command.c_str());
        usage(stderr);
        return 2;
    }

    auto sr = client.start();
    if (!sr) {
        std::fprintf(stderr, "s3mmc: start failed: %s\n", sr.error().c_str());
        return 1;
    }
    std::fprintf(stderr, "s3mmc: node '%s' running\n", client.options().nodeId.c_str());

    // block forever; SIGTERM/SIGINT default disposition stops the process,
    // stop() runs from the destructor for graceful cleanup.
    for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    client.stop();
    return 0;
}
