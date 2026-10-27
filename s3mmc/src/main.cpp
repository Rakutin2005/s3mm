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
#include <optional>
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
                 "  visibility <peer>     effective inventory visibility for one peer\n"
                 "\n"
                 "Options:\n"
                 "  -c, --config <file>   configuration file (default /etc/s3mmc/s3mmc.conf)\n"
                 "      --json            machine-readable output for status\n"
                 "  -h, --help            show this help\n"
                 "  -V, --version         show version\n");
}

/// Send one raw control request line; returns the reply line (empty on error).
std::string controlQuery(const std::string& runDir, const std::string& nodeId,
                         const std::string& request, std::string* error) {
    std::string path = runDir + "/" + nodeId + "/s3mmc.sock";
    LOG_DEBUG("cli: control query to ", path, ": ", request);
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        *error = "socket: " + std::string(strerror(errno));
        LOG_ERROR("cli: ", *error);
        return {};
    }
    sockaddr_un un{};
    un.sun_family = AF_UNIX;
    std::strncpy(un.sun_path, path.c_str(), sizeof(un.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) {
        *error = "cannot reach " + path + ": " + strerror(errno);
        LOG_ERROR("cli: ", *error);
        ::close(fd);
        return {};
    }
    std::string req = request + "\n";
    if (::send(fd, req.data(), req.size(), MSG_NOSIGNAL) != (ssize_t)req.size()) {
        *error = "send failed";
        LOG_ERROR("cli: control request to ", path, " send failed: ", strerror(errno));
        ::close(fd);
        return {};
    }
    std::string line;
    char c;
    while (::recv(fd, &c, 1, 0) == 1) {
        if (c == '\n') break;
        line.push_back(c);
    }
    ::close(fd);
    if (line.empty()) {
        LOG_ERROR("cli: no reply from ", path);
    } else {
        LOG_DEBUG("cli: control reply ", line.size(), " bytes");
    }
    return line;
}

/// Send one control frame to the running instance and print the reply.
int runStatus(const std::string& runDir, const std::string& nodeId, bool json) {
    LOG_INFO("cli: status of node '", nodeId, "'", json ? " (json)" : "");
    std::string err;
    std::string line = controlQuery(runDir, nodeId, "{\"cmd\":\"status\"}", &err);
    if (line.empty()) {
        std::fprintf(stderr, "s3mmc: %s\n", err.c_str());
        return 1;
    }
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

int runVisibility(const std::string& runDir, const std::string& nodeId,
                  const std::string& peer, bool json) {
    LOG_INFO("cli: visibility of peer '", peer, "' on node '", nodeId, "'", json ? " (json)" : "");
    std::string req = "{\"cmd\":\"visibility\",\"peer\":\"" + peer + "\"}";
    std::string err;
    std::string line = controlQuery(runDir, nodeId, req, &err);
    if (line.empty()) {
        std::fprintf(stderr, "s3mmc: %s\n", err.c_str());
        return 1;
    }
    if (json) { std::printf("%s\n", line.c_str()); return 0; }
    auto v = s3mm::Value::parseJson(line);
    if (!v.isObject() || (v.find("ok") && !v.find("ok")->asBool())) {
        LOG_ERROR("cli: visibility of '", peer, "' failed: ", v.getString("error"));
        std::fprintf(stderr, "s3mmc: %s\n", v.getString("error").c_str());
        return 1;
    }
    std::printf("peer:    %s\n", v.getString("peer").c_str());
    std::printf("manager: %s\n", (v.find("manager") && v.find("manager")->asBool()) ? "yes" : "no");
    std::printf("mode:    %s\n", v.getString("mode").c_str());
    if (const s3mm::Value* el = v.find("elements"); el && el->isArray()) {
        std::printf("elements:");
        for (const auto& e : el->items()) std::printf(" %s", e.asString().c_str());
        std::printf("\n");
    }
    if (const s3mm::Value* wd = v.find("would_disclose"); wd && wd->isObject()) {
        std::printf("discloses now: clusters=%lld replications=%lld local_clusters=%lld\n",
                    (long long)wd->find("clusters")->asInt(0),
                    (long long)wd->find("replications")->asInt(0),
                    (long long)wd->find("local_clusters")->asInt(0));
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    {
        s3mm::log::Options bootstrap;
        bootstrap.ident = "s3mmc";
        bootstrap.level = s3mm::log::Level::Info;
        s3mm::log::init(bootstrap);
    }
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
            default:
                LOG_ERROR("invalid command line option");
                usage(stderr);
                return 2;
        }
    }
    if (optind < argc) command = argv[optind++];
    LOG_DEBUG("s3mmc: command '", command.empty() ? "run" : command, "' config ", configPath);

    using namespace s3mm::s3mmc;

    ClusterClient::Options opts;
    TlsConfig tls;
    ClusterClient client(opts, tls);

    std::optional<s3mm::log::Options> logOpts;
    if (auto r = applyConfigFile(client, configPath, &logOpts); !r) {
        LOG_CRITICAL("s3mmc: configuration ", configPath, " failed: ", r.error());
        std::fprintf(stderr, "s3mmc: %s\n", r.error().c_str());
        return 1;
    }
    client.setConfigPath(configPath);
    if (logOpts) {
        s3mm::log::init(*logOpts);
        LOG_INFO("s3mmc: logging re-initialised: level=", s3mm::log::levelName(logOpts->level), " facility=",
                 s3mm::log::facilityName(logOpts->facility), " socket=", logOpts->socketPath);
    }

    if (command == "status") {
        auto cur = client.options();
        return runStatus(cur.runDir, cur.nodeId, jsonOut);
    }
    if (command == "visibility") {
        auto cur = client.options();
        if (optind >= argc) {
            LOG_ERROR("cli: visibility: <peer-id> required");
            std::fprintf(stderr, "s3mmc visibility: <peer-id> required\n");
            return 2;
        }
        return runVisibility(cur.runDir, cur.nodeId, argv[optind], jsonOut);
    }
    if (!command.empty()) {
        LOG_ERROR("s3mmc: unknown command '", command, "'");
        std::fprintf(stderr, "s3mmc: unknown command '%s'\n", command.c_str());
        usage(stderr);
        return 2;
    }

    LOG_NOTICE("s3mmc: starting node '", client.options().nodeId, "' (config ", configPath, ")");
    auto sr = client.start();
    if (!sr) {
        LOG_CRITICAL("s3mmc: start failed: ", sr.error());
        return 1;
    }
    LOG_NOTICE("s3mmc: node '", client.options().nodeId, "' running");

    // block forever; SIGTERM/SIGINT default disposition stops the process,
    // stop() runs from the destructor for graceful cleanup.
    for (;;) std::this_thread::sleep_for(std::chrono::seconds(1));
    client.stop();
    return 0;
}
