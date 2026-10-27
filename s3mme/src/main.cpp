// s3mme — event client for s3mmd (event-driven integration).
//
//   s3mme [-c /etc/s3mme/s3mme.conf]        run the event daemon
//   s3mme status [--json]                   state of the running instance
//
// s3mme is exactly what s3mmc is for clustering: an optional companion client
// that talks to the s3mmd control socket. It tails the daemon's routing log
// (`replication route` records), turns every new decision into an Event,
// evaluates it against its OWN policy bundles (send/drop per broker) and
// publishes accepted events through loadable broker modules (.so): kafka,
// rabbitmq, ... Default configuration is trivially "send all" — policies are
// optional. Inbound messages can be consumed too (react-on-message model)
// when a module supports it; s3mme reacts by issuing control-socket commands.
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/value.hpp"
#include "s3mm/common/units.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/policy/bundle.hpp"
#include "s3mm/policy/engine.hpp"

#include "s3mme/event.hpp"
#include "s3mme/loader.hpp"

namespace {

std::atomic<bool> g_stop{false};

void onSignal(int) { g_stop = true; }

void usage(std::FILE* out) {
    std::fprintf(out,
                 "Usage: s3mme [command] [options]\n"
                 "\n"
                 "Commands:\n"
                 "  (default)          run the event daemon\n"
                 "  status [--json]    state of the running instance\n"
                 "  test-event         publish one synthetic event (dry-run wiring)\n"
                 "\n"
                 "Options:\n"
                 "  -c, --config <f>   configuration file (default /etc/s3mme/s3mme.conf)\n"
                 "  -t, --test         parse config, list brokers, exit non-zero on error\n"
                 "  -h, --help         show this help\n"
                 "  -V, --version      show version\n");
}

struct Opts {
    std::string node = "s3mme-1";
    std::string coreSocket = "/var/run/s3mm/s3mmd.sock";
    std::string runDir = "/var/run/s3mme";
    std::string modulePath;              // extra search dir for broker .so
    std::string pollInterval = "1s";     // tail interval of the routing log
    std::string defaultBroker;           // used when no policy `set broker=`
    std::vector<std::string> brokers;    // enabled broker names from config
    std::string policyBundle;            // optional bundle name in this config
    bool sendAll = true;                 // default model: everything is sent
    std::string logLevel, logFacility, logSocket; // optional log { } block
};

/// Top-level directives/blocks with the implicit `s3mm { }` and optional
/// `s3mme { }` wrappers flattened away.
std::vector<const s3mm::config::Node*> configScopes(const s3mm::config::Config& cfg) {
    std::vector<const s3mm::config::Node*> scopes;
    std::function<void(const s3mm::config::Node&)> add = [&](const s3mm::config::Node& n) {
        if ((n.name == "s3mme" || n.name == "s3mm") && n.block) { for (const auto& c : n.children) add(c); }
        else scopes.push_back(&n);
    };
    for (const auto& root : cfg.roots()) add(root);
    return scopes;
}

bool loadConfig(const std::string& path, Opts& o, std::string& err) {
    LOG_DEBUG("config: reading ", path);
    auto file = s3mm::fs::readFile(path);
    if (!file) { err = "cannot read " + path; LOG_ERROR("config: ", err); return false; }
    LOG_DEBUG("config: read ", file->size(), " bytes from ", path);
    auto parsed = s3mm::config::Config::parse(*file, path);
    if (!parsed) { err = parsed.error(); LOG_ERROR("config: parse ", path, " failed: ", err); return false; }
    const auto& cfg = parsed.value();
    LOG_DEBUG("config: parsed ", cfg.roots().size(), " top-level node(s)");

    auto scopes = configScopes(cfg);
    if (scopes.empty()) { err = "empty configuration"; LOG_ERROR("config: ", path, ": ", err); return false; }
    LOG_DEBUG("config: ", scopes.size(), " scope node(s) after flattening s3mme/s3mm wrappers");

    auto first = [&](const char* key) -> std::string {
        for (const auto* sc : scopes) {
            if (sc->name == key && !sc->block && sc->hasArg(0)) return sc->arg(0);
        }
        return {};
    };
    if (auto v = first("node"); !v.empty()) o.node = v;
    if (auto v = first("core_socket"); !v.empty()) o.coreSocket = v;
    if (auto v = first("run_dir"); !v.empty()) o.runDir = v;
    if (auto v = first("module_path"); !v.empty()) o.modulePath = v;
    if (auto v = first("poll_interval"); !v.empty()) o.pollInterval = v;
    if (auto v = first("default_broker"); !v.empty()) o.defaultBroker = v;
    if (auto v = first("policy"); !v.empty()) o.policyBundle = v;
    if (auto v = first("send_all"); !v.empty()) o.sendAll = v == "on" || v == "true" || v == "1";
    LOG_DEBUG("config: node=", o.node, " core_socket=", o.coreSocket, " run_dir=", o.runDir,
              " module_path=", o.modulePath.empty() ? "(defaults)" : o.modulePath, " poll_interval=", o.pollInterval,
              " default_broker=", o.defaultBroker.empty() ? "(first broker)" : o.defaultBroker,
              " send_all=", o.sendAll ? "on" : "off");

    for (const auto* sc : scopes) {
        if (sc->name == "broker") {
            std::string nm = sc->hasArg(0) ? sc->arg(0) : "";
            if (!nm.empty()) {
                o.brokers.push_back(nm);
                if (o.defaultBroker.empty()) o.defaultBroker = nm;
                LOG_DEBUG("config: broker block '", nm, "' (", sc->children.size(), " directive(s))");
            } else {
                LOG_WARN("config: broker{} block without a name ignored");
            }
        } else if (sc->name == "policy" && sc->hasArg(0)) {
            o.policyBundle = sc->arg(0);
            LOG_DEBUG("config: policy bundle '", o.policyBundle, "' selected");
        } else if (sc->name == "log") {
            for (const auto& d : sc->children) {
                std::string v = d.hasArg(0) ? d.arg(0) : "";
                if (d.name == "level") o.logLevel = v;
                else if (d.name == "facility") o.logFacility = v;
                else if (d.name == "socket") o.logSocket = v;
                else LOG_WARN("config: unknown log directive '", d.name, "' ignored");
            }
            LOG_DEBUG("config: log level=", o.logLevel, " facility=", o.logFacility, " socket=", o.logSocket);
        }
    }
    // also children of wrapper blocks already flattened via scopes? Broker blocks at top level yes.
    if (o.brokers.empty()) { err = "no broker{} blocks in config"; LOG_ERROR("config: ", path, ": ", err); return false; }
    LOG_INFO("config: loaded ", path, ": node=", o.node, " brokers=", s3mm::str::join(o.brokers, ","),
             " policy=", o.policyBundle.empty() ? "(send-all)" : o.policyBundle);
    return true;
}

void applyLogConfig(const Opts& o) {
    s3mm::log::Options lo = s3mm::log::options();
    if (!o.logLevel.empty()) {
        try { lo.level = s3mm::log::levelFromString(o.logLevel); }
        catch (const std::exception& e) { LOG_WARN("config: ", e.what(), ", keeping ", s3mm::log::levelName(lo.level)); }
    }
    if (!o.logFacility.empty() && !s3mm::log::facilityFromString(o.logFacility, lo.facility))
        LOG_WARN("config: unknown log facility '", o.logFacility, "', keeping ", s3mm::log::facilityName(lo.facility));
    if (!o.logSocket.empty()) lo.socketPath = o.logSocket;
    s3mm::log::init(lo);
    LOG_DEBUG("log: level=", s3mm::log::levelName(lo.level), " facility=", s3mm::log::facilityName(lo.facility),
              " socket=", lo.socketPath);
}

/// Minimal newline-JSON RPC against the s3mmd control socket.
s3mm::Value coreCall(const std::string& sockPath, const s3mm::Value& req, std::string& err) {
    sockaddr_un un{};
    un.sun_family = AF_UNIX;
    if (sockPath.size() >= sizeof(un.sun_path)) { err = "socket path too long"; return {}; }
    std::strncpy(un.sun_path, sockPath.c_str(), sizeof(un.sun_path) - 1);
    s3mm::log::Stopwatch sw;
    LOG_DEBUG("core: connecting to ", sockPath);
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { err = std::strerror(errno); return {}; }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) {
        err = "cannot connect to " + sockPath + ": " + std::strerror(errno);
        ::close(fd);
        return {};
    }
    std::string line = req.toJson(0) + "\n";
    LOG_DEBUG("core: connected to ", sockPath, ", sending ", line.size(), " bytes: ", s3mm::log::clip(line));
    size_t sent = 0;
    while (sent < line.size()) {
        ssize_t n = ::write(fd, line.data() + sent, line.size() - sent);
        if (n <= 0) { err = "write: "; err += std::strerror(errno); ::close(fd); return {}; }
        sent += (size_t)n;
    }
    std::string buf;
    char chunk[4096];
    bool gotLine = false;
    while (!gotLine) {
        ssize_t n = ::read(fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        buf.append(chunk, (size_t)n);
        if (buf.find('\n') != std::string::npos) gotLine = true;
    }
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
    LOG_DEBUG("core: received ", buf.size(), " bytes from ", sockPath, " in ", sw.ms(), " ms");
    if (buf.empty()) { err = "empty reply from core"; return {}; }
    std::string perr;
    auto v = s3mm::Value::parseJson(buf, &perr);
    if (v.isNull()) { err = "bad json reply: " + perr; LOG_DEBUG("core: unparsable reply: ", s3mm::log::clip(buf)); return {}; }
    return v;
}

int64_t parsePollSec(const std::string& s) {
    try { return s3mm::units::parseDurationSeconds(s); } catch (...) {}
    // tolerate plain numbers
    try { return std::stoll(s); } catch (...) {}
    LOG_WARN("config: invalid poll_interval '", s, "', using 2s");
    return 2;
}

std::string controlSocketPath(const Opts& o) { return o.runDir + "/" + o.node + "/s3mme.sock"; }

void writePidfile(const Opts& o) {
    s3mm::fs::mkdirp(o.runDir + "/" + o.node);
    std::string pidPath = controlSocketPath(o) + ".pid";
    std::ofstream pf(pidPath, std::ios::trunc);
    pf << ::getpid() << "\n";
    if (!pf) LOG_ERROR("cannot write pidfile ", pidPath, ": ", std::strerror(errno));
    else LOG_DEBUG("pidfile ", pidPath, " written (pid ", ::getpid(), ")");
}

} // namespace

// ---------------------------------------------------------------- main logic
int main(int argc, char** argv) {
    {
        s3mm::log::Options lo;
        lo.ident = "s3mme";
        s3mm::log::init(lo);
    }
    static struct option longopts[] = {
        {"config", required_argument, nullptr, 'c'},
        {"test", no_argument, nullptr, 't'},
        {"json", no_argument, nullptr, 'J'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {nullptr, 0, nullptr, 0},
    };
    std::string cfgPath = "/etc/s3mme/s3mme.conf";
    bool selfTest = false, asJson = false;
    std::string command;
    int c;
    while ((c = getopt_long(argc, argv, "c:thV", longopts, nullptr)) != -1) {
        switch (c) {
        case 'c': cfgPath = optarg; break;
        case 't': selfTest = true; break;
        case 'J': asJson = true; break;
        case 'h': usage(stdout); return 0;
        case 'V': std::printf("s3mme %s\n", "0.1.0"); return 0;
        default: LOG_ERROR("invalid command line arguments"); usage(stderr); return 2;
        }
    }
    if (optind < argc) command = argv[optind++];
    LOG_DEBUG("command=", command.empty() ? "(daemon)" : command, " config=", cfgPath, " test=", selfTest, " json=", asJson);

    if (command == "status") {
        // status comes from our own control socket:
        Opts o;
        std::string cerr;
        if (!loadConfig(cfgPath, o, cerr)) {
            LOG_ERROR("status: config ", cfgPath, ": ", cerr);
            std::fprintf(stderr, "config: %s\n", cerr.c_str());
            return 1;
        }
        sockaddr_un un{};
        un.sun_family = AF_UNIX;
        std::string sp = controlSocketPath(o);
        std::strncpy(un.sun_path, sp.c_str(), sizeof(un.sun_path) - 1);
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        LOG_DEBUG("status: connecting to ", sp);
        if (fd < 0 || ::connect(fd, reinterpret_cast<sockaddr*>(&un), sizeof(un)) < 0) {
            LOG_ERROR("status: cannot connect to ", sp, ": ", std::strerror(errno));
            std::fprintf(stderr, "s3mme is not running (%s)\n", sp.c_str());
            return 1;
        }
        std::string line = "{\"cmd\":\"status\"}\n";
        ::send(fd, line.data(), line.size(), MSG_NOSIGNAL);
        std::string buf;
        char ch[2048];
        ssize_t n;
        while ((n = ::recv(fd, ch, sizeof(ch), 0)) > 0) {
            buf.append(ch, (size_t)n);
            if (buf.find('\n') != std::string::npos) break;
        }
        ::close(fd);
        LOG_INFO("status: received ", buf.size(), " bytes from ", sp);
        if (asJson) std::printf("%s", buf.c_str());
        else {
            std::string perr;
            auto v = s3mm::Value::parseJson(buf, &perr);
            if (!v.isNull()) std::printf("%s\n", v.toJson(2).c_str());
            else std::printf("%s", buf.c_str());
        }
        return 0;
    }

    Opts o;
    std::string err;
    LOG_NOTICE("s3mme starting (pid ", ::getpid(), ", config ", cfgPath, ")");
    if (!loadConfig(cfgPath, o, err)) {
        LOG_CRITICAL("config ", cfgPath, ": ", err);
        std::fprintf(stderr, "s3mme: config %s: %s\n", cfgPath.c_str(), err.c_str());
        return 1;
    }
    applyLogConfig(o);

    // Load broker modules.
    s3mme::BrokerLoader loader;
    LOG_DEBUG("modules: loading from ", o.modulePath.empty() ? "default search paths" : o.modulePath);
    auto ld = o.modulePath.empty() ? loader.loadDefaults() : loader.loadDir(o.modulePath);
    if (!ld) {
        LOG_CRITICAL("modules: ", ld.error());
        if (selfTest) std::fprintf(stderr, "s3mme: modules: %s\n", ld.error().c_str());
        return 1;
    }
    LOG_INFO("modules: available brokers: ", s3mm::str::join(loader.names(), ","));
    std::vector<std::pair<std::string, s3mme::IBroker*>> brokers;
    for (const auto& name : o.brokers) {
        auto* b = loader.find(name);
        if (!b) {
            LOG_CRITICAL("broker module '", name, "' not found");
            if (selfTest) std::fprintf(stderr, "s3mme: broker module '%s' not found\n", name.c_str());
            return 1;
        }
        LOG_DEBUG("broker '", name, "' resolved to module ", b->name());
        brokers.emplace_back(name, b);
    }

    // Optional local policy bundle ("what to send"). Parsed from the same
    // config file with the core policy parser; absence => send-all.
    std::unique_ptr<s3mm::policy::Bundle> bundle;
    if (!o.policyBundle.empty()) {
        LOG_DEBUG("policy: loading bundle '", o.policyBundle, "' from ", cfgPath);
        auto file2 = s3mm::fs::readFile(cfgPath); auto parsed = file2 ? s3mm::config::Config::parse(*file2, cfgPath) : s3mm::config::Config::parse("", cfgPath);
        if (!parsed) LOG_ERROR("policy: cannot parse ", cfgPath, ": ", parsed.error());
        if (parsed) {
            for (const auto* np : configScopes(parsed.value())) {
                const auto& n = *np;
                if (n.name == "policy" && n.block && n.hasArg(0) && n.arg(0) == o.policyBundle) {
                    auto b = s3mm::policy::Bundle::fromNode(n);
                    if (!b) {
                        LOG_CRITICAL("policy: bundle '", o.policyBundle, "': ", b.error());
                        if (selfTest) std::fprintf(stderr, "s3mme: policy: %s\n", b.error().c_str());
                        return 1;
                    }
                    bundle = std::make_unique<s3mm::policy::Bundle>(b.value());
                    LOG_INFO("policy: bundle '", o.policyBundle, "' loaded");
                }
            }
        }
        if (!bundle) {
            LOG_CRITICAL("policy bundle '", o.policyBundle, "' not found in ", cfgPath);
            if (selfTest) std::fprintf(stderr, "s3mme: policy bundle '%s' not found\n", o.policyBundle.c_str());
            return 1;
        }
    } else {
        LOG_INFO("policy: none configured, send_all=", o.sendAll ? "on" : "off");
    }
    s3mm::policy::Engine polEngine;

    if (selfTest) {
        LOG_NOTICE("config test OK: ", cfgPath, " (", brokers.size(), " broker(s), policy ",
                   bundle ? o.policyBundle : std::string("(send-all)"), ")");
        std::printf("brokers:");
        for (auto& [n, b] : brokers) std::printf(" %s", n.c_str());
        std::printf("\npolicy: %s\n", bundle ? o.policyBundle.c_str() : "(send-all)");
        std::printf("core socket: %s\n", o.coreSocket.c_str());
        return 0;
    }

    // Connect brokers (each gets its broker{} block as config Value).
    auto parsedRootFile = s3mm::fs::readFile(cfgPath); auto parsedRoot = parsedRootFile ? s3mm::config::Config::parse(*parsedRootFile, cfgPath) : s3mm::config::Config::parse("", cfgPath);
    std::map<std::string, const s3mm::config::Node*> brokerNodes;
    if (parsedRoot) {
        for (const auto* n : configScopes(parsedRoot.value()))
            if (n->name == "broker" && n->hasArg(0)) brokerNodes[n->arg(0)] = n;
    }
    for (auto& [name, b] : brokers) {
        s3mm::Value cfg;
        if (auto it = brokerNodes.find(name); it != brokerNodes.end()) {
            for (const auto& d : it->second->children) cfg.set(d.name, s3mm::Value::str(d.hasArg(0)?d.arg(0):""));
        } else {
            LOG_WARN("broker ", name, ": no broker{} block found, connecting with module defaults");
        }
        LOG_DEBUG("broker ", name, ": connecting");
        s3mm::log::Stopwatch sw;
        auto res = b->connect(cfg);
        if (!res) {
            LOG_CRITICAL("broker ", name, " connect failed: ", res.error());
            return 1;
        }
        LOG_INFO("broker ", name, ": connected in ", sw.ms(), " ms");
    }

    signal(SIGINT, onSignal);
    signal(SIGTERM, onSignal);
    writePidfile(o);

    // Tail loop: poll `replication route` from the core, dedupe by cursor.
    int64_t period = parsePollSec(o.pollInterval);
    uint64_t seq = 0;
    std::string lastKey; // cursor: identity of the newest seen record
    LOG_NOTICE("started: node ", o.node, ", polling ", o.coreSocket, " every ", period, "s, ", brokers.size(),
               " broker(s), default broker ", o.defaultBroker);

    auto emit = [&](const s3mme::Event& ev) {
        // Policy decides whether/where to send.
        std::string brokerName = o.defaultBroker;
        bool send = o.sendAll;
        if (bundle) {
            s3mm::policy::Context ctx;
            ctx.set("name", ev.key);
            ctx.set("bucket", ev.bucket);
            ctx.set("kind", ev.kind);
            ctx.set("outcome", ev.outcome);
            ctx.set("target", ev.target);
            ctx.set("rule", ev.rule);
            ctx.set("replication", ev.replication);
            ctx.set("size", ev.size);
            ctx.set("source.cluster", ev.sourceCluster);
            ctx.set("destination.cluster", ev.destCluster);
            auto d = polEngine.evaluate(*bundle, s3mm::policy::Category::Object, ctx, ev.replication);
            send = d.accepted();
            for (const auto& a : d.actions) {
                if (a.name == "set") {
                    auto it = a.params.find("broker");
                    if (it != a.params.end()) brokerName = it->second;
                }
            }
            LOG_DEBUG("event ", ev.id, ": policy '", o.policyBundle, "' -> ", send ? "send" : "drop",
                      " (", d.actions.size(), " action(s)), broker ", brokerName);
        }
        if (!send) { LOG_DEBUG("event ", ev.id, ": dropped (", bundle ? "policy" : "send_all off", ")"); return; }
        s3mme::IBroker* target = nullptr;
        for (auto& [n, b] : brokers) if (n == brokerName) target = b;
        if (!target) {
            LOG_WARN("event ", ev.id, ": broker '", brokerName, "' not enabled, falling back to ", brokers.front().first);
            target = brokers.front().second;
        }
        s3mm::log::Stopwatch sw;
        auto r = target->publish(ev, ev.target);
        if (!r) LOG_ERROR("event ", ev.id, ": publish via ", target->name(), " failed: ", r.error());
        else LOG_DEBUG("event ", ev.id, ": queued to ", target->name(),
                       " (destination ", ev.target.empty() ? "(default)" : ev.target, ") in ", sw.ms(), " ms");
    };

    while (!g_stop) {
        s3mm::Value req;
        req.set("cmd", s3mm::Value::str("routes"));
        req.set("limit", s3mm::Value::number((int64_t)500));
        std::string cerr;
        LOG_DEBUG("poll: routes from ", o.coreSocket);
        s3mm::log::Stopwatch pollSw;
        auto rep = coreCall(o.coreSocket, req, cerr);
        const s3mm::Value* arr = rep.find("data");
        if (!cerr.empty()) {
            LOG_ERROR("core ", o.coreSocket, ": ", cerr);
        } else if (!rep.find("ok") || !rep.find("ok")->asBool(false)) {
            const auto* e = rep.find("error");
            LOG_ERROR("core ", o.coreSocket, ": routes failed: ", e ? e->asString("?") : std::string("(no error text)"));
        } else if (arr && arr->isArray()) {
            // Records arrive newest-first; collect them oldest-first.
            std::vector<s3mme::Event> events;
            std::vector<std::string> cursors;
            for (auto it = arr->items().rbegin(); it != arr->items().rend(); ++it) {
                const auto& ri = *it;
                const auto* at = ri.find("at");
                const auto* rp = ri.find("replication");
                const auto* kd = ri.find("kind");
                const auto* ky = ri.find("key");
                if (!at || !rp || !rp->isString() || !kd || !kd->isString() || !ky || !ky->isString()) {
                    LOG_WARN("poll: skipping malformed route record: ", s3mm::log::clip(ri.toJson(0)));
                    continue;
                }
                auto optStr = [&](const char* k) { const auto* v = ri.find(k); return v ? v->asString("") : std::string(); };
                s3mme::Event ev;
                ev.atSec = at->asInt(0);
                ev.node = o.node;
                ev.replication = rp->asString();
                ev.kind = kd->asString();
                ev.key = ky->asString();
                ev.bucket = optStr("bucket");
                ev.outcome = optStr("outcome");
                ev.target = optStr("target");
                ev.rule = optStr("rule");
                ev.reason = optStr("reason");
                if (const auto* sz = ri.find("size")) ev.size = (uint64_t)sz->asInt(0);
                cursors.push_back(ev.replication + "|" + ev.kind + "|" + std::to_string(ev.atSec) + "|" + ev.key + "|" +
                                  ev.bucket + "|" + ev.outcome + "|" + ev.rule);
                events.push_back(std::move(ev));
            }
            LOG_DEBUG("poll: ", events.size(), " route record(s) in ", pollSw.ms(), " ms");
            // Resume right after the newest record seen last time.
            size_t from = 0;
            if (!lastKey.empty()) {
                size_t i = cursors.size();
                while (i > 0 && cursors[i - 1] != lastKey) --i;
                if (i > 0) { from = i; LOG_DEBUG("poll: cursor ", lastKey, " found, ", events.size() - from, " new record(s)"); }
                else if (!events.empty()) LOG_WARN("poll: cursor ", lastKey, " not in the last ", events.size(), " record(s), events may have been missed");
            }
            uint64_t emitted = 0;
            for (size_t i = from; i < events.size(); ++i) {
                auto& ev = events[i];
                ev.id = o.node + "-" + std::to_string(++seq);
                LOG_DEBUG("event ", ev.id, ": replication=", ev.replication, " kind=", ev.kind, " bucket=", ev.bucket,
                          " key=", ev.key, " outcome=", ev.outcome, " rule=", ev.rule, " target=", ev.target,
                          " size=", ev.size, " reason=", ev.reason);
                emit(ev);
                ++emitted;
            }
            if (!cursors.empty()) lastKey = cursors.back();
            if (emitted) LOG_INFO("poll: ", emitted, " new event(s) processed");
        } else {
            LOG_WARN("core reply without routes: ", s3mm::log::clip(rep.toJson(0)));
        }
        for (int i = 0; i < period * 4 && !g_stop; ++i) {
            struct timespec ts{0, 250 * 1000000L};
            nanosleep(&ts, nullptr);
        }
    }

    LOG_NOTICE("shutting down");
    for (auto& [n, b] : brokers) {
        LOG_DEBUG("broker ", n, ": flushing");
        auto fr = b->flush();
        if (!fr) LOG_WARN("broker ", n, ": flush failed: ", fr.error());
        b->disconnect();
        LOG_INFO("broker ", n, ": disconnected");
    }
    LOG_NOTICE("stopped");
    return 0;
}
