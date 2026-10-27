// s3mmc.conf — see configfile.hpp for the grammar. Applies parsed settings to
// a not-yet-started ClusterClient (options, TLS material, peers).
#include "configfile.hpp"

#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <exception>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/units.hpp"
#include "s3mm/config/config.hpp"

namespace s3mm::s3mmc {

namespace {

std::string firstNonEmpty(const std::vector<const config::Node*>& nodes,
                          const std::string& directive) {
    for (const auto* n : nodes) {
        std::string v = n->value(directive);
        if (!v.empty()) {
            LOG_DEBUG("config: ", directive, " = ", v, " (", n->file, ":", n->line, ")");
            return v;
        }
    }
    LOG_DEBUG("config: ", directive, " not set");
    return {};
}

bool parseListen(const std::string& spec, std::string* address, int* port, std::string* error) {
    auto colon = spec.rfind(':');
    if (colon == std::string::npos) {
        *error = "listen: expected address:port, got '" + spec + "'";
        LOG_ERROR("config: ", *error);
        return false;
    }
    *address = spec.substr(0, colon);
    if (*address == "*" || *address == "any") *address = "0.0.0.0";
    std::string p = spec.substr(colon + 1);
    if (p.empty()) {
        *error = "listen: missing port";
        LOG_ERROR("config: ", *error, " in '", spec, "'");
        return false;
    }
    *port = std::atoi(p.c_str());
    if (*port <= 0 || *port > 65535) LOG_WARN("config: listen port '", p, "' looks invalid (parsed ", *port, ")");
    LOG_DEBUG("config: listen ", *address, ":", *port);
    return true;
}

} // namespace

Result<void> applyConfigText(ClusterClient& client, const std::string& text,
                             const std::string& filename, std::optional<log::Options>* logOut) {
    log::Stopwatch sw;
    LOG_DEBUG("config: parsing ", filename, " (", text.size(), " bytes)");
    auto cfgR = config::Config::parse(text, filename);
    if (!cfgR) {
        LOG_ERROR("config: parse of ", filename, " failed: ", cfgR.error());
        return Result<void>::failure(cfgR.error());
    }
    const config::Config& cfg = cfgR.value();

    // Candidate scopes: an optional "s3mmc"/"s3mm" wrapper block plus any
    // top-level fragments (from includes).
    std::vector<const config::Node*> scopes;
    for (const auto& root : cfg.roots())
        if (root.name == "s3mmc" || root.name == "s3mm") scopes.push_back(&root);
    for (const auto& root : cfg.roots())
        if (root.name != "s3mmc" && root.name != "s3mm") scopes.push_back(&root);
    if (scopes.empty()) {
        LOG_ERROR("config: ", filename, " is empty");
        return Result<void>::failure("empty configuration");
    }
    LOG_DEBUG("config: ", cfg.roots().size(), " top-level nodes, ", scopes.size(), " scopes");

    ClusterClient::Options opts = client.options();
    TlsConfig tls = client.tlsConfig();

    // ---- scalars -----------------------------------------------------------------
    std::string node = firstNonEmpty(scopes, "node");
    if (!node.empty()) opts.nodeId = node;
    if (auto v = firstNonEmpty(scopes, "run_dir"); !v.empty()) opts.runDir = v;
    if (auto v = firstNonEmpty(scopes, "core_socket"); !v.empty()) opts.coreSocket = v;
    if (auto v = firstNonEmpty(scopes, "spool_dir"); !v.empty()) opts.spoolDir = v;
    // managed: node(s) allowed to manage this one — patch our config, pull
    // credentials. Value is a comma/space separated list of peer ids (CNs),
    // "*" (everyone) or "none" (nobody). Identity check happens at frame
    // handling time against the CN authenticated over mTLS.
    if (auto v = firstNonEmpty(scopes, "managed"); !v.empty()) {
        auto ml = parseManagedList(v);
        if (!ml) {
            LOG_ERROR("config: managed '", v, "': ", ml.error());
            return Result<void>::failure(ml.error());
        }
        opts.managedNodes = ml.value();
        LOG_DEBUG("config: managed -> [", str::join(opts.managedNodes, ","), "]");
    }
    // (retired) expose_credentials: credential visibility is now governed by
    // the per-peer `expose` ACL — a peer listed with element `credentials`
    // may request sealed credentials over the cluster channel. Managers may
    // always do so regardless of ACLs.
    if (!firstNonEmpty(scopes, "expose_credentials").empty()) {
        LOG_ERROR("config: expose_credentials is retired; use 'expose { credentials; to <peer>; }'");
        return Result<void>::failure("expose_credentials is retired; use 'expose { credentials; to <peer>; }' instead");
    }
    // required_only: bind remote[id] UNIX sockets only for clusters that our
    // own replication rules reference (lazy provisioning). off => provision
    // every cluster known from the merged inventory.
    if (auto v = firstNonEmpty(scopes, "required_only"); !v.empty()) {
        if (v == "on" || v == "true" || v == "yes" || v == "1")
            opts.requiredOnly = true;
        else if (v == "off" || v == "false" || v == "no" || v == "0")
            opts.requiredOnly = false;
        else {
            LOG_ERROR("config: required_only must be on|off, got '", v, "'");
            return Result<void>::failure("required_only must be on|off, got '" + v + "'");
        }
    }
    // expose — per-peer inventory visibility ACL.
    //   expose { clusters replications !endpoints; to = s3c-2; order = 10; };
    //   expose *;                       (legacy global form, applies to unmanaged)
    // Element spec: "*" = everything, "none" = nothing, "!"-prefixed names are
    // exclusions, plain list = include exactly these. `to` selects the peers
    // the rule governs: "unmanaged" (default), "all", a peer id/CN or a glob
    // ("zone-*"). Managers ALWAYS see everything and ignore every expose rule.
    // Rules with an explicit `to` compile into the ordered per-peer ACL table;
    // bare legacy rules remain the global unmanaged filter.
    for (const auto* sc : scopes) {
        for (const auto& exN : sc->findAll("expose")) {
            const config::Node& ex = *exN;
            ClusterClient::Options::ExposeRule rule;
            rule.line = ex.line;
            std::string spec;
            // Accept both forms: `expose a b c;` (args) and `expose { a; b; };`
            // (block — directive names become the element list).
            for (size_t i = 0; i < 8 && ex.hasArg(i); ++i) {
                if (!spec.empty()) spec += ",";
                spec += ex.arg(i);
            }
            if (spec.empty()) {
                for (const auto& d : ex.children) {
                    if (d.name == "to" || d.name == "order") continue;
                    if (!spec.empty()) spec += ",";
                    spec += d.name;
                    // nested negation form: `!endpoints;` parses as arg too
                    if (d.hasArg(0) && !d.arg(0).empty() && d.name.empty())
                        spec += d.arg(0);
                }
            }
            if (spec.empty()) spec = "*";
            auto el = ClusterClient::parseExposeList(spec);
            if (!el) {
                LOG_ERROR("config: expose (", ex.file, ":", ex.line, ") '", spec, "': ", el.error());
                return Result<void>::failure(el.error());
            }
            rule.spec = spec;
            // scoped block form: `to`/`order` may be nested directives ...
            for (const auto& d : ex.children) {
                if (d.name == "to" && d.hasArg(0)) rule.appliesTo = d.arg(0);
                if (d.name == "order" && d.hasArg(0)) {
                    try { rule.order = std::stoi(d.arg(0)); }
                    catch (...) {
                        LOG_ERROR("config: expose (", ex.file, ":", ex.line, "): bad order '", d.arg(0), "'");
                        return Result<void>::failure("expose: bad order '" + d.arg(0) + "'");
                    }
                }
            }
            // ... or scalar args of `expose <spec> to <peer>;` style lines
            if (rule.appliesTo.empty()) {
                for (size_t i = 0; i < 8 && ex.hasArg(i); ++i)
                    if (ex.arg(i) == "to" && ex.hasArg(i + 1)) { rule.appliesTo = ex.arg(i + 1); break; }
            }
            if (rule.appliesTo.empty()) rule.appliesTo = "unmanaged";
            LOG_DEBUG("config: expose rule line ", rule.line, " spec='", rule.spec, "' to='", rule.appliesTo,
                      "' order=", rule.order);
            opts.exposeRules.push_back(std::move(rule));
        }
    }
    auto aclR = ClusterClient::compilePeerAcls(opts);
    if (!aclR) {
        LOG_ERROR("config: expose ACL compilation failed: ", aclR.error());
        return Result<void>::failure(aclR.error());
    }
    if (auto v = firstNonEmpty(scopes, "inventory"); !v.empty()) {
        if (v != "push" && v != "pull" && v != "both") {
            LOG_ERROR("config: inventory model must be push|pull|both, got '", v, "'");
            return Result<void>::failure("inventory model must be push|pull|both, got '" + v + "'");
        }
        opts.pollModel = v;
    }
    try {
        if (auto v = firstNonEmpty(scopes, "poll_interval"); !v.empty())
            opts.pollIntervalSec = units::parseDurationSeconds(v);
        if (auto v = firstNonEmpty(scopes, "poll_timeout"); !v.empty())
            opts.pollTimeoutSec = units::parseDurationSeconds(v);
        if (auto v = firstNonEmpty(scopes, "core_timeout"); !v.empty())
            opts.coreTimeoutSec = units::parseDurationSeconds(v);
        if (auto v = firstNonEmpty(scopes, "spool_threshold"); !v.empty())
            opts.spoolThresholdBytes = units::parseSize(v);
    } catch (const std::exception& e) {
        LOG_ERROR("config: bad interval/size value: ", e.what());
        return Result<void>::failure(std::string("bad interval value: ") + e.what());
    }
    if (opts.nodeId.empty()) {
        char host[256];
        if (::gethostname(host, sizeof host) == 0) {
            opts.nodeId = host;
            LOG_WARN("config: node not set, using hostname '", opts.nodeId, "'");
        } else {
            LOG_WARN("config: node not set and gethostname failed: ", std::strerror(errno));
        }
    }

    // ---- listen ------------------------------------------------------------------
    std::string listenSpec = firstNonEmpty(scopes, "listen");
    if (!listenSpec.empty()) {
        std::string addr;
        int port = 0;
        std::string err;
        if (!parseListen(listenSpec, &addr, &port, &err)) return Result<void>::failure(err);
        opts.listenAddress = addr;
        opts.listenPort = port;
    }

    // ---- tls block ---------------------------------------------------------------
    for (const auto* sc : scopes) {
        const config::Node* t = sc->find("tls");
        if (!t) continue;
        tls.certFile = t->value("cert", tls.certFile);
        tls.keyFile = t->value("key", tls.keyFile);
        tls.caFile = t->value("ca", tls.caFile);
        LOG_DEBUG("config: tls block (", t->file, ":", t->line, ") cert=", tls.certFile, " key=", tls.keyFile,
                  " ca=", tls.caFile);
    }

    // ---- log block ---------------------------------------------------------------
    for (const auto* sc : scopes) {
        const config::Node* l = sc->name == "log" && sc->block ? sc : sc->find("log");
        if (!l || !logOut) continue;
        log::Options lo = logOut->has_value() ? **logOut : log::Options{};
        lo.ident = "s3mmc";
        if (auto v = l->value("level"); !v.empty()) {
            try { lo.level = log::levelFromString(v); }
            catch (const std::exception& e) { LOG_WARN("config: log level '", v, "' invalid (", e.what(), "), keeping ", log::levelName(lo.level)); }
        }
        if (auto v = l->value("facility"); !v.empty() && !log::facilityFromString(v, lo.facility))
            LOG_WARN("config: unknown log facility '", v, "', keeping ", log::facilityName(lo.facility));
        lo.socketPath = l->value("socket", lo.socketPath);
        LOG_DEBUG("config: log block (", l->file, ":", l->line, ") level=", log::levelName(lo.level),
                  " facility=", log::facilityName(lo.facility), " socket=", lo.socketPath);
        *logOut = lo;
    }

    // ---- peer blocks -------------------------------------------------------------
    std::vector<PeerConfig> peers;
    for (const auto* sc : scopes) {
        for (const config::Node* p : sc->findAll("peer")) {
            if (!p->hasArg(0)) {
                LOG_ERROR("config: peer block without id (", p->file, ":", p->line, ")");
                return Result<void>::failure("peer block requires an id");
            }
            PeerConfig pc;
            pc.id = p->arg(0);
            pc.address = p->value("address");
            if (pc.address.empty()) {
                LOG_ERROR("config: peer '", pc.id, "' (", p->file, ":", p->line, "): address required");
                return Result<void>::failure("peer '" + pc.id + "': address required");
            }
            pc.dial = p->boolValue("connect", true);
            if (auto v = p->value("connect_timeout"); !v.empty()) {
                try {
                    pc.connectTimeoutSec = (int)units::parseDurationSeconds(v);
                } catch (const std::exception& e) {
                    LOG_ERROR("config: peer '", pc.id, "' connect_timeout '", v, "': ", e.what());
                    return Result<void>::failure("peer '" + pc.id + "' connect_timeout: " + e.what());
                }
            }
            LOG_DEBUG("config: peer '", pc.id, "' (", p->file, ":", p->line, ") address=", pc.address,
                      " connect=", pc.dial ? "on" : "off", " connect_timeout=", pc.connectTimeoutSec, "s");
            peers.push_back(pc);
        }
    }

    // ---- apply -------------------------------------------------------------------
    auto cr = client.configure(opts, tls);
    if (!cr) {
        LOG_ERROR("config: ", filename, " rejected by client: ", cr.error());
        return cr;
    }
    size_t peerCount = peers.size();
    if (!peers.empty()) {
        auto pr = client.setPeers(std::move(peers));
        if (!pr) {
            LOG_ERROR("config: ", filename, " peers rejected: ", pr.error());
            return pr;
        }
    } else {
        LOG_DEBUG("config: no peer blocks, keeping current peer set");
    }
    LOG_INFO("config: ", filename, " applied in ", sw.ms(), " ms: node '", opts.nodeId, "', ", peerCount, " peers, ",
             opts.exposeRules.size(), " expose rules, inventory ", opts.pollModel, "/", opts.pollIntervalSec, "s");
    return Result<void>::success();
}

Result<void> applyConfigFile(ClusterClient& client, const std::string& path,
                             std::optional<log::Options>* logOut) {
    LOG_DEBUG("config: loading ", path, " (with includes)");
    auto cfgR = config::Config::load(path);
    if (!cfgR) {
        LOG_ERROR("config: cannot load ", path, ": ", cfgR.error());
        return Result<void>::failure(cfgR.error());
    }
    {
        std::vector<std::string> files;
        for (const auto& root : cfgR.value().roots())
            if (!root.file.empty() && std::find(files.begin(), files.end(), root.file) == files.end())
                files.push_back(root.file);
        for (const auto& f : files) LOG_DEBUG("config: loaded file ", f);
        LOG_INFO("config: loaded ", path, " (", files.size(), " files, ", cfgR.value().roots().size(), " top-level nodes)");
    }
    return applyConfigText(client, cfgR.value().dump(), path, logOut);
}

Result<std::vector<std::string>> parseManagedList(const std::string& spec) {
    // Normalise separators: commas become spaces, then split on whitespace.
    std::string norm;
    norm.reserve(spec.size());
    for (char c : spec) norm.push_back(c == ',' ? ' ' : c);
    auto parts = str::splitWS(norm);
    std::vector<std::string> out;
    for (auto& p : parts) {
        if (p.empty()) continue;
        if (p == "*") {
            LOG_DEBUG("config: managed '*' (every peer may manage this node)");
            return Result<std::vector<std::string>>(std::vector<std::string>{"*"});
        }
        if (p == "none" || p == "off") continue;  // explicit none => empty list
        // Reject accidental wildcards inside the list to keep semantics sharp.
        if (p.find('*') != std::string::npos) {
            LOG_ERROR("config: managed '", spec, "': wildcard only allowed as the sole value");
            return Result<std::vector<std::string>>::failure(
                "managed: wildcard only allowed as the sole value '*'");
        }
        out.push_back(p);
    }
    return Result<std::vector<std::string>>(std::move(out));
}

} // namespace s3mm::s3mmc
