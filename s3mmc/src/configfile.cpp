// s3mmc.conf — see configfile.hpp for the grammar. Applies parsed settings to
// a not-yet-started ClusterClient (options, TLS material, peers).
#include "configfile.hpp"

#include <unistd.h>

#include <cstdlib>
#include <exception>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/units.hpp"
#include "s3mm/config/config.hpp"

namespace s3mm::s3mmc {

namespace {

std::string firstNonEmpty(const std::vector<const config::Node*>& nodes,
                          const std::string& directive) {
    for (const auto* n : nodes) {
        std::string v = n->value(directive);
        if (!v.empty()) return v;
    }
    return {};
}

bool parseListen(const std::string& spec, std::string* address, int* port, std::string* error) {
    auto colon = spec.rfind(':');
    if (colon == std::string::npos) {
        *error = "listen: expected address:port, got '" + spec + "'";
        return false;
    }
    *address = spec.substr(0, colon);
    if (*address == "*" || *address == "any") *address = "0.0.0.0";
    std::string p = spec.substr(colon + 1);
    if (p.empty()) {
        *error = "listen: missing port";
        return false;
    }
    *port = std::atoi(p.c_str());
    return true;
}

} // namespace

Result<void> applyConfigText(ClusterClient& client, const std::string& text,
                             const std::string& filename) {
    auto cfgR = config::Config::parse(text, filename);
    if (!cfgR) return Result<void>::failure(cfgR.error());
    const config::Config& cfg = cfgR.value();

    // Candidate scopes: an optional "s3mmc"/"s3mm" wrapper block plus any
    // top-level fragments (from includes).
    std::vector<const config::Node*> scopes;
    for (const auto& root : cfg.roots())
        if (root.name == "s3mmc" || root.name == "s3mm") scopes.push_back(&root);
    for (const auto& root : cfg.roots())
        if (root.name != "s3mmc" && root.name != "s3mm") scopes.push_back(&root);
    if (scopes.empty()) return Result<void>::failure("empty configuration");

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
        if (!ml) return Result<void>::failure(ml.error());
        opts.managedNodes = ml.value();
    }
    if (auto v = firstNonEmpty(scopes, "expose_credentials"); !v.empty()) {
        if (v == "on" || v == "true" || v == "yes" || v == "1")
            opts.exposeCredentials = true;
        else if (v == "off" || v == "false" || v == "no" || v == "0")
            opts.exposeCredentials = false;
        else
            return Result<void>::failure("expose_credentials must be on|off, got '" + v + "'");
    }
    if (auto v = firstNonEmpty(scopes, "inventory"); !v.empty()) {
        if (v != "push" && v != "pull" && v != "both")
            return Result<void>::failure("inventory model must be push|pull|both, got '" + v + "'");
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
        return Result<void>::failure(std::string("bad interval value: ") + e.what());
    }
    if (opts.nodeId.empty()) {
        char host[256];
        if (::gethostname(host, sizeof host) == 0) opts.nodeId = host;
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
    }

    // ---- peer blocks -------------------------------------------------------------
    std::vector<PeerConfig> peers;
    for (const auto* sc : scopes) {
        for (const config::Node* p : sc->findAll("peer")) {
            if (!p->hasArg(0)) return Result<void>::failure("peer block requires an id");
            PeerConfig pc;
            pc.id = p->arg(0);
            pc.address = p->value("address");
            if (pc.address.empty())
                return Result<void>::failure("peer '" + pc.id + "': address required");
            pc.dial = p->boolValue("connect", true);
            if (auto v = p->value("connect_timeout"); !v.empty()) {
                try {
                    pc.connectTimeoutSec = (int)units::parseDurationSeconds(v);
                } catch (const std::exception& e) {
                    return Result<void>::failure("peer '" + pc.id + "' connect_timeout: " + e.what());
                }
            }
            peers.push_back(pc);
        }
    }

    // ---- apply -------------------------------------------------------------------
    auto cr = client.configure(opts, tls);
    if (!cr) return cr;
    if (!peers.empty()) {
        auto pr = client.setPeers(std::move(peers));
        if (!pr) return pr;
    }
    return Result<void>::success();
}

Result<void> applyConfigFile(ClusterClient& client, const std::string& path) {
    auto cfgR = config::Config::load(path);
    if (!cfgR) return Result<void>::failure(cfgR.error());
    return applyConfigText(client, cfgR.value().dump(), path);
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
        if (p == "*") return Result<std::vector<std::string>>::success(std::vector<std::string>{"*"});
        if (p == "none" || p == "off") continue;  // explicit none => empty list
        // Reject accidental wildcards inside the list to keep semantics sharp.
        if (p.find('*') != std::string::npos)
            return Result<std::vector<std::string>>::failure(
                "managed: wildcard only allowed as the sole value '*'");
        out.push_back(p);
    }
    return Result<std::vector<std::string>>::success(std::move(out));
}

} // namespace s3mm::s3mmc
