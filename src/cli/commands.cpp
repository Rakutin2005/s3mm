#include "s3mm/cli/commands.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>

#include "s3mm/cli/client.hpp"
#include "s3mm/common/error.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/registry/mutate.hpp"
#include "s3mm/registry/registry.hpp"

namespace s3mm::cli {

namespace {

// ------------------------------------------------------------------ args ----

/// True when the operand is a `key=value` configuration field (and not rule
/// text such as `source.size >= 1M => accept`, which contains '=' too).
bool isFieldToken(const std::string& s) {
    if (s.find("=>") != std::string::npos) return false;
    auto eq = s.find('=');
    if (eq == std::string::npos || eq == 0 || eq + 1 == s.size()) return false;
    const char first = s[0];
    if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_'))
        return false;
    for (size_t i = 0; i < eq; ++i) {
        const char c = s[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

struct Args {
    std::vector<std::string> positional;
    std::map<std::string, std::string> opt; // long name → value ("" → flag)
    std::vector<std::string> fields;        // key=value operands
};

/// allowFields: `key=value` operands become fields (add/edit only).
/// lenient: unknown `--options` stay positional (rule text may look like them).
Args parseArgs(const std::vector<std::string>& in, bool allowFields, bool lenient = false) {
    static const std::vector<std::string> kValueOpts = {"replica", "cluster", "policy",
                                                        "before",  "after",  "limit", "ref"};
    static const std::vector<std::string> kFlagOpts = {"apply", "prune", "async", "force"};
    Args a;
    for (size_t i = 0; i < in.size(); ++i) {
        const std::string s = in[i]; // copy: i may advance below
        auto valueOf = [&](const std::string& name) -> std::string {
            if (i + 1 >= in.size()) throw UsageError("--" + name + " requires a value");
            return in[++i];
        };
        if (s == "-b") { a.opt["before"] = valueOf("before"); continue; }
        if (s == "-A") { a.opt["after"] = valueOf("after"); continue; }
        if (s.rfind("--", 0) == 0) {
            std::string body = s.substr(2);
            std::string name = body, val;
            bool inlineVal = false;
            auto eq = body.find('=');
            if (eq != std::string::npos) {
                name = body.substr(0, eq);
                val = body.substr(eq + 1);
                inlineVal = true;
            }
            if (std::find(kValueOpts.begin(), kValueOpts.end(), name) != kValueOpts.end()) {
                a.opt[name] = inlineVal ? val : valueOf(name);
            } else if (std::find(kFlagOpts.begin(), kFlagOpts.end(), name) != kFlagOpts.end()) {
                if (inlineVal) throw UsageError("--" + name + " takes no value");
                a.opt[name] = "true";
            } else if (lenient) {
                a.positional.push_back(s);
            } else {
                throw UsageError("unknown option '" + s + "'");
            }
            continue;
        }
        if (allowFields && isFieldToken(s)) a.fields.push_back(s);
        else a.positional.push_back(s);
    }
    return a;
}

std::string optStr(const Args& a, const std::string& k, const std::string& def = {}) {
    auto it = a.opt.find(k);
    return it != a.opt.end() ? it->second : def;
}

bool optFlag(const Args& a, const std::string& k) {
    auto it = a.opt.find(k);
    return it != a.opt.end() && !it->second.empty() && it->second != "false";
}

int64_t optInt(const Args& a, const std::string& k, int64_t def) {
    auto it = a.opt.find(k);
    if (it == a.opt.end()) return def;
    auto n = str::parseInt64(it->second);
    if (!n) throw UsageError("--" + k + ": expected a number, got '" + it->second + "'");
    return *n;
}

std::string joinFrom(const std::vector<std::string>& v, size_t from) {
    std::string out;
    for (size_t i = from; i < v.size(); ++i) {
        if (!out.empty()) out += ' ';
        out += v[i];
    }
    return out;
}

// --------------------------------------------------------------- requests ----

Value buildRequest(const std::string& cmd, const std::vector<std::string>& rest);

/// Commands that only need the replica selector (+ a few flags).
Value simpleRequest(const std::string& cmd, const std::vector<std::string>& rest) {
    Args a = parseArgs(rest, false);
    if (a.positional.size() > 1)
        throw UsageError(cmd + ": unexpected argument '" + a.positional[1] + "'");
    Value req = Value::object();
    req.set("cmd", Value::str(cmd));
    const std::string rep = !a.positional.empty() ? a.positional[0] : optStr(a, "replica");
    if (!rep.empty()) req.set("replication", Value::str(rep));
    if (cmd == "routes" && a.opt.count("limit"))
        req.set("limit", Value::number(optInt(a, "limit", 50)));
    if (cmd == "scan") {
        if (optFlag(a, "async")) req.set("async", Value::boolean(true));
        if (optFlag(a, "force")) req.set("force", Value::boolean(true));
    }
    return req;
}

Value buildRequest(const std::string& cmd, const std::vector<std::string>& rest) {
    // ---- aliases that expand to base commands -----------------------------

    if (cmd == "replication") {
        if (rest.empty())
            throw UsageError(
                "replication: <subcommand> required "
                "(list|show|period|queue|route|scan|flush)");
        const std::string sub = rest[0];
        std::vector<std::string> tail(rest.begin() + 1, rest.end());
        if (sub == "list") return buildRequest("list", {"replication"});
        if (sub == "show") {
            if (tail.empty()) throw UsageError("replication show: <name> required");
            if (tail.size() > 1) throw UsageError("replication show: too many arguments");
            return buildRequest("show", {"replication", tail[0]});
        }
        if (sub == "period") {
            if (tail.size() < 2)
                throw UsageError("replication period: <name> <duration> required (e.g. 10m)");
            Value req = buildRequest("edit", {"replication", tail[0]});
            Value fields = Value::object();
            fields.set("queue_time", Value::str(tail[1]));
            req.set("fields", fields);
            return req;
        }
        if (sub == "queue") return buildRequest("queues", tail);
        if (sub == "route") return buildRequest("routes", tail);
        if (sub == "scan") return buildRequest("scan", tail);
        if (sub == "flush") return buildRequest("flush", tail);
        throw UsageError("replication: unknown subcommand '" + sub + "'");
    }
    if (cmd == "policy") {
        if (rest.empty())
            throw UsageError("policy: <subcommand> required (list|show|add|edit|rm)");
        std::string sub = rest[0];
        if (sub == "ls") sub = "list";
        if (sub == "remove") sub = "rm";
        if (sub != "list" && sub != "show" && sub != "add" && sub != "edit" && sub != "rm")
            throw UsageError("policy: unknown subcommand '" + rest[0] + "'");
        std::vector<std::string> tail(rest.begin() + 1, rest.end());
        std::vector<std::string> args;
        args.push_back("policy"); // kind
        args.insert(args.end(), tail.begin(), tail.end());
        return buildRequest(sub, args);
    }

    // ---- daemon-only one-shot commands ------------------------------------
    if (cmd == "ping" || cmd == "status" || cmd == "modules" || cmd == "reload" ||
        cmd == "flush-config") {
        if (!rest.empty()) throw UsageError(cmd + ": no arguments accepted");
        Value req = Value::object();
        req.set("cmd", Value::str(cmd));
        return req;
    }

    // ---- operational commands ---------------------------------------------
    if (cmd == "stat" || cmd == "queues" || cmd == "routes" || cmd == "scan" ||
        cmd == "flush" || cmd == "rescan" || cmd == "reset-stats") {
        return simpleRequest(cmd, rest);
    }

    if (cmd == "sync-accounts") {
        Args a = parseArgs(rest, false);
        if (a.positional.empty()) throw UsageError("sync-accounts: <replication> required");
        if (a.positional.size() > 1) throw UsageError("sync-accounts: too many arguments");
        Value req = Value::object();
        req.set("cmd", Value::str(cmd));
        req.set("replication", Value::str(a.positional[0]));
        req.set("dry_run", Value::boolean(!optFlag(a, "apply")));
        if (optFlag(a, "prune")) req.set("prune", Value::boolean(true));
        return req;
    }

    if (cmd == "peer") {
        throw UsageError(
            "peer: clustering is handled by the separate s3mmc cluster client — "
            "configure peers in s3mmc.conf and manage them with the s3mmc binary");
    }

    // ---- registry reads ----------------------------------------------------
    if (cmd == "list") {
        Args a = parseArgs(rest, false);
        if (a.positional.empty())
            throw UsageError(
                "list: <kind> required "
                "(cluster|credential|replication|target|policy|rule|settings)");
        const std::string kind = registry::normKind(a.positional[0]);
        if (a.positional.size() > 2)
            throw UsageError("list: unexpected argument '" + a.positional[2] + "'");
        Value req = Value::object();
        req.set("cmd", Value::str("list"));
        req.set("kind", Value::str(kind));
        std::string policy = optStr(a, "policy");
        if (policy.empty() && a.positional.size() == 2) policy = a.positional[1];
        if (kind == "rule" && policy.empty())
            throw UsageError("list rule: <policy> name required");
        if (!policy.empty()) {
            if (kind != "rule") throw UsageError("list: unexpected argument '" + policy + "'");
            req.set("policy", Value::str(policy));
        }
        return req;
    }
    if (cmd == "show") {
        Args a = parseArgs(rest, false);
        if (a.positional.empty())
            throw UsageError("show: <kind> required (cluster|credential|replication|target|policy|rule|settings)");
        if (a.positional.size() > 2)
            throw UsageError("show: unexpected argument '" + a.positional[2] + "'");
        const std::string kind = registry::normKind(a.positional[0]);
        Value req = Value::object();
        req.set("cmd", Value::str("show"));
        req.set("kind", Value::str(kind));
        std::string name = a.positional.size() > 1 ? a.positional[1] : optStr(a, "policy");
        if (kind == "rule") {
            if (name.empty()) throw UsageError("show rule: <policy> name required");
            req.set("policy", Value::str(name));
        } else if (!name.empty()) {
            req.set("name", Value::str(name));
        }
        return req;
    }

    // ---- registry mutations -------------------------------------------------
    if (cmd == "add" || cmd == "edit" || cmd == "rm") {
        Args a = parseArgs(rest, cmd != "rm");
        if (a.positional.empty())
            throw UsageError(cmd + ": <kind> required");
        if (a.positional.size() > 2)
            throw UsageError(cmd + ": unexpected argument '" + a.positional[2] + "'");
        Value req = Value::object();
        req.set("cmd", Value::str(cmd));
        req.set("kind", Value::str(registry::normKind(a.positional[0])));
        if (a.positional.size() == 2) req.set("name", Value::str(a.positional[1]));
        if (!a.fields.empty()) req.set("fields", registry::parseFields(a.fields));
        return req;
    }

    // ---- rules --------------------------------------------------------------
    if (cmd == "rule") {
        if (rest.empty())
            throw UsageError("rule: <action> required (list|add|edit|rm)");
        std::string action = rest[0];
        if (action == "ls") action = "list";
        if (action == "remove") action = "rm";
        if (action != "list" && action != "add" && action != "edit" && action != "rm")
            throw UsageError("rule: unknown action '" + rest[0] + "'");
        Args a = parseArgs(std::vector<std::string>(rest.begin() + 1, rest.end()), false, true);
        if (a.positional.empty()) throw UsageError("rule " + action + ": <policy> required");

        Value req = Value::object();
        req.set("cmd", Value::str("rule"));
        req.set("action", Value::str(action));
        req.set("policy", Value::str(a.positional[0]));

        if (action == "list") {
            if (a.positional.size() > 1)
                throw UsageError("rule list: unexpected argument '" + a.positional[1] + "'");
            return req;
        }
        if (action == "add") {
            if (a.positional.size() < 2)
                throw UsageError("rule add: <rule text> required (see 's3mm --help' for the format)");
            req.set("line", Value::str(joinFrom(a.positional, 1)));
            if (a.opt.count("before")) req.set("before", Value::str(optStr(a, "before")));
            if (a.opt.count("after")) req.set("after", Value::str(optStr(a, "after")));
            return req;
        }
        if (action == "edit") {
            if (a.positional.size() < 3)
                throw UsageError("rule edit: <ref> and <rule text> required");
            req.set("ref", Value::str(a.positional[1]));
            req.set("line", Value::str(joinFrom(a.positional, 2)));
            return req;
        }
        // rm
        if (a.positional.size() != 2)
            throw UsageError("rule rm: usage: s3mm rule rm <policy> <ref>");
        req.set("ref", Value::str(a.positional[1]));
        return req;
    }

    throw UsageError("unknown command '" + cmd + "'; try 's3mm --help'");
}

// ---------------------------------------------------------------- offline ----

/// Apply a configuration mutation directly to the files (daemon unreachable).
/// This is the moral equivalent of --permanent: the change is always written.
int runOffline(const Options& opts, const std::string& cmd, const Value& req) {
    std::cerr << "s3mm: note: daemon not reachable, applying '" << cmd
              << "' directly to " << opts.config << "\n";

    auto cfg = config::Config::load(opts.config);
    if (!cfg) throw Error("cannot load configuration: " + cfg.error());
    auto regRes = registry::Registry::fromConfig(cfg.value());
    if (!regRes) throw Error("configuration error: " + regRes.error());
    registry::Registry reg = std::move(regRes.value());

    const Value& fields = registry::fieldsOf(req);
    Value out;
    bool changed = true;
    if (cmd == "rule") {
        const std::string action = req.getString("action", "list");
        changed = action != "list";
        out = registry::applyRule(reg, action, req.getString("policy"), req.getString("ref"),
                                  req.getString("line"), req.getString("before"),
                                  req.getString("after"));
    } else {
        out = registry::mutateEntity(reg, cmd, req.getString("kind"), req.getString("name"),
                                     fields);
    }

    if (changed) {
        const unsigned mode = fs::permissions(opts.config).value_or(0640);
        if (!fs::writeFileAtomic(opts.config, reg.dump()))
            throw Error("cannot write " + opts.config);
        fs::setPermissions(opts.config, mode);
    }
    std::cout << render(out, opts.format);
    return 0;
}

// ---------------------------------------------------------------- validate ---

int runValidate(const Options& opts) {
    Value out = Value::object();
    out.set("path", Value::str(opts.config));
    std::vector<std::string> problems;

    if (auto cfg = config::Config::load(opts.config)) {
        for (auto& p : cfg.value().validate()) problems.push_back(std::move(p));
        if (problems.empty()) {
            if (auto reg = registry::Registry::fromConfig(cfg.value())) {
                // semantically consistent
            } else {
                problems.push_back(reg.error());
            }
        }
    } else {
        problems.push_back(cfg.error());
    }

    Value arr = Value::array();
    for (const auto& p : problems) arr.push(Value::str(p));
    out.set("valid", Value::boolean(problems.empty()));
    out.set("problems", arr);
    std::cout << render(out, opts.format);
    return problems.empty() ? 0 : 1;
}

// ----------------------------------------------------------------- socket ----

std::string resolveSocket(const Options& opts) {
    if (!opts.socket.empty()) return opts.socket;
    if (const char* env = std::getenv("S3MM_SOCKET"); env && *env) return env;
    if (auto cfg = config::Config::load(opts.config))
        if (auto reg = registry::Registry::fromConfig(cfg.value()))
            return reg.value().settings().socket;
    return "/run/s3mm/s3mm.sock";
}

} // namespace

// ------------------------------------------------------------------ usage ----

std::string usage() {
    return
R"(Usage: s3mm [options] <command> [args]

Manage s3mm replications. When the daemon is not running, configuration
commands (add/edit/rm/rule) are applied directly to the configuration files.

Commands:
  status                          daemon status
  ping                            check that the daemon answers
  modules                         list the loaded vendor modules
  list <kind> [policy]            list cluster|credential|replication|target|
                                      policy|rule|settings
  show <kind> <name>              show one object
  add <kind> <name> [key=value]   add an object
  edit <kind> <name> [key=value]  change an object
  rm <kind> <name>                remove an object

  rule list <policy>              list the rules of a policy
  rule add <policy> <rule>        add a rule (--before/--after <ref> place it)
  rule edit <policy> <ref> <rule> replace a rule by name or number
  rule rm <policy> <ref>          remove a rule

  policy list|show|add|edit|rm    shorthand for list/show/add/edit/rm kind=policy
  replication list|show           list/show replications
  replication period <name> <dur> set the batching period (e.g. 10m)
  replication queue|route [name]  alias for queues/routes
  replication scan|flush [name]   alias for scan/flush

  stat [replica]                  replication counters
  queues [replica]                queue depths
  routes [replica] [--limit N]    recent routing decisions
  scan [replica] [--async|--force] run a scan now
  flush [replica]                 ship the pending queue now
  sync-accounts <replication> [--apply] [--prune]
                                  account delta (dry-run unless --apply)
  rescan [replica]                drop the delta cache; the next scan is full
  reset-stats [replica]           zero the counters
  reload                          reload the configuration inside the daemon
  validate                        check the configuration files (-t does this)
  flush-config                    write daemon state back to the config files

Options:
  -c, --config <file>     configuration file (default /etc/s3mm/s3mm.conf)
  -s, --socket <path>     control socket (default: $S3MM_SOCKET, then the
                          socket setting of the configuration, then
                          /run/s3mm/s3mm.sock)
  -o, --output <format>   table | json | yaml (default: table)
      --permanent         write changes back to the configuration files
                          (always on when the daemon setting permanent is on)
  -t, --test              validate the configuration and exit
  -h, --help              this help
  -V, --version           print the version

Rule syntax:
  [order] [name=<rule>] [acl|bucket|object] <condition> action <actions...>
  Example: 100 name=big object source.size >= 1M action accept log

Examples:
  s3mm status
  s3mm add cluster minio1 addr=http://minio:9000 credentials=admin1
  s3mm add replication photos source=minio1 destination=aws1 buckets='media*'
  s3mm rule add default "100 object source.size >= 1M action accept" --before 5
  s3mm -o json stat photos
  s3mm --permanent edit settings queue_time=10m
)";
}

// ------------------------------------------------------------------- run ----

int runCommand(const Options& opts, const std::vector<std::string>& args) {
    if (opts.test) return runValidate(opts);
    if (args.empty()) throw UsageError("no command given; try 's3mm --help'");
    const std::string cmd = args[0];
    const std::vector<std::string> rest(args.begin() + 1, args.end());

    if (cmd == "help") {
        std::cout << usage();
        return 0;
    }
    if (cmd == "validate") return runValidate(opts);

    // Build the request first: usage errors must not touch the socket.
    Value req = buildRequest(cmd, rest);
    const std::string effectiveCmd = req.getString("cmd", cmd);

    const bool offlineCapable = effectiveCmd == "add" || effectiveCmd == "edit" ||
                                effectiveCmd == "rm" || effectiveCmd == "rule";
    if (offlineCapable && opts.permanent) req.set("permanent", Value::boolean(true));

    const std::string socket = resolveSocket(opts);
    try {
        Client client(socket);
        Value data = client.call(req);
        std::cout << render(data, opts.format);
        return 0;
    } catch (const ConnectionError&) {
        if (!offlineCapable)
            throw Error("cannot connect to " + socket +
                        " (is s3mmd running?); use -s <socket> to override");
        return runOffline(opts, effectiveCmd, req);
    }
}

} // namespace s3mm::cli
