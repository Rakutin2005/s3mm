// `s3mm s3 ...` and `s3mm check ...`: a small S3 client working directly
// against the clusters of the configuration (the control socket has no data
// plane commands), plus cluster availability checks.
#include "s3mm/cli/s3cmd.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <iostream>
#include <memory>
#include <sys/stat.h>

#include "s3mm/cli/client.hpp"
#include "s3mm/common/error.hpp"
#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/common/time.hpp"
#include "s3mm/common/units.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/module/loader.hpp"
#include "s3mm/registry/registry.hpp"
#include "s3mm/replication/probe.hpp"
#include "s3mm/s3/client.hpp"

namespace s3mm::cli {

namespace {

constexpr uint64_t kChunk = 8ull * 1024 * 1024;

struct S3Args {
    std::vector<std::string> positional;
    std::map<std::string, std::string> opts; // --name[=value]
};

S3Args parseS3Args(const std::vector<std::string>& in) {
    S3Args a;
    for (size_t i = 0; i < in.size(); ++i) {
        const std::string& s = in[i];
        if (s.rfind("--", 0) == 0 && s.size() > 2) {
            auto eq = s.find('=');
            std::string k = s.substr(2, eq == std::string::npos ? std::string::npos : eq - 2);
            if (eq != std::string::npos) a.opts[k] = s.substr(eq + 1);
            else if ((k == "content-type" || k == "limit") && i + 1 < in.size()) a.opts[k] = in[++i];
            else a.opts[k] = "";
        } else if (s == "-r") {
            a.opts["recursive"] = "";
        } else {
            a.positional.push_back(s);
        }
    }
    return a;
}

/// Configuration loaded the way s3mmd loads it, plus the vendor modules.
struct Environment {
    std::unique_ptr<registry::Registry> registry;
    module::Loader loader;
};

std::unique_ptr<Environment> loadEnvironment(const Options& opts) {
    auto env = std::make_unique<Environment>();
    LOG_DEBUG("s3: loading configuration ", opts.config);
    auto cfg = config::Config::load(opts.config);
    if (!cfg) throw Error("cannot load " + opts.config + ": " + cfg.error());
    auto reg = registry::Registry::fromConfig(cfg.value());
    if (!reg) throw Error(opts.config + ": " + reg.error());
    env->registry = std::make_unique<registry::Registry>(std::move(reg.value()));
    const std::string& dir = env->registry->settings().modulesDir;
    auto loaded = dir.empty() ? env->loader.loadDefaults() : env->loader.loadDir(dir);
    if (!loaded) LOG_WARN("s3: vendor modules not loaded (", loaded.error(), "), using generic S3 options");
    return env;
}

const registry::Cluster& findCluster(const Environment& env, const std::string& name) {
    const registry::Cluster* c = env.registry->cluster(name);
    if (!c) throw UsageError("no cluster '" + name + "' in the configuration");
    return *c;
}

std::unique_ptr<s3::Client> clientFor(const Environment& env, const registry::Cluster& c) {
    const registry::Credential* cred = env.registry->bestCredential(c);
    if (!cred) throw Error("cluster '" + c.name + "' has no usable credential");
    s3::ClientOptions o;
    o.endpoints = c.endpoints;
    o.pathStyle = c.pathStyle;
    o.insecure = c.insecure;
    o.timeoutSec = c.timeoutSec;
    o.connectTimeoutSec = c.connectTimeoutSec;
    o.rateLimitPerSec = c.rateLimitPerSec;
    o.maxRetries = c.retries;
    if (module::IModule* mod = env.loader.find(c.vendor)) mod->adjustClientOptions(o);
    LOG_INFO("s3: using cluster '", c.name, "' (", str::join(o.endpoints, ","), ") as ", cred->accessKey);
    return std::make_unique<s3::Client>(o, sigv4::Credentials{cred->accessKey, cred->secretKey, cred->sessionToken,
                                                              cred->region});
}

/// "bucket/key/with/slashes" -> {bucket, key}
std::pair<std::string, std::string> splitPath(const std::string& path) {
    std::string p = path;
    if (p.rfind("s3://", 0) == 0) p = p.substr(5);
    auto slash = p.find('/');
    if (slash == std::string::npos) return {p, ""};
    return {p.substr(0, slash), p.substr(slash + 1)};
}

std::pair<std::string, std::string> objectPath(const std::string& path, const std::string& what) {
    auto [bucket, key] = splitPath(path);
    if (bucket.empty() || key.empty()) throw UsageError(what + ": <bucket>/<key> required, got '" + path + "'");
    return {bucket, key};
}

template <class T> T check(Result<T> r, const std::string& what) {
    if (!r) {
        LOG_ERROR("s3: ", what, " failed: ", r.error());
        throw Error(what + ": " + r.error());
    }
    return std::move(r.value());
}

void check(Result<void> r, const std::string& what) {
    if (!r) {
        LOG_ERROR("s3: ", what, " failed: ", r.error());
        throw Error(what + ": " + r.error());
    }
}

void need(const S3Args& a, size_t n, const std::string& usage) {
    if (a.positional.size() < n) throw UsageError("usage: s3mm s3 " + usage);
}

// -------------------------------------------------------------- commands ----

int cmdLs(const Environment& env, const S3Args& a, Format f) {
    need(a, 2, "ls <cluster> [<bucket>[/<prefix>]] [-r]");
    auto client = clientFor(env, findCluster(env, a.positional[1]));
    if (a.positional.size() < 3) {
        auto buckets = check(client->listBuckets(), "list buckets");
        Value arr = Value::array();
        for (const auto& b : buckets) {
            Value v = Value::object();
            v.set("bucket", Value::str(b.name));
            v.set("created", Value::str(tm::toIso8601(b.created)));
            arr.push(v);
        }
        std::cout << render(arr, f);
        return 0;
    }
    auto [bucket, prefix] = splitPath(a.positional[2]);
    const bool recursive = a.opts.count("recursive");
    int64_t limit = a.opts.count("limit") ? str::parseInt64(a.opts.at("limit")).value_or(0) : 0;
    Value arr = Value::array();
    std::string token;
    int64_t shown = 0;
    do {
        auto page = check(client->listObjects(bucket, prefix, recursive ? "" : "/", token), "list " + bucket);
        for (const auto& p : page.commonPrefixes) {
            Value v = Value::object();
            v.set("key", Value::str(p));
            v.set("size", Value::str("DIR"));
            v.set("last_modified", Value::str(""));
            v.set("etag", Value::str(""));
            arr.push(v);
        }
        for (const auto& o : page.objects) {
            Value v = Value::object();
            v.set("key", Value::str(o.key));
            v.set("size", Value::str(units::formatSize(o.size)));
            v.set("last_modified", Value::str(tm::toIso8601(o.lastModified)));
            v.set("etag", Value::str(o.etag));
            arr.push(v);
            if (limit > 0 && ++shown >= limit) break;
        }
        token = page.truncated ? page.nextToken : "";
    } while (!token.empty() && !(limit > 0 && shown >= limit));
    std::cout << render(arr, f);
    return 0;
}

int cmdStat(const Environment& env, const S3Args& a, Format f) {
    need(a, 3, "stat <cluster> <bucket>/<key>");
    auto client = clientFor(env, findCluster(env, a.positional[1]));
    auto [bucket, key] = objectPath(a.positional[2], "stat");
    auto meta = check(client->headObject(bucket, key), "stat " + bucket + "/" + key);
    if (!meta.exists) throw Error("stat: " + bucket + "/" + key + " does not exist");
    Value v = Value::object();
    v.set("bucket", Value::str(bucket));
    v.set("key", Value::str(key));
    v.set("size", Value::number((int64_t)meta.size));
    v.set("etag", Value::str(meta.etag));
    v.set("last_modified", Value::str(tm::toIso8601(meta.lastModified)));
    v.set("content_type", Value::str(meta.contentType));
    v.set("storage_class", Value::str(meta.storageClass));
    v.set("version_id", Value::str(meta.versionId));
    Value um = Value::object();
    for (const auto& [k, val] : meta.userMeta) um.set(k, Value::str(val));
    v.set("user_meta", um);
    std::cout << render(v, f);
    return 0;
}

int cmdGet(const Environment& env, const S3Args& a) {
    need(a, 3, "get <cluster> <bucket>/<key> [<file>|-]");
    auto client = clientFor(env, findCluster(env, a.positional[1]));
    auto [bucket, key] = objectPath(a.positional[2], "get");
    std::string target = a.positional.size() > 3 ? a.positional[3] : fs::basename(key);
    auto meta = check(client->headObject(bucket, key), "head " + bucket + "/" + key);
    if (!meta.exists) throw Error("get: " + bucket + "/" + key + " does not exist");
    const bool toStdout = target == "-";
    std::string tmp = toStdout ? std::string() : target + ".s3mm-part";
    std::FILE* out = toStdout ? stdout : std::fopen(tmp.c_str(), "wb");
    if (!out) throw Error("get: cannot open " + tmp + ": " + std::strerror(errno));
    log::Stopwatch sw;
    LOG_INFO("s3: downloading ", bucket, "/", key, " (", meta.size, " B) to ", toStdout ? "stdout" : target);
    for (uint64_t off = 0; off < meta.size; off += kChunk) {
        uint64_t len = std::min<uint64_t>(kChunk, meta.size - off);
        auto chunk = client->getObjectRange(bucket, key, off, len);
        if (!chunk || std::fwrite(chunk.value().data(), 1, chunk.value().size(), out) != chunk.value().size()) {
            std::string err = chunk ? std::string(std::strerror(errno)) : chunk.error();
            if (!toStdout) {
                std::fclose(out);
                std::remove(tmp.c_str());
            }
            LOG_ERROR("s3: download of ", bucket, "/", key, " failed at offset ", off, ": ", err);
            throw Error("get: " + err);
        }
    }
    if (toStdout) {
        std::fflush(stdout);
    } else {
        if (std::fclose(out) != 0 || std::rename(tmp.c_str(), target.c_str()) != 0) {
            std::string err = std::strerror(errno);
            std::remove(tmp.c_str());
            throw Error("get: cannot write " + target + ": " + err);
        }
        std::cerr << "downloaded " << bucket << "/" << key << " -> " << target << " ("
                  << units::formatSize(meta.size) << ")\n";
    }
    LOG_INFO("s3: downloaded ", bucket, "/", key, " (", meta.size, " B) in ", sw.ms(), " ms");
    return 0;
}

int cmdPut(const Environment& env, const S3Args& a) {
    need(a, 4, "put <cluster> <file> <bucket>/<key> [--content-type <type>]");
    const registry::Cluster& c = findCluster(env, a.positional[1]);
    auto client = clientFor(env, c);
    const std::string file = a.positional[2];
    auto [bucket, key] = splitPath(a.positional[3]);
    if (bucket.empty()) throw UsageError("put: <bucket>[/<key>] required");
    if (key.empty() || key.back() == '/') key += fs::basename(file);
    struct stat st {};
    if (::stat(file.c_str(), &st) != 0) throw Error("put: " + file + ": " + std::strerror(errno));
    s3::ObjectMeta meta;
    meta.contentType = a.opts.count("content-type") ? a.opts.at("content-type") : "application/octet-stream";
    log::Stopwatch sw;
    LOG_INFO("s3: uploading ", file, " (", (uint64_t)st.st_size, " B) to ", c.name, ":", bucket, "/", key);
    if ((uint64_t)st.st_size > c.partSize)
        check(client->uploadMultipartFromFile(bucket, key, file, c.partSize, meta), "put " + bucket + "/" + key);
    else
        check(client->putObjectFromFile(bucket, key, file, meta), "put " + bucket + "/" + key);
    LOG_INFO("s3: uploaded ", bucket, "/", key, " in ", sw.ms(), " ms");
    std::cerr << "uploaded " << file << " -> " << bucket << "/" << key << " ("
              << units::formatSize((uint64_t)st.st_size) << ")\n";
    return 0;
}

int cmdRm(const Environment& env, const S3Args& a) {
    need(a, 3, "rm <cluster> <bucket>/<key>");
    auto client = clientFor(env, findCluster(env, a.positional[1]));
    auto [bucket, key] = objectPath(a.positional[2], "rm");
    check(client->deleteObject(bucket, key), "rm " + bucket + "/" + key);
    LOG_INFO("s3: deleted ", bucket, "/", key);
    std::cerr << "deleted " << bucket << "/" << key << "\n";
    return 0;
}

int cmdMb(const Environment& env, const S3Args& a) {
    need(a, 3, "mb <cluster> <bucket>");
    const registry::Cluster& c = findCluster(env, a.positional[1]);
    auto client = clientFor(env, c);
    check(client->createBucket(a.positional[2], c.location), "create bucket " + a.positional[2]);
    LOG_INFO("s3: created bucket ", a.positional[2], " on ", c.name);
    std::cerr << "created bucket " << a.positional[2] << "\n";
    return 0;
}

int cmdRb(const Environment& env, const S3Args& a) {
    need(a, 3, "rb <cluster> <bucket> [--force]");
    auto client = clientFor(env, findCluster(env, a.positional[1]));
    const std::string bucket = a.positional[2];
    if (a.opts.count("force")) {
        int64_t removed = 0;
        LOG_WARN("s3: rb --force: deleting every object of ", bucket);
        check(client->forEachObject(bucket, "",
                                    [&](const s3::ObjectInfo& o) -> Result<void> {
                                        auto r = client->deleteObject(bucket, o.key);
                                        if (r) ++removed;
                                        return r;
                                    }),
              "empty bucket " + bucket);
        std::cerr << "deleted " << removed << " object(s) from " << bucket << "\n";
    }
    check(client->deleteBucket(bucket), "delete bucket " + bucket);
    LOG_INFO("s3: deleted bucket ", bucket);
    std::cerr << "deleted bucket " << bucket << "\n";
    return 0;
}

/// Availability plus content: bucket list with object counts and sizes.
int cmdInfo(const Environment& env, const S3Args& a, Format f) {
    need(a, 2, "info <cluster> [--no-count]");
    const registry::Cluster& c = findCluster(env, a.positional[1]);
    auto probe = repl::probeCluster(*env.registry, c, &env.loader);
    Value out = probe.toValue();
    if (probe.available()) {
        auto client = clientFor(env, c);
        auto buckets = check(client->listBuckets(), "list buckets");
        Value arr = Value::array();
        int64_t totalObjects = 0, totalBytes = 0;
        for (const auto& b : buckets) {
            Value v = Value::object();
            v.set("bucket", Value::str(b.name));
            if (!a.opts.count("no-count")) {
                int64_t n = 0, bytes = 0;
                auto r = client->forEachObject(b.name, "", [&](const s3::ObjectInfo& o) -> Result<void> {
                    ++n;
                    bytes += (int64_t)o.size;
                    return Result<void>::success();
                });
                v.set("objects", r ? Value::number(n) : Value::str("error: " + r.error()));
                v.set("size", Value::str(units::formatSize((uint64_t)bytes)));
                totalObjects += n;
                totalBytes += bytes;
            }
            arr.push(v);
        }
        out.set("bucket_list", arr);
        if (!a.opts.count("no-count")) {
            out.set("total_objects", Value::number(totalObjects));
            out.set("total_size", Value::str(units::formatSize((uint64_t)totalBytes)));
        }
    }
    std::cout << render(out, f);
    return probe.available() ? 0 : 1;
}

} // namespace

int runS3(const Options& opts, const std::vector<std::string>& rest) {
    S3Args a = parseS3Args(rest);
    if (a.positional.empty())
        throw UsageError("s3: subcommand required (ls|stat|get|put|rm|mb|rb|info); try 's3mm help'");
    const std::string sub = a.positional[0];
    auto env = loadEnvironment(opts);
    if (sub == "ls") return cmdLs(*env, a, opts.format);
    if (sub == "stat" || sub == "head") return cmdStat(*env, a, opts.format);
    if (sub == "get" || sub == "download") return cmdGet(*env, a);
    if (sub == "put" || sub == "upload") return cmdPut(*env, a);
    if (sub == "rm") return cmdRm(*env, a);
    if (sub == "mb") return cmdMb(*env, a);
    if (sub == "rb") return cmdRb(*env, a);
    if (sub == "info") return cmdInfo(*env, a, opts.format);
    throw UsageError("s3: unknown subcommand '" + sub + "'");
}

int runCheck(const Options& opts, const std::vector<std::string>& rest, const std::string& socket) {
    if (rest.size() > 1) throw UsageError("check: at most one cluster name");
    const std::string name = rest.empty() ? std::string() : rest[0];
    Value data;
    try {
        Value req = Value::object();
        req.set("cmd", Value::str("check"));
        if (!name.empty()) req.set("name", Value::str(name));
        data = Client(socket).call(req);
    } catch (const ConnectionError& e) {
        // s3mmd is not running: probe from here with the same code.
        LOG_WARN("check: ", e.what(), "; probing directly from the configuration");
        std::cerr << "s3mm: note: daemon not reachable, checking directly from " << opts.config << "\n";
        auto env = loadEnvironment(opts);
        data = Value::array();
        for (const auto& c : env->registry->clusters()) {
            if (!name.empty() && c.name != name && c.alias != name) continue;
            data.push(repl::probeCluster(*env->registry, c, &env->loader).toValue());
        }
        if (!name.empty() && data.items().empty()) throw UsageError("check: no cluster '" + name + "'");
    }
    Value table = Value::array();
    bool allOk = true;
    for (const auto& p : data.items()) {
        if (opts.format != Format::Table) break;
        for (const auto& e : p.find("endpoints") ? p.find("endpoints")->items() : std::vector<Value>{}) {
            Value row = Value::object();
            row.set("cluster", Value::str(p.getString("cluster")));
            row.set("managed", Value::str(p.find("managed") && p.find("managed")->asBool(false) ? "yes" : "no"));
            row.set("plane", Value::str(e.getString("plane")));
            row.set("endpoint", Value::str(e.getString("endpoint")));
            bool authorized = e.find("authorized") && e.find("authorized")->asBool(false);
            bool reachable = e.find("reachable") && e.find("reachable")->asBool(false);
            row.set("state", Value::str(authorized ? "OK" : reachable ? (e.getString("plane") == "admin" ? "REACHABLE" : "AUTH/ERROR") : "DOWN"));
            row.set("ms", Value::str(cell(*e.find("ms"))));
            row.set("detail", Value::str(e.getString("error")));
            table.push(row);
        }
    }
    for (const auto& p : data.items())
        if (!(p.find("available") && p.find("available")->asBool(false))) allOk = false;
    std::cout << render(opts.format == Format::Table ? table : data, opts.format);
    return allOk ? 0 : 1;
}

} // namespace s3mm::cli
