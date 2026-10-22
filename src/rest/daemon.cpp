#include "s3mm/rest/daemon.hpp"

#include <csignal>
#include <poll.h>
#include <unistd.h>

#include "s3mm/common/fs.hpp"
#include "s3mm/common/log.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/registry/registry.hpp"
#include "s3mm/s3/client.hpp"
#include "s3mm/s3/http.hpp"
#include "s3mm/rest/rbac.hpp"

namespace s3mm::rest {

namespace {
volatile std::sig_atomic_t gStop = 0;
void onSignal(int) { gStop = 1; }
}

RestDaemon::RestDaemon(Options options)
    : options_(std::move(options)),
      daemonClient_(options_.socket.empty() ? "/run/s3mm/s3mm.sock" : options_.socket) {}

std::unique_ptr<s3::Client> RestDaemon::makeClient(const std::string& clusterName) {
    if (!registry_) return nullptr;
    const registry::Cluster* cluster = registry_->cluster(clusterName);
    if (!cluster) return nullptr;
    const registry::Credential* cred = registry_->bestCredential(*cluster);
    if (!cred) return nullptr;
    s3::ClientOptions opts;
    opts.endpoints = cluster->endpoints;
    opts.pathStyle = cluster->pathStyle;
    opts.insecure = cluster->insecure;
    opts.timeoutSec = cluster->timeoutSec;
    opts.connectTimeoutSec = cluster->connectTimeoutSec;
    opts.rateLimitPerSec = cluster->rateLimitPerSec;
    opts.maxRetries = cluster->retries;
    sigv4::Credentials credentials{cred->accessKey, cred->secretKey, cred->sessionToken, cred->region};
    return std::make_unique<s3::Client>(opts, credentials);
}

void RestDaemon::registerDefaults() {
    router_.add("GET", "/health", [](const RestRequest&, RestResponse& res) {
        res.json(Value::object());
        res.body = "{\"ok\":true}\n";
    });
    router_.add("GET", "/status", [this](const RestRequest&, RestResponse& res) {
        try {
            Value data = daemonClient_.call(Value::object().set("cmd", Value::str("status")));
            res.json(data);
        } catch (const std::exception& e) {
            res.status = 502;
            res.json(Value::object().set("error", Value::str(e.what())));
        }
    });
    router_.add("GET", "/modules", [this](const RestRequest&, RestResponse& res) {
        Value arr = Value::array();
        for (const auto* m : modules_) {
            Value v = Value::object();
            auto info = m->info();
            v.set("name", Value::str(info.name));
            v.set("version", Value::str(info.version));
            v.set("vendor", Value::str(info.vendor));
            arr.push(v);
        }
        res.json(arr);
    });
    router_.add("POST", "/rpc", [this](const RestRequest& req, RestResponse& res) {
        std::string parseError;
        Value parsed = Value::parseJson(req.body, &parseError);
        if (!parseError.empty() || !parsed.isObject()) {
            res.status = 400;
            res.json(Value::object().set("error", Value::str("bad request")));
            return;
        }
        try {
            Value data = daemonClient_.call(parsed);
            res.json(data);
        } catch (const std::exception& e) {
            res.status = 502;
            res.json(Value::object().set("error", Value::str(e.what())));
        }
    });
    router_.add("GET", "/rbac/users", [](const RestRequest&, RestResponse& res) {
        res.status = 501;
        res.json(Value::object().set("error", Value::str("RBAC is not implemented yet")));
    });
    router_.add("GET", "/rbac/roles", [](const RestRequest&, RestResponse& res) {
        res.status = 501;
        res.json(Value::object().set("error", Value::str("RBAC is not implemented yet")));
    });
    router_.add("GET", "/rbac/permissions", [](const RestRequest&, RestResponse& res) {
        res.status = 501;
        res.json(Value::object().set("error", Value::str("RBAC is not implemented yet")));
    });
    router_.add("GET", "/replications", [this](const RestRequest&, RestResponse& res) {
        Value req = Value::object();
        req.set("cmd", Value::str("list"));
        req.set("kind", Value::str("replication"));
        try {
            res.json(daemonClient_.call(req));
        } catch (const std::exception& e) {
            res.status = 502;
            res.json(Value::object().set("error", Value::str(e.what())));
        }
    });    router_.add("GET", "/browse/buckets", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto buckets = client->listBuckets();
        if (!buckets) { res.status = 502; res.json(Value::object().set("error", Value::str(buckets.error()))); return; }
        Value arr = Value::array();
        for (const auto& b : buckets.value()) {
            Value v = Value::object();
            v.set("name", Value::str(b.name));
            v.set("created", Value::str(tm::toIso8601(b.created)));
            arr.push(v);
        }
        res.json(arr);
    });
    router_.add("GET", "/browse/objects", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string prefix = req.query.count("prefix") ? req.query.at("prefix") : "";
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto page = client->listObjects(bucket, prefix, "", "", 1000);
        if (!page) { res.status = 502; res.json(Value::object().set("error", Value::str(page.error()))); return; }
        Value arr = Value::array();
        for (const auto& o : page.value().objects) {
            Value v = Value::object();
            v.set("key", Value::str(o.key));
            v.set("size", Value::number((int64_t)o.size));
            v.set("last_modified", Value::str(tm::toIso8601(o.lastModified)));
            v.set("etag", Value::str(o.etag));
            v.set("storage_class", Value::str(o.storageClass));
            arr.push(v);
        }
        Value prefixes = Value::array();
        for (const auto& pfx : page.value().commonPrefixes) prefixes.push(Value::str(pfx));
        Value out = Value::object();
        out.set("objects", arr);
        out.set("prefixes", prefixes);
        out.set("truncated", Value::boolean(page.value().truncated));
        out.set("next_token", Value::str(page.value().nextToken));
        res.json(out);
    });
    router_.add("GET", "/browse/object", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto meta = client->headObject(bucket, key);
        if (!meta) { res.status = 404; res.json(Value::object().set("error", Value::str(meta.error()))); return; }
        Value v = Value::object();
        v.set("exists", Value::boolean(meta.value().exists));
        v.set("size", Value::number((int64_t)meta.value().size));
        v.set("etag", Value::str(meta.value().etag));
        v.set("last_modified", Value::str(tm::toIso8601(meta.value().lastModified)));
        v.set("content_type", Value::str(meta.value().contentType));
        v.set("content_encoding", Value::str(meta.value().contentEncoding));
        v.set("content_language", Value::str(meta.value().contentLanguage));
        v.set("content_disposition", Value::str(meta.value().contentDisposition));
        v.set("cache_control", Value::str(meta.value().cacheControl));
        v.set("expires", Value::str(meta.value().expires));
        v.set("storage_class", Value::str(meta.value().storageClass));
        Value tags = Value::object();
        for (const auto& [k, val] : meta.value().tags) tags.set(k, Value::str(val));
        v.set("tags", tags);
        Value userMeta = Value::object();
        for (const auto& [k, val] : meta.value().userMeta) userMeta.set(k, Value::str(val));
        v.set("user_meta", userMeta);
        res.json(v);
    });
    router_.add("PUT", "/browse/object", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        std::string parseError;
        Value body = Value::parseJson(req.body, &parseError);
        if (parseError.empty() == false || !body.isObject()) { res.status = 400; res.json(Value::object().set("error", Value::str("bad request"))); return; }
        s3::ObjectMeta meta;
        meta.contentType = body.getString("content_type", "application/octet-stream");
        meta.contentEncoding = body.getString("content_encoding");
        meta.contentLanguage = body.getString("content_language");
        meta.contentDisposition = body.getString("content_disposition");
        meta.cacheControl = body.getString("cache_control");
        meta.expires = body.getString("expires");
        meta.storageClass = body.getString("storage_class");
        if (const Value* m = body.find("metadata")) if (m && m->isObject()) for (const auto& [k, v] : m->members()) meta.userMeta[k] = v.asString();
        if (const Value* t = body.find("tags")) if (t && t->isObject()) for (const auto& [k, v] : t->members()) meta.tags[k] = v.asString();
        std::string content = body.getString("content");
        auto put = client->putObject(bucket, key, content, meta);
        if (!put) { res.status = 502; res.json(Value::object().set("error", Value::str(put.error()))); return; }
        if (const Value* t = body.find("tags")) if (t && t->isObject()) {
            s3::BucketTagging tagging;
            for (const auto& [k, v] : t->members()) tagging.tags[k] = v.asString();
            (void)client->putObjectTagging(bucket, key, tagging);
        }
        res.json(Value::object().set("ok", Value::boolean(true)));
    });
    router_.add("DELETE", "/browse/object", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        auto del = client->deleteObject(bucket, key);
        if (!del) { res.status = 502; res.json(Value::object().set("error", Value::str(del.error()))); return; }
        res.json(Value::object().set("ok", Value::boolean(true)));
    });
    router_.add("GET", "/browse/object-acl", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        http::Request r;
        r.method = "GET";
        r.url = client->primaryEndpoint() + "/" + bucket + "/" + key;
        r.query["acl"] = "";
        auto resp = client->raw(r);
        if (!resp.ok()) { res.status = resp.status; res.text(resp.body); return; }
        res.text(resp.body, "application/xml");
    });
    router_.add("PUT", "/browse/object-acl", [this](const RestRequest& req, RestResponse& res) {
        std::string cluster = req.query.count("cluster") ? req.query.at("cluster") : "";
        std::string bucket = req.query.count("bucket") ? req.query.at("bucket") : "";
        std::string key = req.query.count("key") ? req.query.at("key") : "";
        std::string acl = req.query.count("acl") ? req.query.at("acl") : "private";
        auto client = makeClient(cluster);
        if (!client) { res.status = 404; res.json(Value::object().set("error", Value::str("cluster not found"))); return; }
        http::Request r;
        r.method = "PUT";
        r.url = client->primaryEndpoint() + "/" + bucket + "/" + key;
        r.query["acl"] = "";
        r.headers["x-amz-acl"] = acl;
        auto resp = client->raw(r);
        if (!resp.ok()) { res.status = resp.status; res.text(resp.body); return; }
        res.json(Value::object().set("ok", Value::boolean(true)));
    });

}

int RestDaemon::run() {
    // Load config (optional) for socket/modules defaults.
    if (!options_.config.empty()) {
        auto cfg = config::Config::load(options_.config);
        if (cfg) {
            if (options_.validateOnly) return 0;
            auto reg = registry::Registry::fromConfig(cfg.value());
            if (reg) {
                if (options_.socket.empty()) options_.socket = reg.value().settings().socket;
                if (options_.modulesDir.empty()) options_.modulesDir = reg.value().settings().modulesDir;
                registry_ = std::make_unique<registry::Registry>(std::move(reg.value()));
            }
        } else {
            if (options_.validateOnly) return 1;
        }
    }
    if (options_.validateOnly) return 0;

    if (options_.socket.empty()) options_.socket = "/run/s3mm/s3mm.sock";
    daemonClient_ = cli::Client(options_.socket);
    if (options_.modulesDir.empty()) options_.modulesDir = "./modules";

    auto loaded = loader_.loadDir(options_.modulesDir);
    if (!loaded) LOG_WARN("rest modules: ", loaded.error());

    RestContext ctx(daemonClient_, options_.modulesDir);
    for (auto* m : loader_.modules()) {
        m->onLoad(ctx);
        m->registerRoutes(router_);
        modules_.push_back(m);
    }

    registerDefaults();

    auto listened = http_.listen(options_.listen, options_.port);
    if (!listened) {
        LOG_ERROR("rest http: ", listened.error());
        return 1;
    }
    LOG_INFO("rest http on http://", options_.listen, ":", options_.port);

    if (options_.daemonize) {
        // Simple daemonize.
        pid_t pid = fork();
        if (pid < 0) return 1;
        if (pid > 0) return 0;
        setsid();
    }

    std::signal(SIGTERM, onSignal);
    std::signal(SIGINT, onSignal);
    std::signal(SIGPIPE, SIG_IGN);

    while (!gStop) {
        pollfd pfd{http_.fd(), POLLIN, 0};
        int rc = ::poll(&pfd, 1, 500);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (rc > 0 && (pfd.revents & POLLIN)) {
            http_.acceptOne([this](const RestRequest& req, RestResponse& res) {
                // Authentication chain.
                for (auto* m : modules_) {
                    if (!m->authenticate(req, res)) return;
                }
                // Request processing chain.
                for (auto* m : modules_) {
                    if (m->process(req, res)) return;
                }
                if (!router_.route(req, res)) {
                    res.status = 404;
                    res.json(Value::object().set("error", Value::str("not found")));
                }
            });
        }
    }
    http_.close();
    return 0;
}

} // namespace s3mm::rest
