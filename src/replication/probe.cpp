#include "s3mm/replication/probe.hpp"

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"
#include "s3mm/s3/client.hpp"
#include "s3mm/s3/xml.hpp"

namespace s3mm::repl {

bool ClusterProbe::available() const {
    for (const auto& e : endpoints)
        if (e.plane == "s3" && e.authorized) return true;
    return false;
}

bool ClusterProbe::healthy() const {
    bool any = false;
    for (const auto& e : endpoints) {
        if (e.plane != "s3") continue;
        if (!e.authorized) return false;
        any = true;
    }
    return any;
}

Value ClusterProbe::toValue() const {
    Value v = Value::object();
    v.set("cluster", Value::str(cluster));
    v.set("vendor", Value::str(vendor));
    v.set("managed", Value::boolean(managed));
    v.set("credential", Value::str(credential));
    v.set("access_key", Value::str(accessKey));
    v.set("module_loaded", Value::boolean(moduleLoaded));
    v.set("admin_error", Value::str(adminError));
    v.set("available", Value::boolean(available()));
    v.set("healthy", Value::boolean(healthy()));
    v.set("buckets", Value::number(buckets));
    v.set("ms", Value::number((int64_t)ms));
    Value arr = Value::array();
    for (const auto& e : endpoints) {
        Value x = Value::object();
        x.set("endpoint", Value::str(e.endpoint));
        x.set("plane", Value::str(e.plane));
        x.set("reachable", Value::boolean(e.reachable));
        x.set("authorized", Value::boolean(e.authorized));
        x.set("status", Value::number((int64_t)e.status));
        x.set("ms", Value::number((int64_t)e.ms));
        x.set("error", Value::str(e.error));
        arr.push(x);
    }
    v.set("endpoints", arr);
    return v;
}

std::string ClusterProbe::summary() const {
    int ok = 0, total = 0;
    for (const auto& e : endpoints)
        if (e.plane == "s3") {
            ++total;
            if (e.authorized) ++ok;
        }
    std::string out = std::string(healthy() ? "healthy" : available() ? "degraded" : "unavailable") + ", " +
                      std::to_string(ok) + "/" + std::to_string(total) + " data endpoint(s) ok";
    if (buckets >= 0) out += ", " + std::to_string(buckets) + " bucket(s)";
    return out;
}

namespace {

// S3 error code from an XML error body, empty when there is none.
std::string s3ErrorCode(const http::Response& r) {
    auto parsed = xml::parse(r.body);
    if (!parsed) return {};
    return parsed.value().childText("Code");
}

int64_t countBuckets(const http::Response& r) {
    auto parsed = xml::parse(r.body);
    if (!parsed) return -1;
    const xml::Element* list = parsed.value().child("Buckets");
    return list ? (int64_t)list->childrenNamed("Bucket").size() : 0;
}

s3::ClientOptions probeOptions(const registry::Cluster& c, const std::string& endpoint) {
    s3::ClientOptions o;
    o.endpoints = {endpoint};
    o.pathStyle = c.pathStyle;
    o.insecure = c.insecure;
    o.connectTimeoutSec = c.connectTimeoutSec;
    o.timeoutSec = c.connectTimeoutSec + 10; // a probe must not hang for the full data timeout
    o.maxRetries = 1;
    return o;
}

} // namespace

ClusterProbe probeCluster(const registry::Registry& registry, const registry::Cluster& cluster,
                          const module::Loader* loader) {
    log::Stopwatch total;
    ClusterProbe p;
    p.cluster = cluster.name;
    p.vendor = cluster.vendor;
    p.managed = cluster.managed;
    LOG_INFO("probe: checking availability of cluster '", cluster.name, "' (vendor ", cluster.vendor, ", ",
             cluster.managed ? "managed" : "unmanaged", ", data endpoints [", str::join(cluster.endpoints, ","), "])");

    module::IModule* mod = loader ? loader->find(cluster.vendor) : nullptr;
    p.moduleLoaded = mod != nullptr;
    if (loader && !mod && cluster.vendor != "generic")
        LOG_WARN("probe: cluster '", cluster.name, "': vendor module '", cluster.vendor, "' is not loaded");

    const registry::Credential* cred = registry.bestCredential(cluster);
    if (!cred) {
        LOG_ERROR("probe: cluster '", cluster.name, "' has no usable credential, data plane cannot be checked");
    } else {
        p.credential = cred->name;
        p.accessKey = cred->accessKey;
    }
    sigv4::Credentials sig;
    if (cred) sig = {cred->accessKey, cred->secretKey, cred->sessionToken, cred->region};

    for (const auto& endpoint : cluster.endpoints) {
        EndpointProbe e;
        e.endpoint = endpoint;
        e.plane = "s3";
        if (!cred) {
            e.error = "no usable credential";
            p.endpoints.push_back(e);
            continue;
        }
        s3::ClientOptions o = probeOptions(cluster, endpoint);
        if (mod) mod->adjustClientOptions(o);
        LOG_DEBUG("probe: cluster '", cluster.name, "': ListBuckets on ", endpoint, " as ", cred->accessKey,
                  " (connect timeout ", o.connectTimeoutSec, "s)");
        log::Stopwatch sw;
        s3::Client client(o, sig);
        http::Request req;
        req.method = "GET";
        req.url = endpoint + "/";
        req.connectTimeoutSec = o.connectTimeoutSec;
        req.timeoutSec = o.timeoutSec;
        http::Response r = client.raw(req);
        e.ms = sw.ms();
        e.status = r.status;
        e.reachable = !r.transportError();
        e.authorized = r.ok();
        if (r.transportError()) {
            e.error = r.curlError.empty() ? "no response" : r.curlError;
            LOG_ERROR("probe: cluster '", cluster.name, "': endpoint ", endpoint, " is UNREACHABLE: ", e.error,
                      " (", e.ms, " ms)");
        } else if (!r.ok()) {
            std::string code = s3ErrorCode(r);
            e.error = "HTTP " + std::to_string(r.status) + (code.empty() ? "" : " " + code);
            if (r.status == 401 || r.status == 403)
                LOG_ERROR("probe: cluster '", cluster.name, "': endpoint ", endpoint, " is reachable but rejected credential '",
                          cred->name, "' (access key ", cred->accessKey, "): ", e.error, " (", e.ms, " ms)");
            else
                LOG_WARN("probe: cluster '", cluster.name, "': endpoint ", endpoint, " answered ", e.error, " (", e.ms, " ms)");
        } else {
            int64_t n = countBuckets(r);
            if (p.buckets < 0) p.buckets = n;
            LOG_INFO("probe: cluster '", cluster.name, "': endpoint ", endpoint, " is available, credential '", cred->name,
                     "' accepted, ", n, " bucket(s) visible (", e.ms, " ms)");
        }
        p.endpoints.push_back(e);
    }

    if (!cluster.managed) {
        LOG_DEBUG("probe: cluster '", cluster.name, "' is unmanaged, management API is not checked");
    } else {
        const auto& adminEndpoints = cluster.adminEndpoints.empty() ? cluster.endpoints : cluster.adminEndpoints;
        if (cluster.adminEndpoints.empty())
            LOG_DEBUG("probe: cluster '", cluster.name, "': management API shares the data endpoints");
        for (const auto& endpoint : cluster.adminEndpoints) {
            EndpointProbe e;
            e.endpoint = endpoint;
            e.plane = "admin";
            s3::ClientOptions o = probeOptions(cluster, endpoint);
            if (mod) mod->adjustClientOptions(o);
            LOG_DEBUG("probe: cluster '", cluster.name, "': checking management endpoint ", endpoint);
            log::Stopwatch sw;
            s3::Client client(o, sig);
            http::Request req;
            req.method = "GET";
            req.url = endpoint + "/";
            req.connectTimeoutSec = o.connectTimeoutSec;
            req.timeoutSec = o.timeoutSec;
            http::Response r = client.raw(req);
            e.ms = sw.ms();
            e.status = r.status;
            e.reachable = !r.transportError();
            if (!e.reachable) {
                e.error = r.curlError.empty() ? "no response" : r.curlError;
                LOG_ERROR("probe: cluster '", cluster.name, "': management endpoint ", endpoint, " is UNREACHABLE: ",
                          e.error, " (", e.ms, " ms)");
            } else {
                LOG_INFO("probe: cluster '", cluster.name, "': management endpoint ", endpoint, " answers (HTTP ",
                         r.status, ", ", e.ms, " ms)");
            }
            p.endpoints.push_back(e);
        }
        if (mod && cred) {
            s3::ClientOptions o;
            o.endpoints = adminEndpoints;
            o.pathStyle = cluster.pathStyle;
            o.insecure = cluster.insecure;
            mod->adjustClientOptions(o);
            auto admin = mod->createAdmin(o, sig);
            if (!admin) {
                p.adminError = admin.error();
                LOG_ERROR("probe: cluster '", cluster.name, "': vendor module '", cluster.vendor,
                          "' cannot create the admin provider: ", admin.error());
            } else if (!admin.value()->features().credentials) {
                LOG_INFO("probe: cluster '", cluster.name, "': module '", cluster.vendor,
                         "' has no account administration, account sync is not available");
            } else {
                LOG_DEBUG("probe: cluster '", cluster.name, "': admin provider of module '", cluster.vendor, "' is ready");
            }
        } else if (!mod) {
            p.adminError = "vendor module '" + cluster.vendor + "' not loaded";
        }
    }

    p.ms = total.ms();
    if (p.healthy())
        LOG_INFO("probe: cluster '", cluster.name, "' is ", p.summary(), " (", p.ms, " ms)");
    else if (p.available())
        LOG_WARN("probe: cluster '", cluster.name, "' is ", p.summary(), " (", p.ms, " ms)");
    else
        LOG_ERROR("probe: cluster '", cluster.name, "' is ", p.summary(), " (", p.ms, " ms)");
    return p;
}

} // namespace s3mm::repl
