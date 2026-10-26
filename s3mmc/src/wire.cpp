#include "s3mm/wire.hpp"

#include <chrono>

#include "s3mm/common/crypto.hpp"
#include "s3mm/common/time.hpp"

namespace s3mm::peer {

std::string encodeFrame(const Value& frame) {
    std::string line = frame.toJson();
    // toJson() never emits raw newlines inside strings, but be defensive:
    for (auto& ch : line)
        if (ch == '\n') ch = ' ';
    line.push_back('\n');
    return line;
}

Result<Value> decodeFrame(const std::string& line) {
    if (line.size() > kMaxFrameBytes)
        return Result<Value>::failure("peer frame too large (" + std::to_string(line.size()) + " bytes)");
    std::string error;
    auto v = Value::parseJson(line, &error);
    if (!error.empty()) return Result<Value>::failure("peer frame parse error: " + error);
    if (!v.isObject()) return Result<Value>::failure("peer frame is not a JSON object");
    return Result<Value>(std::move(v));
}

// --------------------------------------------------------------- inventory --

Value Inventory::toJson() const {
    Value v = Value::object();
    v.set("node", Value::str(nodeId));
    v.set("revision", Value::number(revision));
    v.set("generated_at", Value::number(generatedAtSec));
    Value clustersArr = Value::array();
    for (const auto& c : clusters) {
        Value cv = Value::object();
        cv.set("id", Value::str(c.id));
        cv.set("alias", Value::str(c.alias));
        cv.set("vendor", Value::str(c.vendor));
        cv.set("zone", Value::str(c.zone));
        Value eps = Value::array();
        for (const auto& e : c.endpoints) eps.push(Value::str(e));
        cv.set("endpoints", eps);
        clustersArr.push(cv);
    }
    v.set("clusters", clustersArr);
    Value reps = Value::array();
    for (const auto& r : replications) {
        Value rv = Value::object();
        rv.set("name", Value::str(r.name));
        rv.set("source", Value::str(r.source));
        rv.set("destination", Value::str(r.destination));
        rv.set("paused", Value::boolean(r.paused));
        reps.push(rv);
    }
    v.set("replications", reps);
    Value locals = Value::array();
    for (const auto& l : localClusters) locals.push(Value::str(l));
    v.set("local_clusters", locals);
    return v;
}

static std::vector<std::string> stringArray(const Value& parent, const char* key) {
    std::vector<std::string> out;
    const Value* arr = parent.find(key);
    if (arr && arr->isArray())
        for (const auto& e : arr->items())
            if (e.isString()) out.push_back(e.asString());
    return out;
}

Result<Inventory> Inventory::fromJson(const Value& v) {
    if (!v.isObject()) return Result<Inventory>::failure("inventory: not an object");
    Inventory inv;
    inv.nodeId = v.getString("node");
    if (inv.nodeId.empty()) return Result<Inventory>::failure("inventory: missing node id");
    if (const Value* r = v.find("revision")) inv.revision = r->asInt(0);
    if (const Value* g = v.find("generated_at")) inv.generatedAtSec = g->asInt(0);
    if (const Value* arr = v.find("clusters"); arr && arr->isArray()) {
        for (const auto& cv : arr->items()) {
            InventoryCluster c;
            c.id = cv.getString("id");
            if (c.id.empty()) continue;
            c.alias = cv.getString("alias");
            c.vendor = cv.getString("vendor");
            c.zone = cv.getString("zone");
            c.endpoints = stringArray(cv, "endpoints");
            inv.clusters.push_back(std::move(c));
        }
    }
    if (const Value* arr = v.find("replications"); arr && arr->isArray()) {
        for (const auto& rv : arr->items()) {
            RemoteReplication r;
            r.name = rv.getString("name");
            if (r.name.empty()) continue;
            r.source = rv.getString("source");
            r.destination = rv.getString("destination");
            if (const Value* p = rv.find("paused")) r.paused = p->asBool(false);
            inv.replications.push_back(std::move(r));
        }
    }
    inv.localClusters = stringArray(v, "local_clusters");
    return Result<Inventory>(std::move(inv));
}

// --------------------------------------------------------------------- task --

Value TaskSpec::toJson() const {
    Value v = Value::object();
    v.set("id", Value::str(id));
    v.set("origin", Value::str(origin));
    Value trail = Value::array();
    for (const auto& t : this->trail) trail.push(Value::str(t));
    v.set("trail", trail);
    v.set("replication", Value::str(replication));
    v.set("kind", Value::str(kind));
    v.set("bucket", Value::str(bucket));
    v.set("key", Value::str(key));
    v.set("size", Value::number(size));
    v.set("etag", Value::str(etag));
    v.set("version_id", Value::str(versionId));
    v.set("content_type", Value::str(contentType));
    v.set("last_modified", Value::str(lastModified));
    v.set("reason", Value::str(reason));
    Value metaObj = Value::object();
    for (const auto& [k, m] : meta) metaObj.set(k, Value::str(m));
    v.set("meta", metaObj);
    return v;
}

Result<TaskSpec> TaskSpec::fromJson(const Value& v) {
    if (!v.isObject()) return Result<TaskSpec>::failure("task: not an object");
    TaskSpec t;
    t.id = v.getString("id");
    t.origin = v.getString("origin");
    t.trail = stringArray(v, "trail");
    t.replication = v.getString("replication");
    t.kind = v.getString("kind");
    t.bucket = v.getString("bucket");
    t.key = v.getString("key");
    if (const Value* s = v.find("size")) t.size = (uint64_t)s->asInt(0);
    t.etag = v.getString("etag");
    t.versionId = v.getString("version_id");
    t.contentType = v.getString("content_type");
    t.lastModified = v.getString("last_modified");
    t.reason = v.getString("reason");
    if (const Value* m = v.find("meta"); m && m->isObject())
        for (const auto& [k, val] : m->members())
            if (val.isString()) t.meta[k] = val.asString();
    if (t.id.empty()) return Result<TaskSpec>::failure("task: missing id");
    if (t.bucket.empty() || t.key.empty()) return Result<TaskSpec>::failure("task: missing bucket/key");
    return Result<TaskSpec>(std::move(t));
}

Value TaskResult::toJson() const {
    Value v = Value::object();
    v.set("task", Value::str(taskId));
    v.set("node", Value::str(node));
    v.set("status", Value::str(status));
    v.set("reason", Value::str(reason));
    v.set("bytes", Value::number(bytesShipped));
    return v;
}

Result<TaskResult> TaskResult::fromJson(const Value& v) {
    if (!v.isObject()) return Result<TaskResult>::failure("task result: not an object");
    TaskResult r;
    r.taskId = v.getString("task");
    r.node = v.getString("node");
    r.status = v.getString("status");
    r.reason = v.getString("reason");
    if (const Value* b = v.find("bytes")) r.bytesShipped = (uint64_t)b->asInt(0);
    if (r.taskId.empty()) return Result<TaskResult>::failure("task result: missing task id");
    if (r.status != "ok" && r.status != "denied" && r.status != "failed")
        return Result<TaskResult>::failure("task result: unknown status '" + r.status + "'");
    return Result<TaskResult>(std::move(r));
}

} // namespace s3mm::peer
