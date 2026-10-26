#include "s3mme/event.hpp"

namespace s3mme {

Value Event::toJson() const {
    Value v = Value::object();
    v.set("id", Value::str(id));
    v.set("at", Value::number(atSec));
    v.set("node", Value::str(node));
    v.set("replication", Value::str(replication));
    v.set("kind", Value::str(kind));
    if (!sourceCluster.empty()) v.set("source_cluster", Value::str(sourceCluster));
    if (!sourceBucket.empty()) v.set("source_bucket", Value::str(sourceBucket));
    if (!destCluster.empty()) v.set("dest_cluster", Value::str(destCluster));
    if (!destBucket.empty()) v.set("dest_bucket", Value::str(destBucket));
    v.set("bucket", Value::str(bucket));
    v.set("key", Value::str(key));
    v.set("outcome", Value::str(outcome));
    if (!target.empty()) v.set("target", Value::str(target));
    if (!rule.empty()) v.set("rule", Value::str(rule));
    if (!reason.empty()) v.set("reason", Value::str(reason));
    v.set("size", Value::number(size));
    return v;
}

} // namespace s3mme
