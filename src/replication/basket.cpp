#include "s3mm/replication/basket.hpp"

#include "s3mm/common/log.hpp"
#include "s3mm/common/str.hpp"

namespace s3mm::repl {

Candidate Candidate::fromDecision(const policy::Decision& decision, const s3::ObjectInfo& info,
                                  const std::string& replication, const std::string& bucket) {
    Candidate c;
    c.kind = Kind::Object;
    c.replication = replication;
    c.bucket = bucket;
    c.key = info.key;
    c.size = info.size;
    c.etag = info.etag;
    c.lastModified = info.lastModified;
    c.outcome = decision.outcome;
    c.target = decision.target;
    c.rule = decision.rule ? (decision.rule->name.empty() ? std::to_string(decision.rule->order) : decision.rule->name)
                           : std::string("default");
    c.reason = decision.rule ? decision.rule->conditionText() : "default action";
    return c;
}

uint64_t Basket::bytes() const {
    uint64_t total = 0;
    for (const auto& item : items) total += item.size;
    return total;
}

Task::Task(std::string replication, std::string source, std::string destination, std::string bucket, int64_t cycle)
    : replication_(std::move(replication)),
      source_(std::move(source)),
      destination_(std::move(destination)),
      bucket_(std::move(bucket)),
      cycle_(cycle),
      started_(tm::now()) {
    id_ = replication_ + "/" + bucket_ + "#" + std::to_string(cycle);
    LOG_DEBUG("task ", id_, " created (", source_, " -> ", destination_, ")");
}

void Task::add(Candidate candidate) {
    std::string outcome = candidate.outcome.empty() ? "success" : candidate.outcome;
    Basket& b = baskets_[outcome];
    if (b.outcome.empty()) b.outcome = outcome;
    if (b.targetName.empty()) b.targetName = candidate.target;
    LOG_DEBUG("task ", id_, ": ", candidate.bucket, "/", candidate.key, " (", candidate.size, " bytes) added to ",
              outcome, " basket -> ", b.targetName.empty() ? std::string("null") : b.targetName, " (",
              b.items.size() + 1, " item(s))");
    b.items.push_back(std::move(candidate));
}

Basket& Task::basket(const std::string& outcome) {
    Basket& b = baskets_[outcome];
    if (b.outcome.empty()) b.outcome = outcome;
    return b;
}

size_t Task::total() const {
    size_t n = 0;
    for (const auto& [outcome, b] : baskets_) n += b.items.size();
    return n;
}

uint64_t Task::bytes() const {
    uint64_t total = 0;
    for (const auto& [outcome, b] : baskets_) total += b.bytes();
    return total;
}

std::map<std::string, std::vector<Candidate>> Task::byTarget() const {
    std::map<std::string, std::vector<Candidate>> out;
    for (const auto& [outcome, b] : baskets_) {
        auto& bucket = out[b.targetName.empty() ? std::string("null") : b.targetName];
        bucket.insert(bucket.end(), b.items.begin(), b.items.end());
    }
    return out;
}

} // namespace s3mm::repl
