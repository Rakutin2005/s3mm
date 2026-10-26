#pragma once
#include <memory>
#include <string>
#include <vector>

#include "s3mme/event.hpp"
#include "s3mm/common/result.hpp"

namespace s3mme {
using s3mm::Value;
template<class T> using Result = s3mm::Result<T>;

/// Capabilities a broker module declares; s3mme degrades gracefully.
struct BrokerFeatures {
    bool consume = false;   // inbound events (reacting on messages) supported
};

/// A loadable broker backend. Implemented in modules/s3mme_mod_<broker>.so.
/// The .so itself carries no policy logic: s3mme decides *whether* an event is
/// emitted (policy bundles from s3mme.conf); the module only delivers it to
/// the configured destination (topic/exchange resolved via the routing hint).
class IBroker {
public:
    virtual ~IBroker() = default;
    virtual const char* name() const = 0;             // "kafka" | "rabbitmq" | ...
    virtual BrokerFeatures features() const { return {}; }

    /// Connect/open channels. `config` is the broker{} block from s3mme.conf.
    virtual Result<void> connect(const s3mm::Value& config) = 0;
    virtual void disconnect() {}

    /// Publish one event. `routingHint` is the policy-resolved destination
    /// (topic/exchange/routing key), or empty => module default topic.
    /// Must be non-blocking-ish: buffer internally, fail soft.
    virtual Result<void> publish(const Event& ev, const std::string& routingHint) = 0;

    /// Optional consumer path: poll up to `max` inbound payloads (JSON strings).
    virtual Result<std::vector<std::string>> consume(int /*max*/) {
        return Result<std::vector<std::string>>::failure("consume not supported");
    }

    /// Flush buffered publishes (called on shutdown).
    virtual Result<void> flush() { return Result<void>::success(); }
};

extern "C" {
typedef IBroker* (*CreateBrokerFn)();
}

#define S3MME_BROKER_ENTRY(ClassName)                                        \
    extern "C" s3mme::IBroker* s3mme_broker_entry() { return new ClassName(); }

} // namespace s3mme
