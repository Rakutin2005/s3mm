#include "s3mm/replication/target.hpp"
#include "s3mm/registry/registry.hpp"
#include "s3mm/registry/mutate.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/module/loader.hpp"
#include <stdexcept>
#include "testkit.hpp"

using namespace s3mm;
using namespace s3mm::repl;

static registry::Registry makeRegistry() {
    const char* text = R"(
s3mm {
    cluster src { addr http://127.0.0.1:9000; credential c; }
    cluster dst { addr http://127.0.0.1:9001; credential c; }
    credential c { access_key AK; secret_key SK; }
    target q { kind file; uri file:/tmp/opencode/tgtq; }
    target h { kind http; uri http://example.com/hook; }
    replication r { source src; destination dst; policy default; }
}
)";
    auto cfg = config::Config::parse(text);
    auto reg = registry::Registry::fromConfig(cfg.value());
    if (!reg) throw std::runtime_error(reg.error());
    return reg.value();
}

TEST(target_factory_null_quarantine_db) {
    auto reg = makeRegistry();
    module::Loader loader;
    TargetFactory tf(reg, &loader);
    auto n = tf.create("null");
    CHECK(n.ok());
    CHECK(n.value() != nullptr);
    CHECK_EQ(n.value()->kind(), std::string("null"));
    auto q = tf.create("quarantine");
    CHECK(q.ok());
    CHECK_EQ(q.value()->kind(), std::string("file"));
    auto db = tf.create("db");
    CHECK(db.ok());
    CHECK_EQ(db.value()->kind(), std::string("null"));
}

TEST(target_factory_explicit) {
    auto reg = makeRegistry();
    module::Loader loader;
    TargetFactory tf(reg, &loader);
    auto q = tf.create("q");
    CHECK(q.ok());
    CHECK_EQ(q.value()->kind(), std::string("file"));
    auto h = tf.create("h");
    CHECK(h.ok());
    CHECK_EQ(h.value()->kind(), std::string("http"));
}

TEST(target_factory_unknown) {
    auto reg = makeRegistry();
    module::Loader loader;
    TargetFactory tf(reg, &loader);
    auto r = tf.create("does-not-exist");
    CHECK(!r.ok());
}

TEST(target_factory_find_cached) {
    auto reg = makeRegistry();
    module::Loader loader;
    TargetFactory tf(reg, &loader);
    auto a = tf.create("null");
    auto b = tf.find("null");
    CHECK(a.ok());
    CHECK(b != nullptr);
}

TEST(target_factory_routes_for) {
    auto reg = makeRegistry();
    module::Loader loader;
    TargetFactory tf(reg, &loader);
    const auto* rep = reg.replication("r");
    CHECK(rep != nullptr);
    auto routes = tf.routesFor(*rep);
    CHECK(routes.ok());
    CHECK(routes.value().denied != nullptr);
    CHECK(routes.value().warning != nullptr);
    CHECK(routes.value().success != nullptr);
}

TEST(target_null_ship) {
    NullTarget n("null");
    ShipRecord r;
    r.outcome = "denied";
    r.kind = "object";
    r.bucket = "b";
    r.key = "k";
    CHECK(n.ship(r, "").ok());
}
