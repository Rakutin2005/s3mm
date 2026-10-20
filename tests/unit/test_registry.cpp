#include "s3mm/registry/registry.hpp"
#include "s3mm/config/config.hpp"
#include "s3mm/policy/bundle.hpp"
#include "testkit.hpp"

using namespace s3mm;
using namespace s3mm::policy;

static const char* BASE_CFG = R"(
s3mm {
    socket /tmp/s3mm-test.sock;
    cache_dir /tmp/s3mm-test-cache;
    cluster src { addr http://127.0.0.1:9000; credential c; }
    cluster dst { addr http://127.0.0.1:9001; credential c; }
    credential c { access_key AK; secret_key SK; }
    target q { kind file; uri file:/tmp/q; }
    replication r { source src; destination dst; policy default; }
}
)";

TEST(registry_from_config) {
    auto cfg = config::Config::parse(BASE_CFG);
    CHECK(cfg);
    auto reg = registry::Registry::fromConfig(cfg.value());
    CHECK(reg);
    CHECK_EQ(reg.value().clusters().size(), 2u);
    CHECK_EQ(reg.value().credentials().size(), 1u);
    CHECK_EQ(reg.value().replications().size(), 1u);
    CHECK_EQ(reg.value().targets().size(), 1u);
    CHECK(reg.value().cluster("src") != nullptr);
    CHECK(reg.value().bundle("default") != nullptr);
    CHECK(reg.value().bundle("drop-all") != nullptr);
    CHECK(reg.value().replication("r") != nullptr);
}

TEST(registry_dump_roundtrip) {
    auto cfg = config::Config::parse(BASE_CFG);
    CHECK(cfg);
    auto reg = registry::Registry::fromConfig(cfg.value());
    CHECK(reg);
    std::string dumped = reg.value().dump();
    auto cfg2 = config::Config::parse(dumped);
    CHECK(cfg2);
    auto errs = cfg2.value().validate();
    CHECK(errs.empty());
    auto reg2 = registry::Registry::fromConfig(cfg2.value());
    CHECK(reg2);
    CHECK_EQ(reg2.value().clusters().size(), 2u);
    CHECK_EQ(reg2.value().replications().size(), 1u);
    CHECK_EQ(reg2.value().targets().size(), 1u);
    CHECK(reg2.value().bundle("default") != nullptr);
}

TEST(registry_mutations) {
    auto cfg = config::Config::parse(BASE_CFG);
    auto reg = registry::Registry::fromConfig(cfg.value()).value();

    // add cluster
    registry::Cluster c;
    c.name = "extra";
    c.endpoints.push_back("http://127.0.0.1:9002");
    c.credentials.push_back("c");
    CHECK(reg.addCluster(c).ok());
    CHECK(reg.cluster("extra") != nullptr);
    CHECK(!reg.addCluster(c).ok()); // duplicate
    CHECK(reg.updateCluster("extra", c).ok());
    CHECK(reg.removeCluster("extra").ok());
    CHECK(reg.cluster("extra") == nullptr);
    CHECK(!reg.removeCluster("extra").ok());

    // removeCluster in use
    CHECK(!reg.removeCluster("src").ok()); // used by replication r

    // credential
    registry::Credential cr;
    cr.name = "c2";
    cr.accessKey = "AK2";
    cr.secretKey = "SK2";
    CHECK(reg.addCredential(cr).ok());
    CHECK(reg.removeCredential("c2").ok());

    // target
    registry::Target t;
    t.name = "t2";
    t.kind = "null";
    t.uri = "null";
    CHECK(reg.addTarget(t).ok());
    CHECK(reg.removeTarget("t2").ok());

    // bundle
    policy::Bundle b;
    b.name = "custom";
    CHECK(reg.addBundle(b).ok());
    CHECK(!reg.removeBundle("default").ok());
    CHECK(!reg.removeBundle("drop-all").ok());
    CHECK(reg.removeBundle("custom").ok());

    // replication
    registry::Replication r;
    r.name = "r2";
    r.source = "src";
    r.destination = "dst";
    r.policy = "default";
    CHECK(reg.addReplication(r).ok());
    CHECK(reg.removeReplication("r2").ok());
}

TEST(registry_add_rule) {
    auto cfg = config::Config::parse(BASE_CFG);
    auto reg = registry::Registry::fromConfig(cfg.value()).value();
    policy::Rule rule = policy::Rule::parseLine("10 name=r1 object action accept").value();
    CHECK(reg.addRule("default", rule, "", "").ok());
    CHECK(reg.bundle("default")->findRule("r1") != nullptr);
    // duplicate name is rejected
    policy::Rule rule2 = policy::Rule::parseLine("20 name=r1 object action drop").value();
    CHECK(!reg.addRule("default", rule2, "", "").ok());
    // duplicate (unnamed) order is renumbered, not rejected
    policy::Rule rule3 = policy::Rule::parseLine("10 object action accept").value();
    CHECK(reg.addRule("default", rule3, "", "").ok());
    CHECK(reg.removeRule("default", "r1").ok());
}

TEST(registry_builtin_override_via_config) {
    const char* text = R"(
s3mm {
    policy default {
        default_action object drop;
        rule '10 object action accept';
    }
}
)";
    auto cfg = config::Config::parse(text);
    CHECK(cfg);
    auto reg = registry::Registry::fromConfig(cfg.value());
    CHECK(reg);
    CHECK_EQ(reg.value().bundle("default")->defaultAction(Category::Object).name, std::string("drop"));
    CHECK_EQ(reg.value().bundle("default")->rules.size(), 1u);
}
