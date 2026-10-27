#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "s3mm/common/fs.hpp"
#include "s3mm/config/config.hpp"
#include "testkit.hpp"

using namespace s3mm;

TEST(config_parse_basic) {
    const char* text = R"(
# top-level comment
s3mm {
    socket /run/s3mm/s3mm.sock; // trailing
    worker_count 4;
    log {
        level info;
        facility daemon;
        socket /dev/log;
    }
    cluster src {
        addr http://127.0.0.1:9000;
        alias source;
    }
}
)";
    auto cfg = config::Config::parse(text);
    CHECK(cfg);
    CHECK(cfg.value().s3mm() != nullptr);
    const auto* root = cfg.value().s3mm();
    CHECK_EQ(root->value("socket"), std::string("/run/s3mm/s3mm.sock"));
    CHECK_EQ(root->int64Value("worker_count", 0), 4);
    const config::Node* log = root->find("log");
    CHECK(log != nullptr);
    CHECK_EQ(log->value("level"), std::string("info"));
    CHECK_EQ(log->value("facility"), std::string("daemon"));
    const config::Node* cluster = root->find("cluster");
    CHECK(cluster != nullptr);
    CHECK_EQ(cluster->argOr(0), std::string("src"));
    CHECK_EQ(cluster->value("addr"), std::string("http://127.0.0.1:9000"));
}

TEST(config_quoted_args) {
    const char* text = R"(
s3mm {
    cluster c {
        alias "my cluster";
        description 'has spaces and; semicolons';
    }
}
)";
    auto cfg = config::Config::parse(text);
    CHECK(cfg);
    const auto* c = cfg.value().s3mm()->find("cluster");
    CHECK(c != nullptr);
    CHECK_EQ(c->value("alias"), std::string("my cluster"));
    CHECK_EQ(c->value("description"), std::string("has spaces and; semicolons"));
}

TEST(config_errors) {
    CHECK(!config::Config::parse("s3mm { socket x ").ok());
    CHECK(!config::Config::parse("s3mm { socket x;").ok()); // missing closing brace
    CHECK(!config::Config::parse("s3mm { socket \"unterminated; }").ok());
    CHECK(!config::Config::parse("s3mm { socket x; extra y z }").ok()); // neither ; nor { after extra? actually "extra y z" then } -> ';' or '{' expected
}

TEST(config_include) {
    const std::string dir = "/tmp/opencode/cfgtest";
    fs::removeTree(dir);
    fs::mkdirp(dir + "/frag");
    fs::writeFileAtomic(dir + "/frag/a.conf", "cluster a { addr http://127.0.0.1:9001; }\n");
    fs::writeFileAtomic(dir + "/frag/b.conf", "cluster b { addr http://127.0.0.1:9002; }\n");
    std::string main = "s3mm {\n  include frag/*.conf;\n}\n";
    fs::writeFileAtomic(dir + "/main.conf", main);

    auto cfg = config::Config::load(dir + "/main.conf");
    CHECK(cfg);
    std::vector<std::string> names;
    for (const auto& c : cfg.value().s3mm()->children)
        if (c.name == "cluster") names.push_back(c.argOr(0));
    CHECK_EQ(names.size(), 2u);
    CHECK(std::find(names.begin(), names.end(), "a") != names.end());
    CHECK(std::find(names.begin(), names.end(), "b") != names.end());

    // include cycle detection
    fs::writeFileAtomic(dir + "/a.conf", "s3mm { include b.conf; }\n");
    fs::writeFileAtomic(dir + "/b.conf", "s3mm { include a.conf; }\n");
    auto c2 = config::Config::load(dir + "/a.conf");
    CHECK(!c2);
    CHECK(c2.error().find("cycle") != std::string::npos);
}

TEST(config_validate) {
    const char* bad = R"(
s3mm {
    cluster src { addr http://x; credential ghost; }
    replication r { source src; destination dst; }
}
)";
    auto cfg = config::Config::parse(bad);
    CHECK(cfg);
    auto errs = cfg.value().validate();
    CHECK(!errs.empty()); // unknown cluster 'dst', unknown credential 'ghost'
    const char* good = R"(
s3mm {
    cluster src { addr http://x; credential c; }
    cluster dst { addr http://y; credential c; }
    credential c { access_key a; secret_key s; }
    replication r { source src; destination dst; }
}
)";
    auto cfg2 = config::Config::parse(good);
    CHECK(cfg2);
    CHECK(cfg2.value().validate().empty());
}

TEST(config_dump_roundtrip) {
    const char* text = "s3mm {\n  socket /tmp/x.sock;\n  worker_count 2;\n}\n";
    auto cfg = config::Config::parse(text);
    CHECK(cfg);
    std::string dumped = cfg.value().dump();
    auto cfg2 = config::Config::parse(dumped);
    CHECK(cfg2);
    CHECK_EQ(cfg2.value().s3mm()->value("socket"), std::string("/tmp/x.sock"));
    CHECK_EQ(cfg2.value().s3mm()->int64Value("worker_count", 0), 2);
}

TEST(config_top_level_block_rejected) {
    const char* text = R"(
cluster outside { addr http://x; }
s3mm {
    socket /tmp/s.sock;
}
)";
    auto cfg = config::Config::parse(text);
    CHECK(cfg);
    auto errs = cfg.value().validate();
    CHECK(!errs.empty());
    bool found = false;
    for (const auto& e : errs) found = found || e.find("outside") != std::string::npos;
    CHECK(found);
}

TEST(config_validate_without_wrapper) {
    const char* text = R"(
cluster src { addr http://x; credential c; }
cluster dst { addr http://y; credential c; }
credential c { access_key a; secret_key s; }
replication r { source src; destination dst; }
)";
    auto cfg = config::Config::parse(text, "wrapperless.conf");
    CHECK(cfg);
    CHECK(cfg.value().s3mm() != nullptr);
    CHECK(cfg.value().validate().empty());

    const char* bad = "cluster src { addr http://x; }\nreplication r { source src; destination ghost; }\n";
    auto cfg2 = config::Config::parse(bad, "wrapperless-bad.conf");
    CHECK(cfg2);
    CHECK(!cfg2.value().validate().empty()); // unknown cluster 'ghost'
}

TEST(config_validate_include_matched_nothing) {
    // wrapper-less entry point whose drop-in glob matches no files
    const std::string dir = "/tmp/opencode/cfgtest-empty";
    fs::removeTree(dir);
    fs::mkdirp(dir + "/conf.d");
    fs::writeFileAtomic(dir + "/main.conf", "# entry point\ninclude conf.d/*.conf;\n");
    auto cfg = config::Config::load(dir + "/main.conf");
    CHECK(cfg);
    CHECK(cfg.value().validate().empty());

    fs::writeFileAtomic(dir + "/conf.d/00-core.conf", "socket /tmp/s.sock;\n");
    auto cfg2 = config::Config::load(dir + "/main.conf");
    CHECK(cfg2);
    CHECK(cfg2.value().validate().empty());
    CHECK_EQ(cfg2.value().s3mm()->value("socket"), std::string("/tmp/s.sock"));
}
