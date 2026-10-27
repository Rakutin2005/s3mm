// s3mme broker module: Apache Kafka.
//
// Native producer over plain TCP using the Kafka wire protocol directly —
// no librdkafka dependency (keeps the project self-contained like the S3
// client). Supported: PLAINTEXT and SASL/PLAIN (`sasl on; sasl_user ...`).
// Produce v3 with a single record per batch (magic v2, CRC32C from zlib is
// NOT usable here — Kafka batches use CRC-32C Castagnoli, implemented below).
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <ctime>

#include "s3mm/common/log.hpp"
#include "s3mme/broker.hpp"

namespace {
namespace log = s3mm::log;

static std::string getCfgString(const s3mm::Value& cfg, const char* key, const std::string& def = {}) {
    if (auto* v = cfg.find(key)) return v->asString(def);
    return def;
}

const char* apiName(int16_t k) {
    switch (k) {
        case 0: return "Produce";
        case 17: return "SaslHandshake";
        case 36: return "SaslAuthenticate";
        default: return "api";
    }
}

// ------------------------------------------------------------ crc32c
uint32_t crc32c(const void* data, size_t len) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (c >> 1) ^ 0x82F63B78u : c >> 1;
            table[i] = c;
        }
        init = true;
    }
    const uint8_t* p = (const uint8_t*)data;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ------------------------------------------------------------ byte writer
class Buf {
public:
    void i8(int8_t v) { b_.push_back((char)v); }
    void i16(int16_t v) { be((uint32_t)v, 2); }
    void i32(int32_t v) { be((uint32_t)v, 4); }
    void i64(int64_t v) { be((uint64_t)v, 8); }
    void uvarint(uint64_t v) { do { char c = (char)((v & 0x7f) | ((v >> 7) ? 0x80 : 0)); v >>= 7; b_.push_back(c); } while (v); }
    void zigzag(int64_t v) { uvarint(((uint64_t)v << 1) ^ (uint64_t)(v >> 63)); }
    void raw(const std::string& s) { b_.append(s); }
    void bytes(const std::string& s) { i32((int32_t)s.size()); b_.append(s); }
    void nullableString(const std::string& s) { if (s.empty()) i16(-1); else { i16((int16_t)s.size()); b_.append(s); } }
    void string(const std::string& s) { i16((int16_t)s.size()); b_.append(s); }
    void varstr(const std::string& s) { zigzag((int64_t)s.size()); b_.append(s); }
    const std::string& str() const { return b_; }
    size_t size() const { return b_.size(); }

private:
    void be(uint64_t v, int n) { for (int i = n - 1; i >= 0; --i) b_.push_back((char)((v >> (8 * i)) & 0xff)); }
    std::string b_;
};

// ------------------------------------------------------------ byte reader
class Rdr {
public:
    explicit Rdr(std::string s) : b_(std::move(s)), p_(0) {}
    int8_t i8() { need(1); return (int8_t)b_[p_++]; }
    int16_t i16() { return (int16_t)be(2); }
    int32_t i32() { return (int32_t)be(4); }
    int64_t i64() { return (int64_t)be(8); }
    std::string str16() {
        int16_t n = i16();
        if (n < 0 || failed_) return {};
        need((size_t)n);
        std::string out = b_.substr(p_, (size_t)n);
        p_ += (size_t)n;
        return out;
    }
    uint64_t uvarint() {
        uint64_t v = 0; int sh = 0;
        while (true) { char c = i8(); v |= (uint64_t)((uint8_t)c & 0x7f) << sh; if (!((uint8_t)c & 0x80)) break; sh += 7; }
        return v;
    }
    bool failed_ = false;

private:
    uint64_t be(int n) { uint64_t v = 0; for (int i = 0; i < n; ++i) v = (v << 8) | (uint8_t)i8(); return v; }
    void need(size_t n) { if (p_ + n > b_.size()) { failed_ = true; p_ = b_.size(); } }
    std::string b_;
    size_t p_;
};

// ------------------------------------------------------------ socket io
bool sendAll(int fd, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n <= 0) { LOG_ERROR("kafka: send on fd ", fd, " failed after ", off, "/", data.size(), " bytes: ", n < 0 ? std::strerror(errno) : "connection closed"); return false; }
        off += (size_t)n;
    }
    return true;
}

bool recvAll(int fd, std::string& out, size_t want) {
    out.clear();
    char chunk[8192];
    while (out.size() < want) {
        ssize_t n = ::recv(fd, chunk, std::min(sizeof(chunk), want - out.size()), 0);
        if (n <= 0) { LOG_ERROR("kafka: recv on fd ", fd, " failed after ", out.size(), "/", want, " bytes: ", n < 0 ? std::strerror(errno) : "connection closed by broker"); return false; }
        out.append(chunk, (size_t)n);
    }
    return true;
}

int tcpConnect(const std::string& hostList, std::string& err) {
    // hostList: "host:port" or comma-separated list; use the first reachable.
    size_t pos = 0;
    while (pos <= hostList.size()) {
        size_t comma = hostList.find(',', pos);
        if (comma == std::string::npos) comma = hostList.size();
        std::string hp = hostList.substr(pos, comma - pos);
        pos = comma + (comma == hostList.size() ? 1 : 1);
        auto colon = hp.rfind(':');
        std::string h = colon == std::string::npos ? hp : hp.substr(0, colon);
        int port = colon == std::string::npos ? 9092 : std::atoi(hp.c_str() + colon + 1);
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        LOG_DEBUG("kafka: resolving ", h, ":", port);
        if (int rc = ::getaddrinfo(h.c_str(), std::to_string(port).c_str(), &hints, &res); rc != 0) {
            LOG_ERROR("kafka: cannot resolve ", h, ": ", gai_strerror(rc));
            continue;
        }
        int fd = -1;
        for (addrinfo* ai = res; ai; ai = ai->ai_next) {
            fd = ::socket(ai->ai_family, ai->ai_socktype, 0);
            if (fd < 0) { LOG_ERROR("kafka: socket() failed: ", std::strerror(errno)); continue; }
            timeval tv{10, 0};
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            LOG_DEBUG("kafka: connecting to ", hp, " (family ", ai->ai_family, ")");
            if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
            LOG_WARN("kafka: connect to ", hp, " failed: ", std::strerror(errno));
            ::close(fd);
            fd = -1;
        }
        ::freeaddrinfo(res);
        if (fd >= 0) { LOG_INFO("kafka: connected to ", hp, " (fd ", fd, ")"); return fd; }
        err = "cannot connect to " + hp;
        LOG_ERROR("kafka: ", err);
    }
    return -1;
}


struct Reply { int32_t correlation = 0; std::string body; };

bool roundTrip(int fd, int16_t apiKey, int16_t apiVersion, const std::string& body, Reply& out, std::string& err) {
    static std::atomic<int32_t> corrSeq{1};
    int32_t corr = corrSeq.fetch_add(1);
    log::Stopwatch sw;
    Buf h;
    h.i16(apiKey);
    h.i16(apiVersion);
    h.i32(corr);
    h.nullableString("s3mme");
    std::string payload = h.str() + body;
    Buf framed;
    framed.i32((int32_t)payload.size());
    framed.raw(payload);
    LOG_DEBUG("kafka: -> ", apiName(apiKey), " v", apiVersion, " corr=", corr, " ", framed.size(), " bytes");
    if (!sendAll(fd, framed.str())) { err = "send failed (broker down?)"; LOG_ERROR("kafka: ", apiName(apiKey), ": ", err); return false; }
    std::string head;
    if (!recvAll(fd, head, 4)) { err = "recv header failed"; LOG_ERROR("kafka: ", apiName(apiKey), ": ", err); return false; }
    Rdr hr(head);
    int32_t sz = hr.i32();
    if (sz <= 0 || sz > 64 * 1024 * 1024) { err = "bad frame size"; LOG_ERROR("kafka: ", apiName(apiKey), ": bad response frame size ", sz); return false; }
    std::string raw;
    if (!recvAll(fd, raw, (size_t)sz)) { err = "recv body failed"; LOG_ERROR("kafka: ", apiName(apiKey), ": ", err, " (", sz, " bytes expected)"); return false; }
    Rdr r(raw);
    out.correlation = r.i32();
    if (out.correlation != corr) {
        err = "correlation mismatch";
        LOG_ERROR("kafka: ", apiName(apiKey), ": correlation mismatch (sent ", corr, ", got ", out.correlation, ")");
        return false;
    }
    out.body = raw.substr(4);
    LOG_DEBUG("kafka: <- ", apiName(apiKey), " corr=", corr, " ", sz, " bytes in ", sw.ms(), " ms");
    return true;
}

// ------------------------------------------------------------ record batch v2
std::string encodeBatchV2(int64_t nowMs, const std::string& key, const std::string& value) {
    Buf body;
    body.i8(0);             // record attributes
    body.zigzag(0);         // timestamp delta (varlong)
    body.zigzag(0);         // offset delta
    if (key.empty()) body.zigzag(-1); else body.varstr(key);
    body.varstr(value);
    body.zigzag(0);         // header count
    Buf rec;
    rec.zigzag((int64_t)body.size()); // record length
    rec.raw(body.str());

    Buf afterCrc;
    afterCrc.i16(0);                      // batch attributes (no compression, create time)
    afterCrc.i32(0);                      // last offset delta
    afterCrc.i64(nowMs);                  // first timestamp
    afterCrc.i64(nowMs);                  // max timestamp
    afterCrc.i64(-1);                     // producer id (none)
    afterCrc.i16(-1);                     // producer epoch
    afterCrc.i32(-1);                     // base sequence
    afterCrc.i32(1);                      // record count
    afterCrc.raw(rec.str());              // records

    uint32_t crc = crc32c(afterCrc.str().data(), afterCrc.str().size());

    Buf batch;
    batch.i64(0);                         // base offset
    batch.i32((int32_t)(4 + 1 + 4 + afterCrc.size())); // length
    batch.i32(0);                         // partition leader epoch
    batch.i8(2);                          // magic
    batch.i32((int32_t)crc);
    batch.raw(afterCrc.str());
    return batch.str();
}

class KafkaBroker : public s3mme::IBroker {
public:
    const char* name() const override { return "kafka"; }

    s3mm::Result<void> connect(const s3mm::Value& cfg) override {
        hosts_ = getCfgString(cfg, "hosts", "localhost:9092");
        topic_ = getCfgString(cfg, "topic", "s3mm.events");
        sasl_ = getCfgString(cfg, "sasl") == "on";
        saslUser_ = getCfgString(cfg, "sasl_user");
        saslPass_ = getCfgString(cfg, "sasl_pass");
        LOG_DEBUG("kafka: connect hosts=", hosts_, " topic=", topic_, " sasl=", sasl_ ? "on" : "off");
        std::string err;
        fd_ = tcpConnect(hosts_, err);
        if (fd_ < 0) { LOG_ERROR("kafka: no reachable broker in ", hosts_, ": ", err); return s3mm::Result<void>::failure(err); }
        if (sasl_ && !saslPlain(saslUser_, saslPass_, err)) { ::close(fd_); fd_ = -1; return s3mm::Result<void>::failure(err); }
        running_ = true;
        worker_ = std::thread([this] { loop(); });
        LOG_INFO("kafka: producer ready (hosts ", hosts_, ", default topic ", topic_, ")");
        return s3mm::Result<void>::success();
    }

    void disconnect() override {
        LOG_DEBUG("kafka: disconnecting");
        running_ = false;
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        LOG_INFO("kafka: disconnected from ", hosts_);
    }

    s3mm::Result<void> publish(const s3mme::Event& ev, const std::string& routingHint) override {
        Item it;
        it.id = ev.id;
        it.topic = routingHint.empty() ? topic_ : routingHint;
        it.key = ev.replication + "/" + ev.kind;
        it.value = ev.toJson().toJson(0);
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (queue_.size() > 10000) {
                LOG_ERROR("kafka: queue overflow (", queue_.size(), " pending), event ", ev.id, " rejected");
                return s3mm::Result<void>::failure("kafka queue overflow");
            }
            LOG_DEBUG("kafka: queued event ", ev.id, " topic=", it.topic, " key=", it.key, " ", it.value.size(),
                      " bytes (", queue_.size() + 1, " pending)");
            queue_.push_back(std::move(it));
        }
        cv_.notify_one();
        return s3mm::Result<void>::success();
    }

    s3mm::Result<void> flush() override {
        for (int i = 0; i < 100; ++i) {
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (queue_.empty()) return s3mm::Result<void>::success();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        size_t left;
        { std::lock_guard<std::mutex> lk(mu_); left = queue_.size(); }
        LOG_WARN("kafka: flush timed out with ", left, " message(s) pending");
        return s3mm::Result<void>::failure("flush timeout");
    }

private:
    struct Item { std::string id, topic, key, value; int attempts = 0; };
    static constexpr int kMaxAttempts = 3;

    bool saslPlain(const std::string& user, const std::string& pass, std::string& err) {
        LOG_DEBUG("kafka: SASL/PLAIN handshake as user '", user, "' (password ", log::redact(pass), ")");
        Buf req;
        req.nullableString("PLAIN");
        Reply rep;
        if (!roundTrip(fd_, 17, 1, req.str(), rep, err)) { LOG_ERROR("kafka: SASL handshake failed: ", err); return false; }
        Rdr r(rep.body);
        int16_t code = r.i16();
        if (code != 0) { err = "sasl handshake error code " + std::to_string(code); LOG_ERROR("kafka: ", err); return false; }
        LOG_DEBUG("kafka: SASL handshake ok, mechanism PLAIN accepted");
        std::string auth;
        auth.push_back('\0');
        auth += user;
        auth.push_back('\0');
        auth += pass;
        Buf req2;
        req2.bytes(auth);
        Reply rep2;
        if (!roundTrip(fd_, 36, 0, req2.str(), rep2, err)) { LOG_ERROR("kafka: SASL authenticate failed: ", err); return false; }
        Rdr r2(rep2.body);
        int16_t code2 = r2.i16();
        if (code2 != 0) {
            err = "sasl authenticate failed: " + r2.str16();
            LOG_ERROR("kafka: SASL authentication of user '", user, "' rejected (code ", code2, "): ", err);
            return false;
        }
        LOG_INFO("kafka: SASL/PLAIN authenticated as '", user, "'");
        return true;
    }

    void loop() {
        while (running_) {
            Item it;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait_for(lk, std::chrono::seconds(1), [this] { return !queue_.empty() || !running_; });
                if (!running_ && queue_.empty()) return;
                if (queue_.empty()) continue;
                it = queue_.front();
                queue_.pop_front();
            }
            std::string err;
            log::Stopwatch sw;
            if (!produce(it.topic, it.key, it.value, err)) {
                if (++it.attempts < kMaxAttempts) {
                    LOG_WARN("kafka: produce of event ", it.id, " to ", it.topic, " key=", it.key, " (", it.value.size(),
                             " bytes) failed after ", sw.ms(), " ms: ", err, "; attempt ", it.attempts, "/", kMaxAttempts,
                             ", requeued, reconnecting");
                    std::lock_guard<std::mutex> lk(mu_);
                    queue_.push_front(it);
                } else {
                    LOG_ERROR("kafka: produce of event ", it.id, " to ", it.topic, " key=", it.key, " (", it.value.size(),
                              " bytes) failed after ", it.attempts, " attempt(s): ", err, "; message dropped, reconnecting");
                }
                reconnect();
                if (fd_ < 0 && running_) {
                    std::unique_lock<std::mutex> lk(mu_);
                    cv_.wait_for(lk, std::chrono::seconds(1), [this] { return !running_.load(); });
                }
            } else {
                LOG_INFO("kafka: published event ", it.id, " (", it.value.size(), " bytes) to ", it.topic, " key=", it.key, " in ", sw.ms(), " ms");
            }
        }
    }

    void reconnect() {
        LOG_WARN("kafka: reconnecting to ", hosts_);
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        std::string err;
        fd_ = tcpConnect(hosts_, err);
        if (fd_ >= 0 && sasl_ && !saslPlain(saslUser_, saslPass_, err)) { ::close(fd_); fd_ = -1; }
        if (fd_ < 0) LOG_ERROR("kafka: reconnect to ", hosts_, " failed: ", err);
        else LOG_NOTICE("kafka: reconnected to ", hosts_);
    }

    bool produce(const std::string& topic, const std::string& key, const std::string& value, std::string& err) {
        if (fd_ < 0) { err = "not connected"; return false; }
        LOG_DEBUG("kafka: produce topic=", topic, " partition=0 key=", key, " value ", value.size(), " bytes");
        int64_t now = (int64_t)time(nullptr) * 1000;
        std::string batch = encodeBatchV2(now, key, value);
        Buf req;
        req.nullableString("");   // transactional id
        req.i16(1);               // acks = leader
        req.i32(5000);            // timeout ms
        req.i32(1);               // topic array
        req.string(topic);
        req.i32(1);               // partition array
        req.i32(0);               // partition 0
        req.bytes(batch);
        Reply rep;
        if (!roundTrip(fd_, 0, 3, req.str(), rep, err)) return false;
        Rdr r(rep.body);
        if (r.i32() < 1 || r.failed_) { err = "bad produce reply"; LOG_ERROR("kafka: produce: empty topic array in reply (", rep.body.size(), " bytes)"); return false; }
        r.str16();                // topic
        if (r.i32() < 1 || r.failed_) { err = "bad produce reply"; LOG_ERROR("kafka: produce: empty partition array in reply"); return false; }
        r.i32();                  // partition
        int16_t code = r.i16();
        int64_t offset = r.i64(); // base offset
        r.i64();                  // log append time
        if (r.failed_) { err = "truncated produce reply"; LOG_ERROR("kafka: produce: truncated reply (", rep.body.size(), " bytes)"); return false; }
        if (code != 0) { err = "produce error code " + std::to_string(code); LOG_ERROR("kafka: broker returned error code ", code, " for topic ", topic); return false; }
        int32_t throttle = r.i32(); // throttle time (last in v3)
        LOG_DEBUG("kafka: produce ok topic=", topic, " partition=0 offset=", offset, " throttle=", throttle, " ms");
        return true;
    }

    std::string hosts_, topic_, saslUser_, saslPass_;
    bool sasl_ = false;
    int fd_ = -1;
    std::atomic<bool> running_{false};
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Item> queue_;
    std::thread worker_;
};

} // namespace

S3MME_BROKER_ENTRY(KafkaBroker)
