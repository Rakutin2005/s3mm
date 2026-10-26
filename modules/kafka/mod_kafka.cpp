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
    void varstr(const std::string& s) { uvarint((uint64_t)s.size()); b_.append(s); }
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
        if (n <= 0) return false;
        off += (size_t)n;
    }
    return true;
}

bool recvAll(int fd, std::string& out, size_t want) {
    out.clear();
    char chunk[8192];
    while (out.size() < want) {
        ssize_t n = ::recv(fd, chunk, sizeof(chunk), 0);
        if (n <= 0) return false;
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
        if (::getaddrinfo(h.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) continue;
        int fd = -1;
        for (addrinfo* ai = res; ai; ai = ai->ai_next) {
            fd = ::socket(ai->ai_family, ai->ai_socktype, 0);
            if (fd < 0) continue;
            timeval tv{10, 0};
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
            ::close(fd);
            fd = -1;
        }
        ::freeaddrinfo(res);
        if (fd >= 0) return fd;
        err = "cannot connect to " + hp;
    }
    return -1;
}


struct Reply { int32_t correlation = 0; std::string body; };

bool roundTrip(int fd, int16_t apiKey, int16_t apiVersion, const std::string& body, Reply& out, std::string& err) {
    static std::atomic<int32_t> corrSeq{1};
    int32_t corr = corrSeq.fetch_add(1);
    Buf h;
    h.i16(apiKey);
    h.i16(apiVersion);
    h.i32(corr);
    h.nullableString("s3mme");
    std::string payload = h.str() + body;
    Buf framed;
    framed.i32((int32_t)payload.size());
    framed.raw(payload);
    if (!sendAll(fd, framed.str())) { err = "send failed (broker down?)"; return false; }
    std::string head;
    if (!recvAll(fd, head, 4)) { err = "recv header failed"; return false; }
    Rdr hr(head);
    int32_t sz = hr.i32();
    if (sz <= 0 || sz > 64 * 1024 * 1024) { err = "bad frame size"; return false; }
    std::string raw;
    if (!recvAll(fd, raw, (size_t)sz)) { err = "recv body failed"; return false; }
    Rdr r(raw);
    out.correlation = r.i32();
    if (out.correlation != corr) { err = "correlation mismatch"; return false; }
    out.body = raw.substr(4);
    return true;
}

// ------------------------------------------------------------ record batch v2
std::string encodeBatchV2(int64_t nowMs, const std::string& key, const std::string& value) {
    Buf rec;
    rec.i8(0);              // record attributes
    rec.i64(0);             // timestamp delta
    rec.zigzag(0);          // offset delta
    if (key.empty()) { rec.uvarint(1); rec.i8((int8_t)0xFF); } else { rec.varstr(key); }
    rec.varstr(value);
    rec.uvarint(0);         // header count

    Buf afterCrc;
    afterCrc.i8(0);                       // batch attributes (no compression, delta timestamps)
    afterCrc.i32(0);                      // last offset delta
    afterCrc.i64(nowMs);                  // first timestamp
    afterCrc.i64(-1);                     // max timestamp
    afterCrc.i64(0);                      // producer id
    afterCrc.i16(-1);                     // producer epoch
    afterCrc.i32(0);                      // base sequence
    afterCrc.zigzag(1);                   // record count
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
        hosts_ = cfg.getString("hosts", "localhost:9092");
        topic_ = cfg.getString("topic", "s3mm.events");
        std::string err;
        fd_ = tcpConnect(hosts_, err);
        if (fd_ < 0) return s3mm::Result<void>::failure(err);
        if (cfg.getString("sasl") == "on") {
            std::string user = cfg.getString("sasl_user"), pass = cfg.getString("sasl_pass");
            if (!saslPlain(user, pass, err)) { ::close(fd_); fd_ = -1; return s3mm::Result<void>::failure(err); }
        }
        running_ = true;
        worker_ = std::thread([this] { loop(); });
        return s3mm::Result<void>::success();
    }

    void disconnect() override {
        running_ = false;
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

    s3mm::Result<void> publish(const s3mme::Event& ev, const std::string& routingHint) override {
        Item it;
        it.topic = routingHint.empty() ? topic_ : routingHint;
        it.key = ev.replication + "/" + ev.kind;
        it.value = ev.toJson().toJson(0);
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (queue_.size() > 10000) return s3mm::Result<void>::failure("kafka queue overflow");
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
        return s3mm::Result<void>::failure("flush timeout");
    }

private:
    struct Item { std::string topic, key, value; };

    bool saslPlain(const std::string& user, const std::string& pass, std::string& err) {
        Buf req;
        req.nullableString("PLAIN");
        Reply rep;
        if (!roundTrip(fd_, 17, 1, req.str(), rep, err)) return false;
        Rdr r(rep.body);
        int16_t code = r.i16();
        if (code != 0) { err = "sasl handshake error code " + std::to_string(code); return false; }
        std::string auth;
        auth.push_back('\0');
        auth += user;
        auth.push_back('\0');
        auth += pass;
        Buf req2;
        req2.bytes(auth);
        Reply rep2;
        if (!roundTrip(fd_, 36, 0, req2.str(), rep2, err)) return false;
        Rdr r2(rep2.body);
        int16_t code2 = r2.i16();
        if (code2 != 0) { err = "sasl authenticate failed: " + r2.str16(); return false; }
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
            if (!produce(it.topic, it.key, it.value, err)) {
                LOG_WARN("kafka produce failed: ", err, " (reconnecting)");
                reconnect();
            }
        }
    }

    void reconnect() {
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        std::string err;
        fd_ = tcpConnect(hosts_, err);
    }

    bool produce(const std::string& topic, const std::string& key, const std::string& value, std::string& err) {
        if (fd_ < 0) { err = "not connected"; return false; }
        int64_t now = (int64_t)time(nullptr) * 1000;
        std::string batch = encodeBatchV2(now, key, value);
        Buf req;
        req.nullableString("");   // transactional id
        req.i16(1);               // acks = leader
        req.i32(5000);            // timeout ms
        req.i16(1);               // topic array
        req.nullableString(topic);
        req.i16(1);               // partition array
        req.i32(0);               // partition 0
        req.bytes(batch);
        Reply rep;
        if (!roundTrip(fd_, 0, 3, req.str(), rep, err)) return false;
        Rdr r(rep.body);
        r.i32();                  // throttle time
        if (r.i16() < 1) { err = "bad produce reply"; return false; }
        r.str16();                // topic
        if (r.i16() < 1) { err = "bad produce reply"; return false; }
        r.i32();                  // partition
        int16_t code = r.i16();
        if (code != 0) { err = "produce error code " + std::to_string(code); return false; }
        return true;
    }

    std::string hosts_, topic_;
    int fd_ = -1;
    std::atomic<bool> running_{false};
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Item> queue_;
    std::thread worker_;
};

} // namespace

S3MME_BROKER_ENTRY(KafkaBroker)
