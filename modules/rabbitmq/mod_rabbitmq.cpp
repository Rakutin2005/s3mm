// s3mme broker module: RabbitMQ (AMQP 0-9-1).
//
// Native publisher over plain TCP — no librabbitmq/AMQPClient dependency, in
// the same self-contained spirit as the S3 client and the Kafka module.
// Implements exactly the frames needed to publish: protocol header,
// Connection.Start/Start-Ok/Tune/Tune-Ok/Open/Open-Ok, Channel.Open/Open-Ok,
// Basic.Qos, Exchange.Declare (optional), Basic.Publish + content frames,
// and reads Basic.Ack when `confirm on`. TLS is not implemented here; run
// behind a stunnel/sidecar or use the kafka module for SASL setups.
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

#include "s3mm/common/log.hpp"
#include "s3mme/broker.hpp"

namespace {

// ------------------------------------------------------------ writers
class Buf {
public:
    void u8(uint8_t v) { b_.push_back((char)v); }
    void u16(uint16_t v) { b_.push_back((char)(v >> 8)); b_.push_back((char)v); }
    void u32(uint32_t v) { for (int i = 3; i >= 0; --i) b_.push_back((char)((v >> (8 * i)) & 0xff)); }
    void u64(uint64_t v) { for (int i = 7; i >= 0; --i) b_.push_back((char)((v >> (8 * i)) & 0xff)); }
    void shortstr(const std::string& s) { u8((uint8_t)s.size()); b_.append(s); }
    void bits(bool first, bool second = false) { u8((first ? 1 : 0) | (second ? 2 : 0)); }
    void raw(const std::string& s) { b_.append(s); }
    const std::string& str() const { return b_; }
};

class Rdr {
public:
    explicit Rdr(std::string s) : b_(std::move(s)), p_(0) {}
    uint8_t u8() { need(1); return (uint8_t)b_[p_++]; }
    uint16_t u16() { uint8_t a = u8(), c = u8(); return (uint16_t)((a << 8) | c); }
    uint32_t u32() { uint32_t v = 0; for (int i = 0; i < 4; ++i) v = (v << 8) | u8(); return v; }
    uint64_t u64() { uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | u8(); return v; }
    std::string shortstr() { size_t n = u8(); need(n); std::string out = b_.substr(p_, n); p_ += n; return out; }
    bool failed_ = false;

private:
    void need(size_t n) { if (p_ + n > b_.size()) { failed_ = true; p_ = b_.size(); } }
    std::string b_;
    size_t p_;
};

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

int tcpConnect(const std::string& host, int port, std::string& err) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        err = "dns: " + host;
        return -1;
    }
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
    if (fd < 0) err = "cannot connect to " + host + ":" + std::to_string(port);
    return fd;
}

// AMQP frame types
constexpr uint8_t FRAME_METHOD = 1, FRAME_HEADER = 2, FRAME_BODY = 3, FRAME_HEARTBEAT = 8, FRAME_END = 206;

// Build a method frame: type(1) channel(2) size(4) payload class+method... end(1)
std::string methodFrame(uint16_t ch, uint16_t cls, uint16_t method, const std::string& args) {
    Buf f;
    f.u8(FRAME_METHOD);
    f.u16(ch);
    f.u32((uint32_t)(args.size() + 4));
    f.u16(cls);
    f.u16(method);
    f.raw(args);
    f.u8(FRAME_END);
    return f.str();
}

class RabbitBroker : public s3mme::IBroker {
public:
    const char* name() const override { return "rabbitmq"; }

    s3mm::Result<void> connect(const s3mm::Value& cfg) override {
        host_ = cfg.getString("host", "localhost");
        port_ = (int)cfg.getInt("port", 5672);
        vhost_ = cfg.getString("vhost", "/");
        user_ = cfg.getString("user", "guest");
        pass_ = cfg.getString("pass", "guest");
        exchange_ = cfg.getString("exchange", "");   // empty => default exchange
        routingKey_ = cfg.getString("routing_key", "s3mm.events");
        declareExchange_ = cfg.getString("declare_exchange") == "on";
        exchangeType_ = cfg.getString("exchange_type", "topic");
        confirm_ = cfg.getString("confirm") == "on";

        std::string err;
        fd_ = tcpConnect(host_, port_, err);
        if (fd_ < 0) return s3mm::Result<void>::failure(err);
        if (!handshake(err)) { ::close(fd_); fd_ = -1; return s3mm::Result<void>::failure(err); }
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
        it.key = routingHint.empty() ? (ev.replication + "." + ev.kind) : routingHint;
        it.value = ev.toJson().toJson(0);
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (queue_.size() > 10000) return s3mm::Result<void>::failure("rabbitmq queue overflow");
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
    struct Item { std::string key, value; };

    // ---------------------------------------------------------- handshake
    bool readFrame(Rdr& body, uint16_t& ch, uint8_t& type, std::string& err) {
        std::string head;
        if (!recvAll(fd_, head, 7)) { err = "frame header lost"; return false; }
        Rdr h(head);
        type = h.u8();
        ch = h.u16();
        uint32_t size = h.u32();
        std::string payload;
        if (!recvAll(fd_, payload, (size_t)size + 1)) { err = "frame body lost"; return false; }
        if ((uint8_t)payload.back() != FRAME_END) { err = "bad frame-end"; return false; }
        payload.pop_back();
        body = Rdr(std::move(payload));
        return true;
    }

    bool expectMethod(uint16_t cls, uint16_t method, std::string& err) {
        for (int guard = 0; guard < 32; ++guard) {
            Rdr body;
            uint16_t ch = 0;
            uint8_t type = 0;
            if (!readFrame(body, ch, type, err)) return false;
            if (type == FRAME_HEARTBEAT) continue;
            if (type != FRAME_METHOD) { err = "unexpected frame type " + std::to_string(type); return false; }
            uint16_t gotCls = body.u16();
            uint16_t gotMth = body.u16();
            if (gotCls == cls && gotMth == method) return true;
            if (gotCls == 2 && gotMth == 10) { err = "connection closed by broker"; return false; } // Close
            // unexpected but tolerable (e.g. Channel.Flow) — keep reading
        }
        err = "too many unexpected frames";
        return false;
    }

    bool handshake(std::string& err) {
        static const char proto[] = {'A', 'M', 'Q', 'P', '\r', '\n', 1, 1};
        std::string hdr(proto, sizeof(proto));
        if (!sendAll(fd_, hdr)) { err = "protocol header send failed"; return false; }

        // Connection.Start (10,10) -> Start-Ok (10,11)
        {
            Rdr body; uint16_t ch; uint8_t type;
            if (!readFrame(body, ch, type, err)) return false;
            if (type != FRAME_METHOD) { err = "expected method frame"; return false; }
            // skip class/method/version/mechanisms/locale — we assume PLAIN is offered
        }
        {
            Buf a;
            a.u32(0);                       // client-properties table size (empty)
            a.shortstr("PLAIN");
            std::string resp;
            resp.push_back('\0'); resp += user_;
            resp.push_back('\0'); resp += pass_;
            a.shortstr(resp);
            a.shortstr("en_US");
            if (!sendAll(fd_, methodFrame(0, 10, 11, a.str()))) { err = "start-ok send failed"; return false; }
        }
        if (!expectMethod(10, 30, err)) return false; // Connection.Tune
        return tuneAndOpen(err);
    }

    bool tuneAndOpen(std::string& err) {
        // We already consumed one frame after Start-Ok via expectMethod; that frame
        // is Tune. Parse nothing from it, just reply with defaults.
        {
            Buf a;
            a.u16(2047);   // channel max
            a.u32(131072); // frame max
            a.u16(60);     // heartbeat sec
            if (!sendAll(fd_, methodFrame(0, 10, 31, a.str()))) { err = "tune-ok send failed"; return false; }
        }
        {
            Buf a;
            a.shortstr(vhost_);
            a.shortstr("");  // capabilities
            a.bits(false);   // insist
            if (!sendAll(fd_, methodFrame(0, 10, 40, a.str()))) { err = "open send failed"; return false; }
        }
        if (!expectMethod(10, 41, err)) return false; // Open-Ok

        // Channel 1
        {
            Buf a;
            a.shortstr("");
            a.bits(false);
            if (!sendAll(fd_, methodFrame(1, 20, 10, a.str()))) { err = "channel.open send failed"; return false; }
        }
        if (!expectMethod(20, 11, err)) return false; // Channel.Open-Ok

        if (confirm_) { // publisher confirms: Confirm.Select (90,5)
            Buf a;
            a.bits(true);
            if (!sendAll(fd_, methodFrame(1, 90, 5, a.str()))) { err = "confirm send failed"; return false; }
            if (!expectMethod(90, 6, err)) return false; // Confirm.Select-Ok
        }

        if (declareExchange_ && !exchange_.empty()) {
            Buf a;
            a.u16(0);                 // reserved ticket
            a.shortstr(exchange_);
            a.shortstr(exchangeType_);
            a.u8(0x02);               // bits: passive|durable|auto-delete|internal|nowait -> durable
            a.u32(0);                 // arguments table (empty)
            if (!sendAll(fd_, methodFrame(1, 40, 10, a.str()))) { err = "exchange.declare send failed"; return false; }
            if (!expectMethod(40, 11, err)) return false; // Declare-Ok
        }
        return true;
    }

    // ---------------------------------------------------------- publishing
    bool publishOne(const Item& it, std::string& err) {
        if (fd_ < 0) { err = "not connected"; return false; }
        {
            Buf a;
            a.u16(0);                    // reserved ticket
            a.shortstr(exchange_);
            a.shortstr(it.key);          // routing key
            a.bits(false, false);        // mandatory, immediate
            if (!sendAll(fd_, methodFrame(1, 60, 40, a.str()))) { err = "basic.publish send failed"; return false; }
        }
        {
            // ContentHeader: class 60, weight 0, body size, flags none, priority/delivery/expires/type/user/id all absent
            Buf f;
            // property flags bitmap: contentType(bit15)=present, everything else absent
            uint16_t flags = 0x8000; // content-type present
            f.u16(60);               // class id
            f.u16(0);                // weight
            f.u64(it.value.size());  // body size
            f.u16(flags);
            f.shortstr("application/json");
            // remaining property fields absent per bitmap
            Buf hf;
            hf.u8(FRAME_HEADER);
            hf.u16(1);
            hf.u32((uint32_t)f.size());
            hf.raw(f.str());
            hf.u8(FRAME_END);
            if (!sendAll(fd_, hf.str())) { err = "header frame send failed"; return false; }
        }
        {
            Buf bf;
            bf.u8(FRAME_BODY);
            bf.u16(1);
            bf.u32((uint32_t)it.value.size());
            bf.raw(it.value);
            bf.u8(FRAME_END);
            if (!sendAll(fd_, bf.str())) { err = "body frame send failed"; return false; }
        }
        if (confirm_) {
            Rdr body; uint16_t ch; uint8_t type;
            if (!readFrame(body, ch, type, err)) return false;
            if (type == FRAME_METHOD) {
                uint16_t cls = body.u16();
                uint16_t mth = body.u16();
                if (cls == 60 && mth == 32) return true;  // Basic.Ack
                if (cls == 60 && mth == 31) { err = "basic.nack from broker"; return false; }
                if (cls == 60 && mth == 30) return true;  // Basic.Return (undeliverable) — soft
            }
        }
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
            if (!publishOne(it, err)) {
                LOG_WARN("rabbitmq publish failed: ", err, " (reconnecting)");
                reconnect();
            }
        }
    }

    void reconnect() {
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        std::string err;
        fd_ = tcpConnect(host_, port_, err);
        if (fd_ >= 0 && handshake(err)) return;
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

    std::string host_, vhost_, user_, pass_, exchange_, exchangeType_, routingKey_;
    int port_ = 5672;
    bool declareExchange_ = false, confirm_ = false;
    int fd_ = -1;
    std::atomic<bool> running_{false};
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Item> queue_;
    std::thread worker_;
};

} // namespace

S3MME_BROKER_ENTRY(RabbitBroker)
