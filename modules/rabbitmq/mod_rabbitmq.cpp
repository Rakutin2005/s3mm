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

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

#include "s3mm/common/log.hpp"
#include "s3mme/broker.hpp"

namespace {
namespace log = s3mm::log;

static std::string getCfgString(const s3mm::Value& cfg, const char* key, const std::string& def = {}) {
    if (auto* v = cfg.find(key)) return v->asString(def);
    return def;
}
static int getCfgInt(const s3mm::Value& cfg, const char* key, int def = 0) {
    auto* v = cfg.find(key);
    if (!v) return def;
    if (!v->isString()) return (int)v->asInt(def);
    const std::string& s = v->asString();
    char* end = nullptr;
    errno = 0;
    long n = s.empty() ? 0 : std::strtol(s.c_str(), &end, 10);
    if (s.empty() || *end != '\0' || errno != 0) {
        LOG_WARN("rabbitmq: invalid integer '", s, "' for ", key, ", using ", def);
        return def;
    }
    return (int)n;
}

// ------------------------------------------------------------ writers
class Buf {
public:
    void u8(uint8_t v) { b_.push_back((char)v); }
    void u16(uint16_t v) { b_.push_back((char)(v >> 8)); b_.push_back((char)v); }
    void u32(uint32_t v) { for (int i = 3; i >= 0; --i) b_.push_back((char)((v >> (8 * i)) & 0xff)); }
    void u64(uint64_t v) { for (int i = 7; i >= 0; --i) b_.push_back((char)((v >> (8 * i)) & 0xff)); }
    void shortstr(const std::string& s) { u8((uint8_t)s.size()); b_.append(s); }
    void longstr(const std::string& s) { u32((uint32_t)s.size()); b_.append(s); }
    void bits(bool first, bool second = false) { u8((first ? 1 : 0) | (second ? 2 : 0)); }
    void raw(const std::string& s) { b_.append(s); }
    const std::string& str() const { return b_; }
    size_t size() const { return b_.size(); }
private:
    std::string b_;
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
        if (n <= 0) { LOG_ERROR("rabbitmq: send on fd ", fd, " failed after ", off, "/", data.size(), " bytes: ", n < 0 ? std::strerror(errno) : "connection closed"); return false; }
        off += (size_t)n;
    }
    return true;
}

bool recvAll(int fd, std::string& out, size_t want) {
    out.clear();
    char chunk[8192];
    while (out.size() < want) {
        ssize_t n = ::recv(fd, chunk, std::min(sizeof(chunk), want - out.size()), 0);
        if (n <= 0) { LOG_ERROR("rabbitmq: recv on fd ", fd, " failed after ", out.size(), "/", want, " bytes: ", n < 0 ? std::strerror(errno) : "connection closed by broker"); return false; }
        out.append(chunk, (size_t)n);
    }
    return true;
}

int tcpConnect(const std::string& host, int port, std::string& err) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    LOG_DEBUG("rabbitmq: resolving ", host, ":", port);
    if (int rc = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res); rc != 0) {
        err = "dns: " + host;
        LOG_ERROR("rabbitmq: cannot resolve ", host, ": ", gai_strerror(rc));
        return -1;
    }
    int fd = -1;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, 0);
        if (fd < 0) { LOG_ERROR("rabbitmq: socket() failed: ", std::strerror(errno)); continue; }
        timeval tv{10, 0};
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        LOG_DEBUG("rabbitmq: connecting to ", host, ":", port, " (family ", ai->ai_family, ")");
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        LOG_WARN("rabbitmq: connect to ", host, ":", port, " failed: ", std::strerror(errno));
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    if (fd < 0) { err = "cannot connect to " + host + ":" + std::to_string(port); LOG_ERROR("rabbitmq: ", err); }
    else LOG_INFO("rabbitmq: TCP connected to ", host, ":", port, " (fd ", fd, ")");
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
        host_ = getCfgString(cfg, "host", "localhost");
        port_ = (int)getCfgInt(cfg, "port", 5672);
        vhost_ = getCfgString(cfg, "vhost", "/");
        user_ = getCfgString(cfg, "user", "guest");
        pass_ = getCfgString(cfg, "pass", "guest");
        exchange_ = getCfgString(cfg, "exchange", "");   // empty => default exchange
        routingKey_ = getCfgString(cfg, "routing_key", "s3mm.events");
        declareExchange_ = getCfgString(cfg, "declare_exchange") == "on";
        exchangeType_ = getCfgString(cfg, "exchange_type", "topic");
        confirm_ = getCfgString(cfg, "confirm") == "on";
        LOG_DEBUG("rabbitmq: connect host=", host_, ":", port_, " vhost=", vhost_, " user=", user_,
                  " pass=", log::redact(pass_), " exchange=", exchange_.empty() ? "(default)" : exchange_,
                  " routing_key=", routingKey_, " declare_exchange=", declareExchange_ ? "on" : "off",
                  " exchange_type=", exchangeType_, " confirm=", confirm_ ? "on" : "off");

        std::string err;
        fd_ = tcpConnect(host_, port_, err);
        if (fd_ < 0) return s3mm::Result<void>::failure(err);
        if (!handshake(err)) {
            LOG_ERROR("rabbitmq: AMQP handshake with ", host_, ":", port_, " failed: ", err);
            ::close(fd_); fd_ = -1; return s3mm::Result<void>::failure(err);
        }
        running_ = true;
        worker_ = std::thread([this] { loop(); });
        LOG_INFO("rabbitmq: publisher ready (", host_, ":", port_, " vhost ", vhost_, ")");
        return s3mm::Result<void>::success();
    }

    void disconnect() override {
        LOG_DEBUG("rabbitmq: disconnecting");
        running_ = false;
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        LOG_INFO("rabbitmq: disconnected from ", host_, ":", port_);
    }

    s3mm::Result<void> publish(const s3mme::Event& ev, const std::string& routingHint) override {
        Item it;
        it.id = ev.id;
        it.key = routingHint.empty() ? (ev.replication + "." + ev.kind) : routingHint;
        it.value = ev.toJson().toJson(0);
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (queue_.size() > 10000) {
                LOG_ERROR("rabbitmq: queue overflow (", queue_.size(), " pending), event ", ev.id, " rejected");
                return s3mm::Result<void>::failure("rabbitmq queue overflow");
            }
            LOG_DEBUG("rabbitmq: queued event ", ev.id, " routing_key=", it.key, " ", it.value.size(),
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
        LOG_WARN("rabbitmq: flush timed out with ", left, " message(s) pending");
        return s3mm::Result<void>::failure("flush timeout");
    }

private:
    struct Item { std::string id, key, value; int attempts = 0; };
    static constexpr int kMaxAttempts = 3;

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
        if ((uint8_t)payload.back() != FRAME_END) { err = "bad frame-end"; LOG_ERROR("rabbitmq: bad frame-end on frame type ", (int)type, " channel ", ch); return false; }
        payload.pop_back();
        body = Rdr(std::move(payload));
        return true;
    }

    bool expectMethod(uint16_t cls, uint16_t method, std::string& err) {
        for (int guard = 0; guard < 32; ++guard) {
            Rdr body(std::string{});
            uint16_t ch = 0;
            uint8_t type = 0;
            if (!readFrame(body, ch, type, err)) return false;
            if (type == FRAME_HEARTBEAT) { LOG_DEBUG("rabbitmq: heartbeat received"); continue; }
            if (type != FRAME_METHOD) { err = "unexpected frame type " + std::to_string(type); LOG_ERROR("rabbitmq: expecting ", cls, ".", method, ": ", err); return false; }
            uint16_t gotCls = body.u16();
            uint16_t gotMth = body.u16();
            if (gotCls == cls && gotMth == method) { LOG_DEBUG("rabbitmq: <- method ", cls, ".", method, " (channel ", ch, ")"); return true; }
            if ((gotCls == 10 && gotMth == 50) || (gotCls == 20 && gotMth == 40)) {
                uint16_t code = body.u16();
                std::string text = body.shortstr();
                LOG_ERROR("rabbitmq: broker sent ", gotCls == 10 ? "Connection.Close" : "Channel.Close", " while expecting ",
                          cls, ".", method, ": ", code, " ", text);
                replyCloseOk(ch, gotCls);
                err = (gotCls == 10 ? "connection closed by broker: " : "channel closed by broker: ") + std::to_string(code) + " " + text;
                return false;
            }
            // unexpected but tolerable (e.g. Channel.Flow) — keep reading
            LOG_DEBUG("rabbitmq: skipping unexpected method ", gotCls, ".", gotMth, " while expecting ", cls, ".", method);
        }
        err = "too many unexpected frames";
        LOG_ERROR("rabbitmq: expecting ", cls, ".", method, ": ", err);
        return false;
    }

    // Answer Connection.Close (10.50) / Channel.Close (20.40) with the matching Close-Ok.
    void replyCloseOk(uint16_t ch, uint16_t cls) {
        LOG_DEBUG("rabbitmq: -> ", cls == 10 ? "Connection.Close-Ok" : "Channel.Close-Ok", " (channel ", ch, ")");
        if (!sendAll(fd_, methodFrame(cls == 10 ? 0 : ch, cls, cls == 10 ? 51 : 41, {})))
            LOG_WARN("rabbitmq: cannot send Close-Ok for class ", cls);
    }

    bool handshake(std::string& err) {
        static const char proto[] = {'A', 'M', 'Q', 'P', '\r', '\n', 1, 1};
        std::string hdr(proto, sizeof(proto));
        log::Stopwatch sw;
        LOG_DEBUG("rabbitmq: -> AMQP 0-9-1 protocol header");
        if (!sendAll(fd_, hdr)) { err = "protocol header send failed"; return false; }

        // Connection.Start (10,10) -> Start-Ok (10,11)
        {
            Rdr body(std::string{}); uint16_t ch; uint8_t type;
            if (!readFrame(body, ch, type, err)) { LOG_ERROR("rabbitmq: waiting for Connection.Start: ", err); return false; }
            if (type != FRAME_METHOD) { err = "expected method frame"; LOG_ERROR("rabbitmq: Connection.Start: got frame type ", (int)type); return false; }
            uint16_t cls = body.u16(), mth = body.u16();
            uint8_t vmaj = body.u8(), vmin = body.u8();
            LOG_DEBUG("rabbitmq: <- Connection.Start (method ", cls, ".", mth, ", server version ", (int)vmaj, ".", (int)vmin, ")");
            // skip class/method/version/mechanisms/locale — we assume PLAIN is offered
        }
        {
            Buf a;
            a.u32(0);                       // client-properties table size (empty)
            a.shortstr("PLAIN");
            std::string resp;
            resp.push_back('\0'); resp += user_;
            resp.push_back('\0'); resp += pass_;
            a.longstr(resp);
            a.shortstr("en_US");
            LOG_DEBUG("rabbitmq: -> Connection.Start-Ok (PLAIN, user '", user_, "', password ", log::redact(pass_), ")");
            if (!sendAll(fd_, methodFrame(0, 10, 11, a.str()))) { err = "start-ok send failed"; return false; }
        }
        if (!expectMethod(10, 30, err)) { LOG_ERROR("rabbitmq: Connection.Tune not received (authentication rejected?): ", err); return false; } // Connection.Tune
        LOG_DEBUG("rabbitmq: <- Connection.Tune");
        bool ok = tuneAndOpen(err);
        if (ok) LOG_INFO("rabbitmq: AMQP session established with ", host_, ":", port_, " vhost ", vhost_, " in ", sw.ms(), " ms");
        return ok;
    }

    bool tuneAndOpen(std::string& err) {
        // We already consumed one frame after Start-Ok via expectMethod; that frame
        // is Tune. Parse nothing from it, just reply with defaults.
        {
            Buf a;
            a.u16(2047);   // channel max
            a.u32(131072); // frame max
            a.u16(0);      // heartbeat disabled: this publisher never sends heartbeat frames
            LOG_DEBUG("rabbitmq: -> Connection.Tune-Ok (channel_max 2047, frame_max 131072, heartbeat off)");
            if (!sendAll(fd_, methodFrame(0, 10, 31, a.str()))) { err = "tune-ok send failed"; return false; }
        }
        {
            Buf a;
            a.shortstr(vhost_);
            a.shortstr("");  // capabilities
            a.bits(false);   // insist
            LOG_DEBUG("rabbitmq: -> Connection.Open vhost ", vhost_);
            if (!sendAll(fd_, methodFrame(0, 10, 40, a.str()))) { err = "open send failed"; return false; }
        }
        if (!expectMethod(10, 41, err)) { LOG_ERROR("rabbitmq: Connection.Open vhost ", vhost_, " failed: ", err); return false; } // Open-Ok
        LOG_DEBUG("rabbitmq: Connection.Open-Ok");

        // Channel 1
        {
            Buf a;
            a.shortstr("");
            a.bits(false);
            LOG_DEBUG("rabbitmq: -> Channel.Open 1");
            if (!sendAll(fd_, methodFrame(1, 20, 10, a.str()))) { err = "channel.open send failed"; return false; }
        }
        if (!expectMethod(20, 11, err)) { LOG_ERROR("rabbitmq: Channel.Open failed: ", err); return false; } // Channel.Open-Ok
        LOG_DEBUG("rabbitmq: channel 1 open");

        if (confirm_) { // publisher confirms: Confirm.Select (90,5)
            Buf a;
            a.bits(false);  // nowait off: we wait for Select-Ok
            LOG_DEBUG("rabbitmq: -> Confirm.Select");
            if (!sendAll(fd_, methodFrame(1, 90, 5, a.str()))) { err = "confirm send failed"; return false; }
            if (!expectMethod(90, 6, err)) { LOG_ERROR("rabbitmq: Confirm.Select failed: ", err); return false; } // Confirm.Select-Ok
            LOG_DEBUG("rabbitmq: publisher confirms enabled");
        }

        if (declareExchange_ && !exchange_.empty()) {
            Buf a;
            a.u16(0);                 // reserved ticket
            a.shortstr(exchange_);
            a.shortstr(exchangeType_);
            a.u8(0x02);               // bits: passive|durable|auto-delete|internal|nowait -> durable
            a.u32(0);                 // arguments table (empty)
            LOG_DEBUG("rabbitmq: -> Exchange.Declare ", exchange_, " type ", exchangeType_, " durable");
            if (!sendAll(fd_, methodFrame(1, 40, 10, a.str()))) { err = "exchange.declare send failed"; return false; }
            if (!expectMethod(40, 11, err)) { LOG_ERROR("rabbitmq: Exchange.Declare ", exchange_, " failed: ", err); return false; } // Declare-Ok
            LOG_INFO("rabbitmq: exchange ", exchange_, " (", exchangeType_, ") declared");
        }
        return true;
    }

    // ---------------------------------------------------------- publishing
    bool publishOne(const Item& it, std::string& err) {
        if (fd_ < 0) { err = "not connected"; return false; }
        LOG_DEBUG("rabbitmq: -> Basic.Publish exchange=", exchange_.empty() ? "(default)" : exchange_,
                  " routing_key=", it.key, " body ", it.value.size(), " bytes");
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
            for (int guard = 0; guard < 32; ++guard) {
                Rdr body(std::string{}); uint16_t ch; uint8_t type;
                if (!readFrame(body, ch, type, err)) { LOG_ERROR("rabbitmq: waiting for publisher confirm: ", err); return false; }
                if (type == FRAME_HEARTBEAT) { LOG_DEBUG("rabbitmq: heartbeat received"); continue; }
                if (type == FRAME_HEADER || type == FRAME_BODY) continue;  // content of a Basic.Return
                if (type != FRAME_METHOD) { LOG_WARN("rabbitmq: unexpected frame type ", (int)type, " instead of publisher confirm"); continue; }
                uint16_t cls = body.u16();
                uint16_t mth = body.u16();
                if (cls == 60 && mth == 80) { LOG_DEBUG("rabbitmq: <- Basic.Ack for routing_key ", it.key); return true; }
                if (cls == 60 && mth == 120) { err = "basic.nack from broker"; LOG_ERROR("rabbitmq: <- Basic.Nack for routing_key ", it.key); return false; }
                if (cls == 60 && mth == 50) { LOG_WARN("rabbitmq: <- Basic.Return: message to routing_key ", it.key, " unroutable"); continue; } // Ack follows
                if ((cls == 10 && mth == 50) || (cls == 20 && mth == 40)) {
                    uint16_t code = body.u16();
                    std::string text = body.shortstr();
                    LOG_ERROR("rabbitmq: broker sent ", cls == 10 ? "Connection.Close" : "Channel.Close", " after publish: ", code, " ", text);
                    replyCloseOk(ch, cls);
                    err = (cls == 10 ? "connection closed by broker: " : "channel closed by broker: ") + std::to_string(code) + " " + text;
                    return false;
                }
                LOG_WARN("rabbitmq: unexpected method ", cls, ".", mth, " instead of publisher confirm");
            }
            err = "no publisher confirm";
            LOG_ERROR("rabbitmq: no publisher confirm for routing_key ", it.key, " after 32 frames");
            return false;
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
            log::Stopwatch sw;
            if (!publishOne(it, err)) {
                if (++it.attempts < kMaxAttempts) {
                    LOG_WARN("rabbitmq: publish of event ", it.id, " to ", exchange_.empty() ? "(default exchange)" : exchange_,
                             " routing_key=", it.key, " (", it.value.size(), " bytes) failed after ", sw.ms(), " ms: ", err,
                             "; attempt ", it.attempts, "/", kMaxAttempts, ", requeued, reconnecting");
                    std::lock_guard<std::mutex> lk(mu_);
                    queue_.push_front(it);
                } else {
                    LOG_ERROR("rabbitmq: publish of event ", it.id, " to ", exchange_.empty() ? "(default exchange)" : exchange_,
                              " routing_key=", it.key, " (", it.value.size(), " bytes) failed after ", it.attempts,
                              " attempt(s): ", err, "; message dropped, reconnecting");
                }
                reconnect();
                if (fd_ < 0 && running_) {
                    std::unique_lock<std::mutex> lk(mu_);
                    cv_.wait_for(lk, std::chrono::seconds(1), [this] { return !running_.load(); });
                }
            } else {
                LOG_INFO("rabbitmq: published event ", it.id, " (", it.value.size(), " bytes) to ", exchange_.empty() ? "(default exchange)" : exchange_,
                         " routing_key=", it.key, confirm_ ? " (confirmed)" : "", " in ", sw.ms(), " ms");
            }
        }
    }

    void reconnect() {
        LOG_WARN("rabbitmq: reconnecting to ", host_, ":", port_);
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        std::string err;
        fd_ = tcpConnect(host_, port_, err);
        if (fd_ >= 0 && handshake(err)) { LOG_NOTICE("rabbitmq: reconnected to ", host_, ":", port_); return; }
        LOG_ERROR("rabbitmq: reconnect to ", host_, ":", port_, " failed: ", err);
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
