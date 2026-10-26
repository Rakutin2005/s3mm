#pragma once
// Line-oriented framing transport for the s3mmc cluster channel.
//
// A Channel carries newline-delimited JSON frames over either a plain UNIX
// socket (core <-> s3mmc) or an mTLS TCP connection (s3mmc <-> s3mmc peer).
// Frames larger than the in-memory threshold are spilled to a temporary file:
// sendFile()/recvFrame() then exchange a JSON header whose "data" field is
// {"file": path, "bytes": n}; the receiving side owns the spool file and must
// call takeSpool() after consuming it. This keeps object payloads out of the
// frame size limit while the wire format stays uniform.
#include <cstdint>
#include <memory>
#include <string>

#include "s3mm/common/result.hpp"
#include "s3mm/common/value.hpp"

namespace s3mm::s3mmc {

class Channel {
public:
    virtual ~Channel() = default;

    /// Write one frame (line without trailing '\n' — the newline is appended).
    virtual Result<void> send(const Value& frame) = 0;
    /// Read one frame; null value + error text on failure / EOF.
    virtual Result<Value> recv() = 0;

    /// Spill threshold for sendFile(). Default 1 MiB.
    void setSpoolThreshold(uint64_t bytes) { spoolThreshold_ = bytes; }

    /// Send a frame whose "data" member is read from `filePath`. Small files
    /// are inlined as base64; large ones become {"file":...,"bytes":...}.
    virtual Result<void> sendFile(Value frame, const std::string& filePath,
                                   const std::string& dataKey = "data");

    /// Receive a frame; when the payload was spooled, the backing file path is
    /// returned in `spoolPath` (empty otherwise). The caller must delete the
    /// spool file via takeSpool() (or leave it — s3mmc sweeps its spool dir).
    virtual Result<Value> recvFrame(std::string* spoolPath = nullptr) {
        (void)spoolPath;
        return recv();
    }

    /// Remove a consumed spool file.
    static void takeSpool(const std::string& path);

    /// Splice raw bytes into a local file (streaming body sink). Used by the
    /// core-side channels where the body never becomes a string.
    virtual bool spliceToFile(int outFd, uint64_t expectedBytes, int64_t timeoutMs);

    /// Drain exactly `n` bytes from the stream (for non-frame binary payloads).
    virtual bool drainBytes(uint64_t n, int64_t timeoutMs);

protected:
    uint64_t spoolThreshold_ = 1ull << 20;
};

/// Plain UNIX-stream-socket channel (blocking, with poll-based timeouts).
Result<std::shared_ptr<Channel>> makeUnixChannel(int fd);

/// Connected TCP socket wrapped in an mTLS session. `clientRole` selects
/// TLS_client_method vs TLS_server_method; when `caFile` is empty verification
/// is disabled (test mode only).
Result<std::shared_ptr<Channel>> makeTlsChannel(int fd, bool clientRole,
                                                const std::string& certFile,
                                                const std::string& keyFile,
                                                const std::string& caFile);

/// Common Name of the counterparty certificate of a TLS channel established
/// via makeTlsChannel(); empty string for non-TLS channels or when no peer
/// certificate was presented. Used as the node identity on the cluster
/// channel (CN == cluster id == peer id) and for managed-node checks.
std::string tlsPeerCommonName(const std::shared_ptr<Channel>& ch);

} // namespace s3mm::s3mmc
