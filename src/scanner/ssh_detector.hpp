#pragma once

#include <chrono>
#include <string>

#include "platform/windows_sockets.hpp"

namespace devdisc {

/// Outcome of probing one address for an SSH server.
enum class SshProbeStatus {
    SshDetected,      ///< Port 22 is open and the peer sent an "SSH-" banner.
    NotSsh,           ///< Port 22 is open but the banner is not an SSH banner.
    NoBanner,         ///< Port 22 is open but no banner arrived in time.
    PortClosed,       ///< Connection refused.
    Timeout,          ///< TCP connection timed out.
    Unreachable,      ///< No route to host.
    Error,            ///< Local error.
};

struct SshProbeResult {
    std::string ip;
    SshProbeStatus status = SshProbeStatus::Error;
    std::string banner;  ///< Trimmed identification string when available.

    bool is_ssh() const { return status == SshProbeStatus::SshDetected; }
};

std::string to_string(SshProbeStatus status);

/// Returns true when `line` is a valid SSH identification string as defined by
/// RFC 4253 section 4.2, i.e. it starts with "SSH-".
bool is_ssh_identification(const std::string& line);

/// Removes trailing CR/LF and control characters from a raw banner line.
std::string sanitize_banner(const std::string& raw);

/// Reads the SSH identification string from an already connected socket.
/// Never blocks longer than `timeout`.
SshProbeResult read_ssh_banner(socket_t handle, const std::string& ip,
                               std::chrono::milliseconds timeout);

/// Connects to `ip`:`port` and verifies that the peer identifies as SSH.
SshProbeResult probe_ssh(const std::string& ip, uint16_t port,
                         std::chrono::milliseconds connect_timeout,
                         std::chrono::milliseconds banner_timeout);

}  // namespace devdisc
