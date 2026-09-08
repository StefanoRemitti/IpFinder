#pragma once

#include <chrono>
#include <string>

#include "platform/windows_sockets.hpp"

namespace devdisc {

/// Result of a single TCP connection attempt.
enum class ConnectResult {
    Connected,     ///< The three-way handshake completed.
    Refused,       ///< The host answered with RST (port closed).
    TimedOut,      ///< No answer within the configured timeout.
    Unreachable,   ///< No route / host unreachable / network unreachable.
    Error,         ///< Any other local error.
};

std::string to_string(ConnectResult result);

/// Attempts a TCP connection using a non-blocking socket and WSAPoll(), so the
/// call never blocks longer than `timeout`.
///
/// On success the connected socket is stored in `out_socket` and the caller
/// owns it. On failure `out_socket` is set to kInvalidSocket.
ConnectResult tcp_connect(const std::string& ip, uint16_t port,
                          std::chrono::milliseconds timeout, socket_t& out_socket);

/// Convenience wrapper that closes the socket immediately.
ConnectResult tcp_probe(const std::string& ip, uint16_t port,
                        std::chrono::milliseconds timeout);

}  // namespace devdisc
