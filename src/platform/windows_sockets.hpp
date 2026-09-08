#pragma once

// Single place where the Windows networking headers are pulled in. Every
// translation unit that touches sockets must include this header first so the
// header order (winsock2.h before windows.h) is always correct.

#ifndef _WIN32
#error "device-discovery targets Windows only"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
// clang-format off
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <windows.h>
#include <iphlpapi.h>
// clang-format on

#include <chrono>
#include <string>

namespace devdisc {

using socket_t = SOCKET;

constexpr socket_t kInvalidSocket = INVALID_SOCKET;

/// Initialises Winsock once per process. Every entry point that may create a
/// socket calls this; it is idempotent and thread safe. Returns false when
/// WSAStartup() failed, in which case no socket operation can succeed.
bool ensure_winsock_initialised();

/// Closes a socket handle and resets it to kInvalidSocket.
void close_socket(socket_t& handle);

/// Last Winsock error of the calling thread.
int last_socket_error();

/// Human readable text for a Winsock error code.
std::string socket_error_text(int error_code);

/// Puts a socket into non-blocking mode.
bool set_non_blocking(socket_t handle);

/// Waits until `handle` is readable (or writable when `for_write`) or the
/// timeout expires. Returns >0 when the socket is ready, 0 on timeout and <0 on
/// error. Uses WSAPoll(), the Windows equivalent of poll(2).
int wait_for_socket(socket_t handle, bool for_write, std::chrono::milliseconds timeout);

/// True when the current process runs with an elevated (Administrator) token.
/// Promiscuous capture (SIO_RCVALL) requires it.
bool is_process_elevated();

}  // namespace devdisc
