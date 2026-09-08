#include "scanner/port_scanner.hpp"

#include <cstdint>

namespace devdisc {
namespace {

ConnectResult classify(int error_code) {
    switch (error_code) {
        case 0:
            return ConnectResult::Connected;
        case WSAECONNREFUSED:
            return ConnectResult::Refused;
        case WSAETIMEDOUT:
            return ConnectResult::TimedOut;
        case WSAEHOSTUNREACH:
        case WSAENETUNREACH:
        case WSAEHOSTDOWN:
        case WSAENETDOWN:
            return ConnectResult::Unreachable;
        default:
            return ConnectResult::Error;
    }
}

}  // namespace

std::string to_string(ConnectResult result) {
    switch (result) {
        case ConnectResult::Connected:
            return "connected";
        case ConnectResult::Refused:
            return "connection refused";
        case ConnectResult::TimedOut:
            return "timed out";
        case ConnectResult::Unreachable:
            return "unreachable";
        case ConnectResult::Error:
            break;
    }
    return "error";
}

ConnectResult tcp_connect(const std::string& ip, uint16_t port,
                          std::chrono::milliseconds timeout, socket_t& out_socket) {
    out_socket = kInvalidSocket;

    if (!ensure_winsock_initialised()) {
        return ConnectResult::Error;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1) {
        return ConnectResult::Error;
    }

    socket_t handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == kInvalidSocket) {
        return ConnectResult::Error;
    }
    if (!set_non_blocking(handle)) {
        close_socket(handle);
        return ConnectResult::Error;
    }

    const int rc = ::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (rc == 0) {
        out_socket = handle;
        return ConnectResult::Connected;
    }
    const int connect_error = last_socket_error();
    if (connect_error != WSAEWOULDBLOCK && connect_error != WSAEINPROGRESS) {
        const ConnectResult result = classify(connect_error);
        close_socket(handle);
        return result;
    }

    // WSAPoll() reports a failed connection attempt through POLLERR/POLLHUP, so
    // the outcome is always confirmed with SO_ERROR below.
    const int poll_rc = wait_for_socket(handle, /*for_write=*/true, timeout);
    if (poll_rc == 0) {
        close_socket(handle);
        return ConnectResult::TimedOut;
    }
    if (poll_rc < 0) {
        close_socket(handle);
        return ConnectResult::Error;
    }

    int so_error = 0;
    int length = static_cast<int>(sizeof(so_error));
    if (::getsockopt(handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &length) !=
        0) {
        close_socket(handle);
        return ConnectResult::Error;
    }
    if (so_error != 0) {
        close_socket(handle);
        return classify(so_error);
    }

    out_socket = handle;
    return ConnectResult::Connected;
}

ConnectResult tcp_probe(const std::string& ip, uint16_t port,
                        std::chrono::milliseconds timeout) {
    socket_t handle = kInvalidSocket;
    const ConnectResult result = tcp_connect(ip, port, timeout, handle);
    close_socket(handle);
    return result;
}

}  // namespace devdisc
