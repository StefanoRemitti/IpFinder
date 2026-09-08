#include "scanner/port_scanner.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>

namespace devdisc {
namespace {

ConnectResult classify(int error_code) {
    switch (error_code) {
        case 0:
            return ConnectResult::Connected;
        case ECONNREFUSED:
            return ConnectResult::Refused;
        case ETIMEDOUT:
            return ConnectResult::TimedOut;
        case EHOSTUNREACH:
        case ENETUNREACH:
        case EHOSTDOWN:
        case ENETDOWN:
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
                          std::chrono::milliseconds timeout, int& out_fd) {
    out_fd = -1;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (::inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1) {
        return ConnectResult::Error;
    }

    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return ConnectResult::Error;
    }

    int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (rc == 0) {
        out_fd = fd;
        return ConnectResult::Connected;
    }
    if (errno != EINPROGRESS) {
        const ConnectResult result = classify(errno);
        ::close(fd);
        return result;
    }

    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    int poll_rc = 0;
    do {
        poll_rc = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
    } while (poll_rc < 0 && errno == EINTR);

    if (poll_rc == 0) {
        ::close(fd);
        return ConnectResult::TimedOut;
    }
    if (poll_rc < 0) {
        ::close(fd);
        return ConnectResult::Error;
    }

    int so_error = 0;
    socklen_t length = sizeof(so_error);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &length) != 0) {
        ::close(fd);
        return ConnectResult::Error;
    }
    if (so_error != 0) {
        ::close(fd);
        return classify(so_error);
    }

    out_fd = fd;
    return ConnectResult::Connected;
}

ConnectResult tcp_probe(const std::string& ip, uint16_t port,
                        std::chrono::milliseconds timeout) {
    int fd = -1;
    const ConnectResult result = tcp_connect(ip, port, timeout, fd);
    if (fd >= 0) {
        ::close(fd);
    }
    return result;
}

}  // namespace devdisc
