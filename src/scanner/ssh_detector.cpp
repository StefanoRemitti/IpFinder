#include "scanner/ssh_detector.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>

#include "scanner/port_scanner.hpp"

namespace devdisc {
namespace {

constexpr std::size_t kMaxBannerBytes = 512;

}  // namespace

std::string to_string(SshProbeStatus status) {
    switch (status) {
        case SshProbeStatus::SshDetected:
            return "ssh detected";
        case SshProbeStatus::NotSsh:
            return "port 22 is open but does not identify as SSH";
        case SshProbeStatus::NoBanner:
            return "port 22 is open but no SSH banner was received";
        case SshProbeStatus::PortClosed:
            return "port 22 is closed";
        case SshProbeStatus::Timeout:
            return "connection timed out";
        case SshProbeStatus::Unreachable:
            return "host unreachable";
        case SshProbeStatus::Error:
            break;
    }
    return "probe error";
}

bool is_ssh_identification(const std::string& line) {
    return line.rfind("SSH-", 0) == 0;
}

std::string sanitize_banner(const std::string& raw) {
    std::string result;
    result.reserve(raw.size());
    for (const char c : raw) {
        if (c == '\r' || c == '\n') {
            break;
        }
        // Replace (rather than drop) non-printable characters: a hostile peer
        // must not be able to inject terminal control sequences, and leading
        // binary garbage must not be silently turned into a valid banner.
        if (static_cast<unsigned char>(c) >= 0x20 && static_cast<unsigned char>(c) < 0x7f) {
            result.push_back(c);
        } else {
            result.push_back('?');
        }
    }
    while (!result.empty() && result.back() == ' ') {
        result.pop_back();
    }
    return result;
}

SshProbeResult read_ssh_banner(int fd, const std::string& ip,
                               std::chrono::milliseconds timeout) {
    SshProbeResult result;
    result.ip = ip;

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::string buffer;
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            break;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();

        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int poll_rc = 0;
        do {
            poll_rc = ::poll(&pfd, 1, static_cast<int>(remaining));
        } while (poll_rc < 0 && errno == EINTR);

        if (poll_rc <= 0) {
            break;
        }

        std::array<char, 128> chunk{};
        const ssize_t bytes = ::recv(fd, chunk.data(), chunk.size(), 0);
        if (bytes <= 0) {
            break;
        }
        buffer.append(chunk.data(), static_cast<std::size_t>(bytes));
        if (buffer.find('\n') != std::string::npos || buffer.size() >= kMaxBannerBytes) {
            break;
        }
    }

    if (buffer.empty()) {
        result.status = SshProbeStatus::NoBanner;
        return result;
    }

    result.banner = sanitize_banner(buffer);
    result.status = is_ssh_identification(result.banner) ? SshProbeStatus::SshDetected
                                                         : SshProbeStatus::NotSsh;
    return result;
}

SshProbeResult probe_ssh(const std::string& ip, uint16_t port,
                         std::chrono::milliseconds connect_timeout,
                         std::chrono::milliseconds banner_timeout) {
    SshProbeResult result;
    result.ip = ip;

    int fd = -1;
    const ConnectResult connect_result = tcp_connect(ip, port, connect_timeout, fd);
    switch (connect_result) {
        case ConnectResult::Connected:
            break;
        case ConnectResult::Refused:
            result.status = SshProbeStatus::PortClosed;
            return result;
        case ConnectResult::TimedOut:
            result.status = SshProbeStatus::Timeout;
            return result;
        case ConnectResult::Unreachable:
            result.status = SshProbeStatus::Unreachable;
            return result;
        case ConnectResult::Error:
            result.status = SshProbeStatus::Error;
            return result;
    }

    result = read_ssh_banner(fd, ip, banner_timeout);
    ::close(fd);
    return result;
}

}  // namespace devdisc
