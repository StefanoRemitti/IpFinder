#include "scanner/ssh_detector.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <string>
#include <thread>

#include "scanner/port_scanner.hpp"
#include "test_support.hpp"

using namespace std::chrono_literals;
using devdisc::probe_ssh;
using devdisc::SshProbeResult;
using devdisc::SshProbeStatus;

namespace {

/// Minimal single-connection TCP server on 127.0.0.1 used to emulate remote
/// services without a physical device.
class FakeServer {
public:
    explicit FakeServer(std::string payload, bool send_payload = true)
        : payload_(std::move(payload)), send_payload_(send_payload) {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int reuse = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = 0;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(listen_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        ::listen(listen_fd_, 4);
        socklen_t length = sizeof(address);
        ::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&address), &length);
        port_ = ntohs(address.sin_port);

        worker_ = std::thread([this]() {
            const int client = ::accept(listen_fd_, nullptr, nullptr);
            if (client < 0) {
                return;
            }
            if (send_payload_) {
                (void)::send(client, payload_.data(), payload_.size(), 0);
            } else {
                std::this_thread::sleep_for(300ms);
            }
            ::close(client);
        });
    }

    ~FakeServer() {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    uint16_t port() const { return port_; }

private:
    std::string payload_;
    bool send_payload_;
    int listen_fd_ = -1;
    uint16_t port_ = 0;
    std::thread worker_;
};

uint16_t closed_port() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    socklen_t length = sizeof(address);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length);
    const uint16_t port = ntohs(address.sin_port);
    ::close(fd);
    return port;
}

void test_banner_validation_helpers() {
    CHECK(devdisc::is_ssh_identification("SSH-2.0-OpenSSH_9.6"));
    CHECK(devdisc::is_ssh_identification("SSH-1.99-Cisco"));
    CHECK(!devdisc::is_ssh_identification("ssh-2.0-lowercase"));
    CHECK(!devdisc::is_ssh_identification("HTTP/1.1 200 OK"));
    CHECK(!devdisc::is_ssh_identification(""));
    CHECK_EQ(devdisc::sanitize_banner("SSH-2.0-OpenSSH_9.6\r\nmore"),
             std::string("SSH-2.0-OpenSSH_9.6"));
    CHECK_EQ(devdisc::sanitize_banner("SSH-2.0-\x1b[31mEvil\r\n"), std::string("SSH-2.0-?[31mEvil"));
}

void test_valid_ssh_banner() {
    FakeServer server("SSH-2.0-OpenSSH_9.6\r\n");
    const SshProbeResult result = probe_ssh("127.0.0.1", server.port(), 750ms, 1000ms);
    CHECK(result.is_ssh());
    CHECK_EQ(result.banner, std::string("SSH-2.0-OpenSSH_9.6"));
}

void test_non_ssh_service() {
    FakeServer server("HTTP/1.1 400 Bad Request\r\n");
    const SshProbeResult result = probe_ssh("127.0.0.1", server.port(), 750ms, 1000ms);
    CHECK(!result.is_ssh());
    CHECK(result.status == SshProbeStatus::NotSsh);
}

void test_malformed_banner() {
    FakeServer server(std::string("\x00\x01\x02SSH-", 7));
    const SshProbeResult result = probe_ssh("127.0.0.1", server.port(), 750ms, 300ms);
    CHECK(!result.is_ssh());
    CHECK(result.status == SshProbeStatus::NotSsh);
}

void test_silent_service_produces_no_banner() {
    FakeServer server("", /*send_payload=*/false);
    const SshProbeResult result = probe_ssh("127.0.0.1", server.port(), 750ms, 100ms);
    CHECK(result.status == SshProbeStatus::NoBanner);
}

void test_connection_refused() {
    const SshProbeResult result = probe_ssh("127.0.0.1", closed_port(), 750ms, 1000ms);
    CHECK(result.status == SshProbeStatus::PortClosed);
}

void test_unroutable_address_does_not_hang() {
    const auto start = std::chrono::steady_clock::now();
    // TEST-NET-1 (RFC 5737) is not routed; the probe must respect the timeout.
    (void)probe_ssh("192.0.2.1", 22, 300ms, 300ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    // The only guarantee that matters: the probe honours its timeouts. Some
    // environments transparently intercept outbound connections, so the
    // outcome itself is not asserted.
    CHECK(elapsed < 3s);
}

void test_invalid_address_is_reported_as_error() {
    CHECK(devdisc::tcp_probe("not-an-ip", 22, 100ms) == devdisc::ConnectResult::Error);
}

}  // namespace

int main() {
    test_banner_validation_helpers();
    test_valid_ssh_banner();
    test_non_ssh_service();
    test_malformed_banner();
    test_silent_service_produces_no_banner();
    test_connection_refused();
    test_unroutable_address_does_not_hang();
    test_invalid_address_is_reported_as_error();
    return testing::finish("ssh_detector");
}
