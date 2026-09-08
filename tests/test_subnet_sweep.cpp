#include "scanner/subnet_sweep.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include "config.hpp"
#include "network/interface_discovery.hpp"
#include "test_support.hpp"

using namespace std::chrono_literals;
using devdisc::enumerate_subnet_hosts;
using devdisc::NetworkInterface;

namespace {

NetworkInterface make_interface(const std::string& ip, const std::string& mask) {
    devdisc::InterfaceSnapshot snapshot;
    snapshot.name = "eth0";
    snapshot.ipv4 = ip;
    snapshot.netmask = mask;
    snapshot.has_ipv4 = true;
    snapshot.is_up = true;
    snapshot.is_running = true;
    return devdisc::filter_candidate_interfaces({snapshot}).front();
}

void test_slash24_enumeration() {
    const NetworkInterface iface = make_interface("192.168.10.20", "255.255.255.0");
    const std::vector<std::string> hosts = enumerate_subnet_hosts(iface, 22);
    CHECK_EQ(hosts.size(), std::size_t{253});  // 254 hosts minus our own address.
    CHECK_EQ(hosts.front(), std::string("192.168.10.1"));
    CHECK_EQ(hosts.back(), std::string("192.168.10.254"));
    CHECK(std::find(hosts.begin(), hosts.end(), "192.168.10.20") == hosts.end());
    CHECK(std::find(hosts.begin(), hosts.end(), "192.168.10.0") == hosts.end());
    CHECK(std::find(hosts.begin(), hosts.end(), "192.168.10.255") == hosts.end());
}

void test_slash30_and_slash31() {
    const NetworkInterface slash30 = make_interface("10.0.0.1", "255.255.255.252");
    CHECK_EQ(enumerate_subnet_hosts(slash30, 22).size(), std::size_t{1});
    CHECK_EQ(enumerate_subnet_hosts(slash30, 22).front(), std::string("10.0.0.2"));

    const NetworkInterface slash31 = make_interface("10.0.0.0", "255.255.255.254");
    CHECK_EQ(enumerate_subnet_hosts(slash31, 22).size(), std::size_t{1});
    CHECK_EQ(enumerate_subnet_hosts(slash31, 22).front(), std::string("10.0.0.1"));
}

void test_oversized_subnet_is_refused() {
    const NetworkInterface slash8 = make_interface("10.1.2.3", "255.0.0.0");
    CHECK_EQ(enumerate_subnet_hosts(slash8, devdisc::defaults::kMinimumScanPrefix).size(),
             std::size_t{0});
}

void test_sweep_finds_only_ssh_speakers() {
    // Two loopback services: one speaks SSH, the other does not.
    struct Server {
        int fd = -1;
        uint16_t port = 0;
        std::thread worker;
    };

    auto start_server = [](const std::string& payload) {
        auto server = std::make_shared<Server>();
        server->fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(server->fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        ::listen(server->fd, 4);
        socklen_t length = sizeof(address);
        ::getsockname(server->fd, reinterpret_cast<sockaddr*>(&address), &length);
        server->port = ntohs(address.sin_port);
        server->worker = std::thread([server, payload]() {
            const int client = ::accept(server->fd, nullptr, nullptr);
            if (client < 0) {
                return;
            }
            (void)::send(client, payload.data(), payload.size(), 0);
            ::close(client);
        });
        return server;
    };

    auto ssh_server = start_server("SSH-2.0-OpenSSH_9.6\r\n");
    auto http_server = start_server("HTTP/1.1 200 OK\r\n");

    devdisc::ThreadPool pool(4);
    const std::vector<devdisc::SshProbeResult> ssh_hits =
        devdisc::sweep_for_ssh(pool, {"127.0.0.1"}, ssh_server->port, 750ms, 1000ms);
    const std::vector<devdisc::SshProbeResult> http_hits =
        devdisc::sweep_for_ssh(pool, {"127.0.0.1"}, http_server->port, 750ms, 1000ms);
    pool.shutdown();

    CHECK_EQ(ssh_hits.size(), std::size_t{1});
    CHECK_EQ(ssh_hits.front().banner, std::string("SSH-2.0-OpenSSH_9.6"));
    CHECK_EQ(http_hits.size(), std::size_t{0});

    for (auto* server : {ssh_server.get(), http_server.get()}) {
        ::shutdown(server->fd, SHUT_RDWR);
        ::close(server->fd);
        if (server->worker.joinable()) {
            server->worker.join();
        }
    }
}

}  // namespace

int main() {
    test_slash24_enumeration();
    test_slash30_and_slash31();
    test_oversized_subnet_is_refused();
    test_sweep_finds_only_ssh_speakers();
    return testing::finish("subnet_sweep");
}
