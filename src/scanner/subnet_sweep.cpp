#include "scanner/subnet_sweep.hpp"

#include "platform/windows_sockets.hpp"

#include <array>
#include <future>

namespace devdisc {
namespace {

std::string to_dotted(uint32_t host_order) {
    ensure_winsock_initialised();
    in_addr addr{};
    addr.s_addr = htonl(host_order);
    std::array<char, INET_ADDRSTRLEN> buffer{};
    if (::inet_ntop(AF_INET, &addr, buffer.data(), buffer.size()) == nullptr) {
        return {};
    }
    return std::string(buffer.data());
}

}  // namespace

std::vector<std::string> enumerate_subnet_hosts(const NetworkInterface& iface, int min_prefix) {
    std::vector<std::string> hosts;
    const int prefix = iface.prefix_length();
    if (prefix < min_prefix || iface.mask == 0) {
        return hosts;
    }
    if (prefix >= 31) {
        // /31 and /32 links: probe the peer address only.
        const uint32_t network = iface.network();
        const uint32_t count = (prefix == 32) ? 1u : 2u;
        for (uint32_t i = 0; i < count; ++i) {
            const uint32_t address = network + i;
            if (address != iface.address) {
                hosts.push_back(to_dotted(address));
            }
        }
        return hosts;
    }

    const uint32_t network = iface.network();
    const uint32_t broadcast = iface.broadcast();
    hosts.reserve(broadcast - network);
    for (uint32_t address = network + 1; address < broadcast; ++address) {
        if (address == iface.address) {
            continue;
        }
        hosts.push_back(to_dotted(address));
    }
    return hosts;
}

std::vector<SshProbeResult> sweep_for_ssh(ThreadPool& pool,
                                          const std::vector<std::string>& addresses,
                                          uint16_t port,
                                          std::chrono::milliseconds connect_timeout,
                                          std::chrono::milliseconds banner_timeout) {
    std::vector<std::future<SshProbeResult>> futures;
    futures.reserve(addresses.size());
    for (const std::string& address : addresses) {
        futures.push_back(pool.submit(
            [address, port, connect_timeout, banner_timeout]() {
                return probe_ssh(address, port, connect_timeout, banner_timeout);
            }));
    }

    std::vector<SshProbeResult> found;
    for (std::future<SshProbeResult>& future : futures) {
        try {
            SshProbeResult result = future.get();
            if (result.is_ssh()) {
                found.push_back(std::move(result));
            }
        } catch (const std::exception&) {
            // A probe task failed unexpectedly; the address is simply treated
            // as "no SSH server here".
        }
    }
    return found;
}

}  // namespace devdisc
