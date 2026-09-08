#include "network/interface_discovery.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string_view>

namespace devdisc {
namespace {

std::string to_dotted(const sockaddr* addr) {
    if (addr == nullptr || addr->sa_family != AF_INET) {
        return {};
    }
    const auto* in4 = reinterpret_cast<const sockaddr_in*>(addr);
    std::array<char, INET_ADDRSTRLEN> buffer{};
    if (::inet_ntop(AF_INET, &in4->sin_addr, buffer.data(), buffer.size()) == nullptr) {
        return {};
    }
    return std::string(buffer.data());
}

bool parse_ipv4(const std::string& text, uint32_t& out_host_order) {
    in_addr addr{};
    if (text.empty() || ::inet_pton(AF_INET, text.c_str(), &addr) != 1) {
        return false;
    }
    out_host_order = ntohl(addr.s_addr);
    return true;
}

bool starts_with(const std::string& value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

}  // namespace

int NetworkInterface::prefix_length() const {
    int bits = 0;
    for (int i = 31; i >= 0; --i) {
        if ((mask >> i) & 1u) {
            ++bits;
        } else {
            break;
        }
    }
    return bits;
}

uint64_t NetworkInterface::usable_host_count() const {
    const int prefix = prefix_length();
    if (prefix >= 31) {
        return prefix == 32 ? 1 : 2;
    }
    return (uint64_t{1} << (32 - prefix)) - 2;
}

bool is_virtual_interface_name(const std::string& name) {
    static constexpr std::string_view kVirtualPrefixes[] = {
        "docker", "veth",  "br-",   "virbr", "vboxnet", "vmnet", "tun",
        "tap",    "wg",    "ppp",   "sit",   "gre",     "bond",  "dummy",
        "lxcbr",  "cni",   "flannel", "kube", "zt",     "tailscale", "utun",
    };
    for (const std::string_view prefix : kVirtualPrefixes) {
        if (starts_with(name, prefix)) {
            return true;
        }
    }
    return false;
}

std::vector<InterfaceSnapshot> enumerate_interfaces() {
    ifaddrs* raw = nullptr;
    if (::getifaddrs(&raw) != 0) {
        throw std::runtime_error(std::string("getifaddrs() failed: ") + std::strerror(errno));
    }

    struct Guard {
        ifaddrs* list;
        ~Guard() { ::freeifaddrs(list); }
    } guard{raw};

    std::vector<InterfaceSnapshot> result;
    for (ifaddrs* it = raw; it != nullptr; it = it->ifa_next) {
        if (it->ifa_name == nullptr) {
            continue;
        }
        // Only report an interface once, preferring the entry carrying IPv4.
        const bool ipv4 = it->ifa_addr != nullptr && it->ifa_addr->sa_family == AF_INET;
        if (!ipv4 && it->ifa_addr != nullptr && it->ifa_addr->sa_family != AF_PACKET) {
            continue;
        }

        InterfaceSnapshot snapshot;
        snapshot.name = it->ifa_name;
        snapshot.is_loopback = (it->ifa_flags & IFF_LOOPBACK) != 0;
        snapshot.is_up = (it->ifa_flags & IFF_UP) != 0;
        snapshot.is_running = (it->ifa_flags & IFF_RUNNING) != 0;
        snapshot.is_point_to_point = (it->ifa_flags & IFF_POINTOPOINT) != 0;
        if (ipv4) {
            snapshot.ipv4 = to_dotted(it->ifa_addr);
            snapshot.netmask = to_dotted(it->ifa_netmask);
            snapshot.has_ipv4 = !snapshot.ipv4.empty();
        }

        bool merged = false;
        for (InterfaceSnapshot& existing : result) {
            if (existing.name == snapshot.name) {
                if (snapshot.has_ipv4 && !existing.has_ipv4) {
                    existing.ipv4 = snapshot.ipv4;
                    existing.netmask = snapshot.netmask;
                    existing.has_ipv4 = true;
                }
                merged = true;
                break;
            }
        }
        if (!merged) {
            result.push_back(std::move(snapshot));
        }
    }
    return result;
}

std::vector<NetworkInterface> filter_candidate_interfaces(
    const std::vector<InterfaceSnapshot>& snapshots) {
    std::vector<NetworkInterface> candidates;
    for (const InterfaceSnapshot& snapshot : snapshots) {
        if (snapshot.is_loopback || !snapshot.is_up || !snapshot.is_running) {
            continue;
        }
        if (!snapshot.has_ipv4) {
            continue;
        }
        if (is_virtual_interface_name(snapshot.name)) {
            continue;
        }

        NetworkInterface iface;
        iface.name = snapshot.name;
        iface.ipv4 = snapshot.ipv4;
        iface.netmask = snapshot.netmask;
        iface.is_loopback = snapshot.is_loopback;
        iface.is_up = snapshot.is_up;
        iface.is_running = snapshot.is_running;
        iface.is_point_to_point = snapshot.is_point_to_point;
        if (!parse_ipv4(snapshot.ipv4, iface.address)) {
            continue;
        }
        if (!parse_ipv4(snapshot.netmask, iface.mask)) {
            continue;
        }
        candidates.push_back(std::move(iface));
    }
    return candidates;
}

std::vector<NetworkInterface> discover_candidate_interfaces() {
    return filter_candidate_interfaces(enumerate_interfaces());
}

}  // namespace devdisc
