#include "network/interface_discovery.hpp"

#include "platform/windows_sockets.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace devdisc {
namespace {

constexpr ULONG kEnumerationFlags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                    GAA_FLAG_SKIP_DNS_SERVER;

std::string wide_to_utf8(const wchar_t* text) {
    if (text == nullptr || *text == L'\0') {
        return {};
    }
    const int required =
        ::WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (required <= 1) {
        return {};
    }
    std::string result(static_cast<std::size_t>(required - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), required, nullptr, nullptr);
    return result;
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

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

std::string netmask_from_prefix(uint8_t prefix_length) {
    if (prefix_length > 32) {
        return {};
    }
    const uint32_t mask =
        prefix_length == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix_length)) & 0xFFFFFFFFu;
    in_addr addr{};
    addr.s_addr = htonl(mask);
    std::array<char, INET_ADDRSTRLEN> buffer{};
    if (::inet_ntop(AF_INET, &addr, buffer.data(), buffer.size()) == nullptr) {
        return {};
    }
    return std::string(buffer.data());
}

std::string format_mac(const BYTE* address, ULONG length) {
    if (address == nullptr || length == 0) {
        return {};
    }
    std::string result;
    std::array<char, 4> byte_text{};
    for (ULONG i = 0; i < length; ++i) {
        std::snprintf(byte_text.data(), byte_text.size(), "%02x", address[i]);
        if (i != 0) {
            result.push_back(':');
        }
        result.append(byte_text.data());
    }
    return result;
}

bool parse_ipv4(const std::string& text, uint32_t& out_host_order) {
    ensure_winsock_initialised();
    in_addr addr{};
    if (text.empty() || ::inet_pton(AF_INET, text.c_str(), &addr) != 1) {
        return false;
    }
    out_host_order = ntohl(addr.s_addr);
    return true;
}

/// Calls GetAdaptersAddresses() into a growing buffer and returns it.
std::vector<unsigned char> query_adapter_addresses() {
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buffer;
    for (int attempt = 0; attempt < 4; ++attempt) {
        buffer.assign(size, 0);
        const ULONG rc = ::GetAdaptersAddresses(
            AF_INET, kEnumerationFlags, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
        if (rc == ERROR_SUCCESS) {
            return buffer;
        }
        if (rc != ERROR_BUFFER_OVERFLOW) {
            throw std::runtime_error("GetAdaptersAddresses() failed: " +
                                     socket_error_text(static_cast<int>(rc)));
        }
    }
    throw std::runtime_error("GetAdaptersAddresses() kept reporting ERROR_BUFFER_OVERFLOW");
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
    // Windows adapter names and descriptions are human readable, so the match
    // is done on case insensitive substrings rather than prefixes.
    static constexpr std::string_view kVirtualMarkers[] = {
        "vethernet",  "hyper-v",   "vmware",    "vmnet",    "virtualbox", "vbox",
        "loopback",   "openvpn",   "tap-windows", "wintun", "wireguard",  "zerotier",
        "tailscale",  "bluetooth", "wan miniport", "teredo", "isatap",    "npcap",
        "pseudo-interface", "docker", "veth",   "br-",      "virbr",      "tun",
        "tap",        "vpn",       "vswitch",   "vlan",     "tunnel",
    };
    const std::string lowered = to_lower(name);
    for (const std::string_view marker : kVirtualMarkers) {
        if (lowered.find(marker) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::vector<InterfaceSnapshot> enumerate_interfaces() {
    ensure_winsock_initialised();
    const std::vector<unsigned char> buffer = query_adapter_addresses();

    std::vector<InterfaceSnapshot> result;
    for (const auto* adapter = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data());
         adapter != nullptr; adapter = adapter->Next) {
        InterfaceSnapshot snapshot;
        snapshot.name = wide_to_utf8(adapter->FriendlyName);
        if (snapshot.name.empty()) {
            snapshot.name = adapter->AdapterName != nullptr ? adapter->AdapterName : "";
        }
        snapshot.description = wide_to_utf8(adapter->Description);
        snapshot.if_index = static_cast<uint32_t>(adapter->IfIndex);
        snapshot.mac = format_mac(adapter->PhysicalAddress, adapter->PhysicalAddressLength);
        snapshot.is_loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
        // Windows reports IfOperStatusUp only when the adapter is enabled *and*
        // the media is connected, which covers both IFF_UP and IFF_RUNNING.
        snapshot.is_up = adapter->OperStatus == IfOperStatusUp;
        snapshot.is_running = snapshot.is_up;
        snapshot.is_point_to_point =
            adapter->IfType == IF_TYPE_PPP || adapter->IfType == IF_TYPE_TUNNEL;

        for (const IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
             unicast != nullptr; unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr == nullptr ||
                unicast->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            const std::string ipv4 = to_dotted(unicast->Address.lpSockaddr);
            if (ipv4.empty() || ipv4 == "0.0.0.0") {
                continue;
            }
            snapshot.ipv4 = ipv4;
            snapshot.netmask = netmask_from_prefix(unicast->OnLinkPrefixLength);
            snapshot.has_ipv4 = !snapshot.netmask.empty();
            break;  // One IPv4 address per adapter is enough to identify the link.
        }

        result.push_back(std::move(snapshot));
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
        if (is_virtual_interface_name(snapshot.name) ||
            is_virtual_interface_name(snapshot.description)) {
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
        iface.if_index = snapshot.if_index;
        iface.mac = snapshot.mac;
        iface.description = snapshot.description;
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
