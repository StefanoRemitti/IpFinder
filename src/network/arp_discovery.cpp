#include "network/arp_discovery.hpp"

#include "platform/windows_sockets.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

namespace devdisc {
namespace {

constexpr std::size_t kIpv4HeaderMinimum = 20;
constexpr std::size_t kIpv4SourceOffset = 12;
constexpr std::size_t kCaptureBufferSize = 65535;
constexpr std::chrono::milliseconds kCapturePollSlice{200};

bool is_zero_mac(const std::string& mac) {
    return mac.empty() || mac == "00:00:00:00:00:00" || mac == "00-00-00-00-00-00";
}

std::string format_ipv4(uint32_t network_order) {
    ensure_winsock_initialised();
    in_addr addr{};
    addr.s_addr = network_order;
    std::array<char, INET_ADDRSTRLEN> buffer{};
    if (::inet_ntop(AF_INET, &addr, buffer.data(), buffer.size()) == nullptr) {
        return {};
    }
    return std::string(buffer.data());
}

std::string format_mac(const unsigned char* address, std::size_t length) {
    if (address == nullptr || length == 0) {
        return {};
    }
    std::string result;
    std::array<char, 4> byte_text{};
    for (std::size_t i = 0; i < length; ++i) {
        std::snprintf(byte_text.data(), byte_text.size(), "%02x", address[i]);
        if (i != 0) {
            result.push_back(':');
        }
        result.append(byte_text.data());
    }
    return result;
}

/// True for addresses that can never identify the connected device: the
/// unspecified address, the limited broadcast address and multicast.
bool is_uninteresting_address(const std::string& ip) {
    if (ip.empty() || ip == "0.0.0.0" || ip == "255.255.255.255") {
        return true;
    }
    ensure_winsock_initialised();
    in_addr addr{};
    if (::inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return true;
    }
    const uint32_t host_order = ntohl(addr.s_addr);
    return (host_order & 0xF0000000u) >= 0xE0000000u;  // 224.0.0.0/4 and above.
}

void add_observation(std::vector<L2Observation>& observations, L2Observation candidate) {
    if (is_uninteresting_address(candidate.ip)) {
        return;
    }
    const auto existing = std::find_if(observations.begin(), observations.end(),
                                       [&](const L2Observation& o) { return o.ip == candidate.ip; });
    if (existing != observations.end()) {
        if (is_zero_mac(existing->mac)) {
            existing->mac = candidate.mac;
        }
        return;
    }
    observations.push_back(std::move(candidate));
}

/// Opens a promiscuous raw socket on `iface` and records the source address of
/// every IPv4 packet arriving during `listen_window`.
void capture_link_traffic(const NetworkInterface& iface, std::chrono::milliseconds listen_window,
                          L2DiscoveryResult& result) {
    if (!ensure_winsock_initialised()) {
        result.error = "Winsock initialisation failed";
        return;
    }

    socket_t handle = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (handle == kInvalidSocket) {
        const int error_code = last_socket_error();
        result.permission_denied = error_code == WSAEACCES;
        result.error = "cannot open a promiscuous capture socket on " + iface.name + ": " +
                       socket_error_text(error_code);
        if (result.permission_denied || !is_process_elevated()) {
            result.error +=
                " (layer-2 discovery needs an elevated process: re-run device-discovery "
                "from an Administrator command prompt)";
        }
        return;
    }

    struct SocketGuard {
        socket_t& handle;
        ~SocketGuard() { close_socket(handle); }
    } guard{handle};

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = 0;
    if (::inet_pton(AF_INET, iface.ipv4.c_str(), &local.sin_addr) != 1) {
        result.error = "invalid local address " + iface.ipv4 + " for " + iface.name;
        return;
    }
    if (::bind(handle, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        result.error = "cannot bind the capture socket to " + iface.ipv4 + ": " +
                       socket_error_text(last_socket_error());
        return;
    }

    DWORD value = RCVALL_ON;
    DWORD returned = 0;
    if (::WSAIoctl(handle, SIO_RCVALL, &value, sizeof(value), nullptr, 0, &returned, nullptr,
                   nullptr) == SOCKET_ERROR) {
        const int error_code = last_socket_error();
        result.permission_denied = error_code == WSAEACCES;
        result.error = "cannot enable promiscuous mode on " + iface.name + ": " +
                       socket_error_text(error_code);
        if (result.permission_denied) {
            result.error +=
                " (layer-2 discovery needs an elevated process: re-run device-discovery "
                "from an Administrator command prompt)";
        }
        return;
    }

    std::vector<unsigned char> buffer(kCaptureBufferSize);
    const auto deadline = std::chrono::steady_clock::now() + listen_window;
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            break;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const int ready =
            wait_for_socket(handle, /*for_write=*/false, std::min(remaining, kCapturePollSlice));
        if (ready < 0) {
            break;
        }
        if (ready == 0) {
            continue;
        }

        const int length =
            ::recv(handle, reinterpret_cast<char*>(buffer.data()),
                   static_cast<int>(buffer.size()), 0);
        if (length <= 0) {
            // WSAEMSGSIZE means the packet was larger than the buffer; the
            // truncated copy still carries the IPv4 header we are after.
            if (length == SOCKET_ERROR && last_socket_error() != WSAEMSGSIZE) {
                break;
            }
            continue;
        }

        const std::string source =
            parse_ipv4_source_address(buffer.data(), static_cast<std::size_t>(length));
        if (source.empty() || source == iface.ipv4) {
            continue;
        }
        L2Observation observation;
        observation.ip = source;
        observation.source = L2ObservationSource::Ipv4Traffic;
        add_observation(result.observations, std::move(observation));
    }
}

}  // namespace

std::string to_string(L2ObservationSource source) {
    switch (source) {
        case L2ObservationSource::ArpTraffic:
            return "arp";
        case L2ObservationSource::Ipv4Traffic:
            return "ipv4";
        case L2ObservationSource::NeighbourCache:
            break;
    }
    return "neighbour-cache";
}

std::vector<L2Observation> select_neighbour_entries(const std::vector<NeighbourEntry>& entries,
                                                    uint32_t if_index) {
    std::vector<L2Observation> observations;
    for (const NeighbourEntry& entry : entries) {
        if (entry.if_index != if_index || !entry.reachable || is_zero_mac(entry.mac)) {
            continue;
        }
        L2Observation observation;
        observation.ip = entry.ip;
        observation.mac = entry.mac;
        observation.source = L2ObservationSource::NeighbourCache;
        add_observation(observations, std::move(observation));
    }
    return observations;
}

std::string parse_ipv4_source_address(const unsigned char* packet, std::size_t length) {
    if (packet == nullptr || length < kIpv4HeaderMinimum) {
        return {};
    }
    if ((packet[0] >> 4) != 4) {
        return {};
    }
    const std::size_t header_length = static_cast<std::size_t>(packet[0] & 0x0F) * 4;
    if (header_length < kIpv4HeaderMinimum || header_length > length) {
        return {};
    }
    uint32_t network_order = 0;
    std::memcpy(&network_order, packet + kIpv4SourceOffset, sizeof(network_order));
    return format_ipv4(network_order);
}

std::vector<L2Observation> read_neighbour_cache(uint32_t if_index) {
    MIB_IPNET_TABLE2* table = nullptr;
    if (::GetIpNetTable2(AF_INET, &table) != NO_ERROR || table == nullptr) {
        return {};
    }

    std::vector<NeighbourEntry> entries;
    entries.reserve(table->NumEntries);
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPNET_ROW2& row = table->Table[i];
        NeighbourEntry entry;
        entry.if_index = static_cast<uint32_t>(row.InterfaceIndex);
        entry.ip = format_ipv4(row.Address.Ipv4.sin_addr.s_addr);
        entry.mac = format_mac(row.PhysicalAddress, row.PhysicalAddressLength);
        entry.reachable = row.State != NlnsUnreachable && row.State != NlnsIncomplete;
        entries.push_back(std::move(entry));
    }
    ::FreeMibTable(table);

    return select_neighbour_entries(entries, if_index);
}

L2DiscoveryResult discover_link_layer_hosts(const NetworkInterface& iface,
                                            std::chrono::milliseconds listen_window) {
    L2DiscoveryResult result;
    for (L2Observation& observation : read_neighbour_cache(iface.if_index)) {
        if (observation.ip != iface.ipv4) {
            add_observation(result.observations, std::move(observation));
        }
    }

    capture_link_traffic(iface, listen_window, result);

    // Stations seen during the capture may have been resolved in the meantime;
    // a second cache read fills in the missing hardware addresses.
    for (L2Observation& observation : read_neighbour_cache(iface.if_index)) {
        if (observation.ip != iface.ipv4) {
            add_observation(result.observations, std::move(observation));
        }
    }

    if (!result.observations.empty()) {
        result.error.clear();
    } else if (result.error.empty()) {
        result.error = "no station announced an IPv4 address on " + iface.name +
                       " during the layer-2 listening window";
    }
    return result;
}

}  // namespace devdisc
