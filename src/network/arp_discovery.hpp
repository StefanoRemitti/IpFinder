#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "network/interface_discovery.hpp"

namespace devdisc {

/// How an address was observed on the directly connected link.
enum class L2ObservationSource {
    ArpTraffic,       ///< Sender address of an ARP request/reply.
    Ipv4Traffic,      ///< Source address of a captured IPv4 packet.
    NeighbourCache,   ///< Entry already present in the Windows neighbour cache.
};

struct L2Observation {
    std::string ip;
    std::string mac;
    L2ObservationSource source = L2ObservationSource::ArpTraffic;
};

struct L2DiscoveryResult {
    std::vector<L2Observation> observations;
    bool permission_denied = false;  ///< Promiscuous capture needs Administrator.
    std::string error;               ///< Human readable diagnostic, empty on success.
};

/// One row of the Windows neighbour (ARP) cache, decoupled from the iphlpapi
/// structures so the selection rules can be unit tested.
struct NeighbourEntry {
    uint32_t if_index = 0;
    std::string ip;
    std::string mac;
    bool reachable = true;  ///< False for incomplete/unreachable entries.
};

std::string to_string(L2ObservationSource source);

/// Keeps the usable neighbour cache rows of `if_index`: entries with a
/// resolved (non zero) hardware address that are neither multicast nor
/// broadcast. Duplicate addresses are merged.
std::vector<L2Observation> select_neighbour_entries(const std::vector<NeighbourEntry>& entries,
                                                    uint32_t if_index);

/// Extracts the source address of a captured IPv4 packet. Returns an empty
/// string when the buffer is not a well formed IPv4 header.
std::string parse_ipv4_source_address(const unsigned char* packet, std::size_t length);

/// Reads the Windows neighbour cache (GetIpNetTable2) for one interface.
std::vector<L2Observation> read_neighbour_cache(uint32_t if_index);

/// Layer-2 discovery restricted to a single directly connected link.
///
/// Two Windows mechanisms are combined, both limited to the link `iface` is
/// attached to; no address outside the directly connected link is ever probed:
///
///  1. the neighbour cache of the adapter, which already holds every station
///     that recently exchanged ARP with this PC;
///  2. a promiscuous capture (SOCK_RAW + SIO_RCVALL) for `listen_window`,
///     recording the source address of every IPv4 packet seen on the link.
///     This is what finds a device whose static address lies outside the PC's
///     own subnet. It requires an elevated process; when the socket cannot be
///     created for that reason `permission_denied` is set and the neighbour
///     cache result is still returned.
L2DiscoveryResult discover_link_layer_hosts(const NetworkInterface& iface,
                                            std::chrono::milliseconds listen_window);

}  // namespace devdisc
