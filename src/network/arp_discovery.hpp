#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "network/interface_discovery.hpp"

namespace devdisc {

/// How an address was observed on the directly connected link.
enum class L2ObservationSource {
    ArpTraffic,       ///< Sender address of an ARP request/reply.
    Ipv4Traffic,      ///< Source address of an IPv4 frame.
    NeighbourCache,   ///< Entry already present in the kernel ARP cache.
};

struct L2Observation {
    std::string ip;
    std::string mac;
    L2ObservationSource source = L2ObservationSource::ArpTraffic;
};

struct L2DiscoveryResult {
    std::vector<L2Observation> observations;
    bool permission_denied = false;  ///< AF_PACKET requires CAP_NET_RAW/root.
    std::string error;               ///< Human readable diagnostic, empty on success.
};

std::string to_string(L2ObservationSource source);

/// Parses the contents of /proc/net/arp and returns the entries belonging to
/// `interface_name` that have a resolved (non zero) hardware address.
std::vector<L2Observation> parse_proc_net_arp(const std::string& contents,
                                              const std::string& interface_name);

/// Reads the kernel neighbour cache for the given interface.
std::vector<L2Observation> read_neighbour_cache(const std::string& interface_name);

/// Layer-2 discovery restricted to a single directly connected link.
///
/// The function listens on an AF_PACKET socket bound to `iface` for
/// `listen_window` and records every IPv4 address advertised by another
/// station, either through ARP or as the source address of an IPv4 frame.
/// A broadcast ARP request for the PC's own address is emitted first to
/// encourage the peer to speak. No address outside the directly connected link
/// is ever probed.
L2DiscoveryResult discover_link_layer_hosts(const NetworkInterface& iface,
                                            std::chrono::milliseconds listen_window);

}  // namespace devdisc
