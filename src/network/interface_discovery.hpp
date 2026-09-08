#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace devdisc {

/// A candidate IPv4 network interface of the local PC.
struct NetworkInterface {
    std::string name;       ///< Adapter friendly name, e.g. "Ethernet 2".
    std::string ipv4;       ///< Dotted-quad IPv4 address of the interface.
    std::string netmask;    ///< Dotted-quad netmask.
    uint32_t address = 0;   ///< IPv4 address in host byte order.
    uint32_t mask = 0;      ///< Netmask in host byte order.
    bool is_loopback = false;
    bool is_up = false;
    bool is_running = false;
    bool is_point_to_point = false;
    uint32_t if_index = 0;   ///< Windows IPv4 interface index (IF_INDEX).
    std::string mac;         ///< Physical address, colon separated, may be empty.
    std::string description; ///< Adapter description reported by Windows.

    /// Network address (host byte order).
    uint32_t network() const { return address & mask; }
    /// Broadcast address (host byte order).
    uint32_t broadcast() const { return network() | ~mask; }
    /// Prefix length derived from the netmask.
    int prefix_length() const;
    /// Number of usable host addresses on the subnet (excluding network and
    /// broadcast addresses for prefixes shorter than /31).
    uint64_t usable_host_count() const;
};

/// Raw snapshot of one interface as reported by the operating system. Kept
/// separate from the filtering logic so the selection rules can be unit tested
/// without touching the real network configuration.
struct InterfaceSnapshot {
    std::string name;
    std::string ipv4;
    std::string netmask;
    bool is_loopback = false;
    bool is_up = false;
    bool is_running = false;
    bool is_point_to_point = false;
    bool has_ipv4 = false;
    uint32_t if_index = 0;
    std::string mac;
    std::string description;
};

/// Reads every IPv4-capable adapter of this machine using
/// GetAdaptersAddresses() (iphlpapi).
std::vector<InterfaceSnapshot> enumerate_interfaces();

/// Returns true when the adapter name or description looks like a virtual
/// adapter that cannot be a direct Ethernet link to the target device
/// (Hyper-V vEthernet switches, VMware/VirtualBox host-only adapters, VPN
/// tunnels, loopback adapters, ...). Matching is case insensitive and
/// substring based because Windows adapter names are human readable.
bool is_virtual_interface_name(const std::string& name);

/// Applies the selection rules to a set of snapshots.
///
/// An interface is a candidate when it:
///   * is not loopback,
///   * is administratively up and operationally running,
///   * has an IPv4 address and a netmask,
///   * is not a well-known virtual adapter.
std::vector<NetworkInterface> filter_candidate_interfaces(
    const std::vector<InterfaceSnapshot>& snapshots);

/// Convenience wrapper: enumerate_interfaces() + filter_candidate_interfaces().
std::vector<NetworkInterface> discover_candidate_interfaces();

}  // namespace devdisc
