#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace devdisc {

/// A candidate IPv4 network interface of the local PC.
struct NetworkInterface {
    std::string name;       ///< Kernel interface name, e.g. "enp3s0".
    std::string ipv4;       ///< Dotted-quad IPv4 address of the interface.
    std::string netmask;    ///< Dotted-quad netmask.
    uint32_t address = 0;   ///< IPv4 address in host byte order.
    uint32_t mask = 0;      ///< Netmask in host byte order.
    bool is_loopback = false;
    bool is_up = false;
    bool is_running = false;
    bool is_point_to_point = false;

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
};

/// Reads every IPv4-capable interface of this machine using getifaddrs(3).
std::vector<InterfaceSnapshot> enumerate_interfaces();

/// Returns true when the interface name looks like a virtual interface that
/// cannot be a direct Ethernet link to the target device (docker bridges,
/// veth pairs, VPN tunnels, virtual bridges, ...).
bool is_virtual_interface_name(const std::string& name);

/// Applies the selection rules to a set of snapshots.
///
/// An interface is a candidate when it:
///   * is not loopback,
///   * is administratively up and operationally running,
///   * has an IPv4 address and a netmask,
///   * is not a well-known virtual interface.
std::vector<NetworkInterface> filter_candidate_interfaces(
    const std::vector<InterfaceSnapshot>& snapshots);

/// Convenience wrapper: enumerate_interfaces() + filter_candidate_interfaces().
std::vector<NetworkInterface> discover_candidate_interfaces();

}  // namespace devdisc
