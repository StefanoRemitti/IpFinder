#pragma once

#include <string>
#include <vector>

namespace devdisc {

struct RemoteInterface {
    std::string name;
    std::string ipv4;
};

/// Parses the stdout of `ifconfig` (net-tools, BusyBox and legacy formats).
/// Loopback interfaces, IPv6 addresses and entries without an IPv4 address are
/// ignored. Interface names are not assumed to be eth0/eth1.
std::vector<RemoteInterface> parse_ifconfig_output(const std::string& output);

/// Parses the stdout of `ip -4 addr` (fallback when ifconfig is unavailable).
std::vector<RemoteInterface> parse_ip_addr_output(const std::string& output);

/// True for names that must be ignored (loopback).
bool is_loopback_interface_name(const std::string& name);

}  // namespace devdisc
