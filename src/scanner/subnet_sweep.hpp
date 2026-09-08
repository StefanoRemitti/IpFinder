#pragma once

#include <chrono>
#include <string>
#include <vector>

#include "network/interface_discovery.hpp"
#include "scanner/ssh_detector.hpp"
#include "threading/thread_pool.hpp"

namespace devdisc {

/// Returns every host address of the interface's directly connected subnet,
/// excluding the network address, the broadcast address and the PC's own
/// address. Subnets larger than 2^(32 - min_prefix) addresses are refused
/// (empty result) so the tool never sweeps an unbounded address range.
std::vector<std::string> enumerate_subnet_hosts(const NetworkInterface& iface, int min_prefix);

/// Probes every address in `addresses` for an SSH server using the shared
/// thread pool. Returns the results of the addresses that answered with a
/// valid SSH identification string.
std::vector<SshProbeResult> sweep_for_ssh(ThreadPool& pool,
                                          const std::vector<std::string>& addresses,
                                          uint16_t port,
                                          std::chrono::milliseconds connect_timeout,
                                          std::chrono::milliseconds banner_timeout);

}  // namespace devdisc
