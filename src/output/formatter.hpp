#pragma once

#include <string>
#include <vector>

#include "parser/ifconfig_parser.hpp"
#include "scanner/ssh_detector.hpp"

namespace devdisc {

struct DiscoveryReport {
    std::string interface_name;              ///< Local PC interface used.
    std::string ssh_ip;
    std::string ssh_banner;
    std::string host_key_status;
    std::string discovery_stage;             ///< "subnet-scan" or "layer2".
    std::vector<RemoteInterface> interfaces; ///< Interfaces of the target.
    std::vector<std::string> warnings;
};

/// Human readable report.
std::string format_text(const DiscoveryReport& report);

/// Machine readable report (--json).
std::string format_json(const DiscoveryReport& report);

/// Escapes a string for embedding into JSON.
std::string json_escape(const std::string& value);

}  // namespace devdisc
