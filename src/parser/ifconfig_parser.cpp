#include "parser/ifconfig_parser.hpp"

#include "platform/windows_sockets.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace devdisc {
namespace {

bool is_valid_ipv4(const std::string& text) {
    ensure_winsock_initialised();
    in_addr addr{};
    return ::inet_pton(AF_INET, text.c_str(), &addr) == 1;
}

std::string trim(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return {};
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::string normalize_name(std::string name) {
    // "eth0:" (net-tools), "veth0@if12" (ip), "eth0:1" (alias).
    if (!name.empty() && name.back() == ':') {
        name.pop_back();
    }
    const auto at = name.find('@');
    if (at != std::string::npos) {
        name = name.substr(0, at);
    }
    return name;
}

/// Extracts the IPv4 address from a line containing "inet <addr>",
/// "inet addr:<addr>" or "inet <addr>/<prefix>". Returns an empty string when
/// the line carries no IPv4 address (for instance "inet6 ...").
std::string extract_inet_address(const std::string& line) {
    std::istringstream tokens(trim(line));
    std::string token;
    while (tokens >> token) {
        std::string candidate;
        if (token == "inet") {
            if (!(tokens >> candidate)) {
                return {};
            }
        } else if (token.rfind("addr:", 0) == 0) {
            candidate = token.substr(5);
        } else {
            continue;
        }

        if (candidate.rfind("addr:", 0) == 0) {
            candidate = candidate.substr(5);
        }
        const auto slash = candidate.find('/');
        if (slash != std::string::npos) {
            candidate = candidate.substr(0, slash);
        }
        if (is_valid_ipv4(candidate)) {
            return candidate;
        }
        return {};
    }
    return {};
}

void append(std::vector<RemoteInterface>& interfaces, const std::string& name,
            const std::string& ipv4) {
    if (name.empty() || ipv4.empty() || is_loopback_interface_name(name)) {
        return;
    }
    const bool duplicate =
        std::any_of(interfaces.begin(), interfaces.end(), [&](const RemoteInterface& existing) {
            return existing.name == name && existing.ipv4 == ipv4;
        });
    if (!duplicate) {
        interfaces.push_back(RemoteInterface{name, ipv4});
    }
}

}  // namespace

bool is_loopback_interface_name(const std::string& name) { return name == "lo" || name == "lo0"; }

std::vector<RemoteInterface> parse_ifconfig_output(const std::string& output) {
    std::vector<RemoteInterface> interfaces;
    std::istringstream stream(output);
    std::string line;
    std::string current;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        const bool new_block = !std::isspace(static_cast<unsigned char>(line.front()));
        if (new_block) {
            std::istringstream tokens(line);
            std::string first;
            tokens >> first;
            current = normalize_name(first);
        }
        if (current.empty()) {
            continue;
        }
        const std::string address = extract_inet_address(line);
        if (!address.empty()) {
            append(interfaces, current, address);
        }
    }
    return interfaces;
}

std::vector<RemoteInterface> parse_ip_addr_output(const std::string& output) {
    std::vector<RemoteInterface> interfaces;
    std::istringstream stream(output);
    std::string line;
    std::string current;
    while (std::getline(stream, line)) {
        const std::string trimmed = trim(line);
        if (trimmed.empty()) {
            continue;
        }
        if (std::isdigit(static_cast<unsigned char>(trimmed.front())) &&
            trimmed.find(':') != std::string::npos) {
            std::istringstream tokens(trimmed);
            std::string index;
            std::string name;
            tokens >> index >> name;
            current = normalize_name(name);
            continue;
        }
        if (current.empty()) {
            continue;
        }
        const std::string address = extract_inet_address(trimmed);
        if (!address.empty()) {
            append(interfaces, current, address);
        }
    }
    return interfaces;
}

}  // namespace devdisc
