#include "output/formatter.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace devdisc {

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (const char c : value) {
        switch (c) {
            case '"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c)) << std::dec;
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

std::string format_text(const DiscoveryReport& report) {
    std::ostringstream out;
    if (report.ssh_ip.empty()) {
        // Offline/mock mode: there is no SSH endpoint to report.
        out << "Network interfaces:\n";
    } else {
        out << "Directly connected device discovered\n\n";
        out << "SSH endpoint:\n";
        out << "  IP:       " << report.ssh_ip << "\n";
        out << "  Banner:   " << report.ssh_banner << "\n";
        if (!report.interface_name.empty()) {
            out << "  Via:      " << report.interface_name;
            if (!report.discovery_stage.empty()) {
                out << " (" << report.discovery_stage << ")";
            }
            out << "\n";
        }
        if (!report.host_key_status.empty()) {
            out << "  Host key: " << report.host_key_status << "\n";
        }
        out << "\nNetwork interfaces:\n";
    }
    if (report.interfaces.empty()) {
        out << "  (none found)\n";
    } else {
        std::size_t width = 4;
        for (const RemoteInterface& iface : report.interfaces) {
            width = std::max(width, iface.name.size());
        }
        for (const RemoteInterface& iface : report.interfaces) {
            out << "  " << std::left << std::setw(static_cast<int>(width) + 2) << iface.name
                << iface.ipv4 << "\n";
        }
    }

    if (!report.warnings.empty()) {
        out << "\n";
        for (const std::string& warning : report.warnings) {
            out << "WARNING: " << warning << "\n";
        }
    }
    return out.str();
}

std::string format_json(const DiscoveryReport& report) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"ssh_ip\": \"" << json_escape(report.ssh_ip) << "\",\n";
    out << "  \"ssh_banner\": \"" << json_escape(report.ssh_banner) << "\",\n";
    out << "  \"local_interface\": \"" << json_escape(report.interface_name) << "\",\n";
    out << "  \"discovery_stage\": \"" << json_escape(report.discovery_stage) << "\",\n";
    out << "  \"host_key_status\": \"" << json_escape(report.host_key_status) << "\",\n";
    out << "  \"interfaces\": [";
    for (std::size_t i = 0; i < report.interfaces.size(); ++i) {
        out << (i == 0 ? "\n" : ",\n");
        out << "    {\n";
        out << "      \"name\": \"" << json_escape(report.interfaces[i].name) << "\",\n";
        out << "      \"ipv4\": \"" << json_escape(report.interfaces[i].ipv4) << "\"\n";
        out << "    }";
    }
    out << (report.interfaces.empty() ? "]" : "\n  ]") << ",\n";
    out << "  \"warnings\": [";
    for (std::size_t i = 0; i < report.warnings.size(); ++i) {
        out << (i == 0 ? "\n" : ",\n");
        out << "    \"" << json_escape(report.warnings[i]) << "\"";
    }
    out << (report.warnings.empty() ? "]" : "\n  ]") << "\n";
    out << "}\n";
    return out.str();
}

}  // namespace devdisc
