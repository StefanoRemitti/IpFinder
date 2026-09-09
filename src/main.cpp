#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "config.hpp"
#include "platform/windows_sockets.hpp"
#include "network/arp_discovery.hpp"
#include "network/interface_discovery.hpp"
#include "output/formatter.hpp"
#include "parser/ifconfig_parser.hpp"
#include "scanner/ssh_detector.hpp"
#include "scanner/subnet_sweep.hpp"
#include "ssh/ssh_client.hpp"
#include "threading/thread_pool.hpp"

namespace devdisc {
namespace {

struct Options {
    std::size_t threads = defaults::kThreadCount;
    std::string ssh_user = defaults::kSshUser;
    std::string password_env = defaults::kPasswordEnvVar;
    std::string ssh_password;  ///< --ssh-password, takes precedence over the env var.
    bool password_from_cli = false;
    bool json = false;
    bool verbose = false;
    bool strict_host_key = false;
    std::chrono::milliseconds connect_timeout = defaults::kTcpConnectTimeout;
    std::chrono::milliseconds banner_timeout = defaults::kSshBannerTimeout;
    std::chrono::milliseconds auth_timeout = defaults::kSshAuthTimeout;
    std::chrono::milliseconds command_timeout = defaults::kSshCommandTimeout;
    std::chrono::milliseconds layer2_window = defaults::kLayer2ListenWindow;
    std::string interface_hint;  ///< --interface, only to disambiguate.
    std::string select_candidate;  ///< --select IP when several devices answer.
    std::string mock_ifconfig_file;  ///< --mock-ifconfig FILE (offline testing).
};

void print_usage() {
    std::cout
        << "Usage: device-discovery [options]\n"
           "\n"
           "Discovers the Linux device directly connected to this PC, authenticates\n"
           "over SSH and reports the IPv4 addresses of its network interfaces.\n"
           "Neither a subnet nor a target IP has to be supplied.\n"
           "\n"
           "Options:\n"
           "  --threads N              Worker threads for probing (default 32)\n"
           "  --ssh-user USER          SSH username (default root)\n"
           "  --ssh-password PASS      SSH password (visible in the process list;\n"
           "                           prefer --ssh-password-env)\n"
           "  --ssh-password-env VAR   Environment variable holding the password\n"
           "                           (default DEVICE_SSH_PASSWORD, used when\n"
           "                           --ssh-password is not given)\n"
           "  --json                   Machine readable output\n"
           "  --verbose                Diagnostic output on stderr\n"
           "  --timeout MS             TCP connect timeout (default 750)\n"
           "  --banner-timeout MS      SSH banner read timeout (default 1000)\n"
           "  --auth-timeout MS        SSH authentication timeout (default 5000)\n"
           "  --command-timeout MS     Remote command timeout (default 5000)\n"
           "  --layer2-window MS       Layer-2 listening window (default 4000)\n"
           "  --interface NAME         Disambiguate between candidate adapters\n"
           "                           (Windows adapter name, e.g. \"Ethernet 2\")\n"
           "  --select IP              Pick a candidate when several SSH devices answer\n"
           "  --strict-host-key        Abort on unknown/mismatching SSH host keys\n"
           "  --mock-ifconfig FILE     Offline mode: parse FILE as ifconfig output\n"
           "  -h, --help               Show this help\n";
}

bool parse_positive(const char* text, long long& out) {
    if (text == nullptr) {
        return false;
    }
    char* end = nullptr;
    const long long value = std::strtoll(text, &end, 10);
    if (end == text || *end != '\0' || value <= 0) {
        return false;
    }
    out = value;
    return true;
}

bool parse_options(int argc, char** argv, Options& options, int& exit_code) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next_value = [&](std::string& target) {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a value\n";
                exit_code = kUsageError;
                return false;
            }
            target = argv[++i];
            return true;
        };
        auto next_ms = [&](std::chrono::milliseconds& target) {
            long long value = 0;
            if (i + 1 >= argc || !parse_positive(argv[i + 1], value)) {
                std::cerr << "Error: " << arg << " requires a positive millisecond value\n";
                exit_code = kUsageError;
                return false;
            }
            ++i;
            target = std::chrono::milliseconds(value);
            return true;
        };

        if (arg == "-h" || arg == "--help") {
            print_usage();
            exit_code = kSuccess;
            return false;
        } else if (arg == "--json") {
            options.json = true;
        } else if (arg == "--verbose") {
            options.verbose = true;
        } else if (arg == "--strict-host-key") {
            options.strict_host_key = true;
        } else if (arg == "--threads") {
            long long value = 0;
            if (i + 1 >= argc || !parse_positive(argv[i + 1], value) || value > 1024) {
                std::cerr << "Error: --threads requires a value between 1 and 1024\n";
                exit_code = kUsageError;
                return false;
            }
            ++i;
            options.threads = static_cast<std::size_t>(value);
        } else if (arg == "--ssh-user") {
            if (!next_value(options.ssh_user)) return false;
        } else if (arg == "--ssh-password") {
            if (!next_value(options.ssh_password)) return false;
            options.password_from_cli = true;
        } else if (arg == "--ssh-password-env") {
            if (!next_value(options.password_env)) return false;
        } else if (arg == "--interface") {
            if (!next_value(options.interface_hint)) return false;
        } else if (arg == "--select") {
            if (!next_value(options.select_candidate)) return false;
        } else if (arg == "--mock-ifconfig") {
            if (!next_value(options.mock_ifconfig_file)) return false;
        } else if (arg == "--timeout") {
            if (!next_ms(options.connect_timeout)) return false;
        } else if (arg == "--banner-timeout") {
            if (!next_ms(options.banner_timeout)) return false;
        } else if (arg == "--auth-timeout") {
            if (!next_ms(options.auth_timeout)) return false;
        } else if (arg == "--command-timeout") {
            if (!next_ms(options.command_timeout)) return false;
        } else if (arg == "--layer2-window") {
            if (!next_ms(options.layer2_window)) return false;
        } else {
            std::cerr << "Error: unknown argument '" << arg << "'\n";
            print_usage();
            exit_code = kUsageError;
            return false;
        }
    }
    return true;
}

void log(const Options& options, const std::string& message) {
    if (options.verbose) {
        std::cerr << "[device-discovery] " << message << "\n";
    }
}

std::string read_file(const std::string& path, bool& ok) {
    std::ifstream file(path);
    if (!file) {
        ok = false;
        return {};
    }
    std::ostringstream contents;
    contents << file.rdbuf();
    ok = true;
    return contents.str();
}

void emit(const Options& options, const DiscoveryReport& report) {
    std::cout << (options.json ? format_json(report) : format_text(report));
}

int run_mock_mode(const Options& options) {
    bool ok = false;
    const std::string contents = read_file(options.mock_ifconfig_file, ok);
    if (!ok) {
        std::cerr << "Error: could not read " << options.mock_ifconfig_file << "\n";
        return kUsageError;
    }

    DiscoveryReport report;
    report.discovery_stage = "mock";
    report.interfaces = parse_ifconfig_output(contents);
    if (report.interfaces.empty()) {
        report.interfaces = parse_ip_addr_output(contents);
    }
    if (report.interfaces.empty()) {
        std::cerr << "Error: could not parse network interfaces from "
                  << options.mock_ifconfig_file << "\n";
        return kParseFailed;
    }
    if (report.interfaces.size() != 2) {
        report.warnings.push_back("expected two network interfaces but found " +
                                  std::to_string(report.interfaces.size()));
    }
    emit(options, report);
    return report.interfaces.size() == 2 ? kSuccess : kUnexpectedInterfaceCount;
}

int select_interface(const Options& options, NetworkInterface& selected) {
    std::vector<NetworkInterface> candidates = discover_candidate_interfaces();
    if (!options.interface_hint.empty()) {
        candidates.erase(std::remove_if(candidates.begin(), candidates.end(),
                                        [&](const NetworkInterface& iface) {
                                            return iface.name != options.interface_hint;
                                        }),
                         candidates.end());
    }

    if (candidates.empty()) {
        std::cerr << "Error: No suitable network interface found.\n"
                  << "       Looked for an adapter that is connected, non-loopback,\n"
                  << "       non-virtual and carrying an IPv4 address.\n";
        return kNoInterface;
    }
    if (candidates.size() > 1) {
        std::cerr << "Error: Multiple candidate interfaces found; refusing to guess.\n";
        for (const NetworkInterface& iface : candidates) {
            std::cerr << "       " << iface.name << " " << iface.ipv4 << "/"
                      << iface.prefix_length() << "\n";
        }
        std::cerr << "       Disconnect the unrelated links or pass --interface NAME.\n";
        return kMultipleInterfaces;
    }
    selected = candidates.front();
    return kSuccess;
}

std::vector<SshProbeResult> stage_a_subnet_scan(const Options& options,
                                                const NetworkInterface& iface,
                                                ThreadPool& pool) {
    const std::vector<std::string> hosts =
        enumerate_subnet_hosts(iface, defaults::kMinimumScanPrefix);
    if (hosts.empty()) {
        log(options, "stage A skipped: subnet of " + iface.name + " is larger than /" +
                         std::to_string(defaults::kMinimumScanPrefix));
        return {};
    }
    log(options, "stage A: probing " + std::to_string(hosts.size()) + " addresses of " +
                     iface.ipv4 + "/" + std::to_string(iface.prefix_length()));
    return sweep_for_ssh(pool, hosts, defaults::kSshPort, options.connect_timeout,
                         options.banner_timeout);
}

std::vector<SshProbeResult> stage_b_layer2(const Options& options, const NetworkInterface& iface,
                                           ThreadPool& pool, std::string& diagnostic) {
    log(options, "stage A found nothing, starting layer-2 discovery on " + iface.name);
    if (!is_process_elevated()) {
        log(options,
            "not running elevated: promiscuous capture will most likely be refused by Windows");
    }
    const L2DiscoveryResult l2 = discover_link_layer_hosts(iface, options.layer2_window);
    if (l2.observations.empty()) {
        diagnostic = l2.error.empty() ? "layer-2 discovery observed no station" : l2.error;
        return {};
    }

    std::vector<std::string> addresses;
    for (const L2Observation& observation : l2.observations) {
        log(options, "layer-2 observation: " + observation.ip + " (" + observation.mac + ", " +
                         to_string(observation.source) + ")");
        addresses.push_back(observation.ip);
    }

    std::vector<SshProbeResult> found = sweep_for_ssh(pool, addresses, defaults::kSshPort,
                                                      options.connect_timeout,
                                                      options.banner_timeout);
    if (found.empty()) {
        std::ostringstream message;
        message << "the directly connected device was seen on the link but no SSH server "
                   "could be reached at:";
        for (const L2Observation& observation : l2.observations) {
            message << "\n         " << observation.ip << " (" << observation.mac << ")";
        }
        message << "\n       If the address is outside " << iface.ipv4 << "/"
                << iface.prefix_length()
                << " the PC has no route to it; add a temporary address on the device's\n"
                   "       subnet, e.g. netsh interface ipv4 add address \"" << iface.name
                << "\" <free-ip> <netmask>";
        diagnostic = message.str();
    }
    return found;
}

int run(const Options& options) {
    if (!options.mock_ifconfig_file.empty()) {
        return run_mock_mode(options);
    }

    std::string password;
    if (options.password_from_cli) {
        password = options.ssh_password;
        if (password.empty()) {
            std::cerr << "Error: --ssh-password requires a non-empty value.\n";
            return kUsageError;
        }
    } else {
        const char* password_env = std::getenv(options.password_env.c_str());
        if (password_env == nullptr || *password_env == '\0') {
            std::cerr << "Error: SSH password not configured.\n"
                      << "       Pass --ssh-password, or set the environment variable "
                      << options.password_env << " (see --ssh-password-env).\n";
            return kUsageError;
        }
        password = password_env;
    }

    NetworkInterface iface;
    const int interface_status = select_interface(options, iface);
    if (interface_status != kSuccess) {
        return interface_status;
    }
    log(options, "using interface " + iface.name + " (" + iface.ipv4 + "/" +
                     std::to_string(iface.prefix_length()) + ")");

    ThreadPool pool(options.threads);
    std::string stage = "subnet-scan";
    std::vector<SshProbeResult> devices = stage_a_subnet_scan(options, iface, pool);
    std::string diagnostic;
    if (devices.empty()) {
        stage = "layer2";
        devices = stage_b_layer2(options, iface, pool, diagnostic);
    }
    pool.shutdown();

    if (devices.empty()) {
        std::cerr << "Error: No device discovered on " << iface.name << ".\n";
        if (!diagnostic.empty()) {
            std::cerr << "       " << diagnostic << "\n";
        }
        return kNoDevice;
    }

    if (devices.size() > 1) {
        auto chosen = devices.end();
        if (!options.select_candidate.empty()) {
            chosen = std::find_if(devices.begin(), devices.end(), [&](const SshProbeResult& r) {
                return r.ip == options.select_candidate;
            });
            if (chosen == devices.end()) {
                std::cerr << "Error: --select " << options.select_candidate
                          << " does not match any discovered device.\n";
                return kUsageError;
            }
        }
        if (chosen == devices.end()) {
            std::cerr << "WARNING: multiple SSH devices discovered\n";
            for (const SshProbeResult& device : devices) {
                std::cerr << "  " << device.ip << "  " << device.banner << "\n";
            }
            std::cerr << "Refusing to authenticate automatically; re-run with --select IP.\n";
            return kMultipleDevices;
        }
        const SshProbeResult selected = *chosen;
        devices.clear();
        devices.push_back(selected);
    }

    const SshProbeResult& device = devices.front();
    log(options, "SSH server confirmed at " + device.ip + " (" + device.banner + ")");

    SshConfig ssh_config;
    ssh_config.host = device.ip;
    ssh_config.port = defaults::kSshPort;
    ssh_config.username = options.ssh_user;
    ssh_config.password = password;
    ssh_config.host_key_policy =
        options.strict_host_key ? HostKeyPolicy::Strict : HostKeyPolicy::Warn;
    ssh_config.connect_timeout = options.auth_timeout;
    ssh_config.auth_timeout = options.auth_timeout;
    ssh_config.command_timeout = options.command_timeout;
    ssh_config.verbose = options.verbose;

    SshClient client(std::move(ssh_config));
    if (!client.connect_and_authenticate()) {
        std::cerr << "Error: " << client.last_error() << "\n";
        return client.last_error().find("authentication") != std::string::npos
                   ? kSshAuthFailed
                   : kSshConnectionFailed;
    }
    if (client.host_key_status() != "match" && !options.strict_host_key) {
        std::cerr << "WARNING: SSH host key not verified (status: " << client.host_key_status()
                  << "); the link is trusted because it is a direct connection.\n";
    }

    CommandResult command = client.execute("ifconfig");
    std::string source_command = "ifconfig";
    const bool ifconfig_usable = command.ok && command.exit_code == 0 &&
                                 !command.stdout_data.empty();
    if (!ifconfig_usable) {
        log(options, "ifconfig unavailable or failed, falling back to 'ip -4 addr'");
        CommandResult fallback = client.execute("ip -4 addr");
        if (!fallback.ok || fallback.exit_code != 0 || fallback.stdout_data.empty()) {
            std::cerr << "Error: ifconfig execution failed on the target";
            if (!command.error.empty()) {
                std::cerr << " (" << command.error << ")";
            } else if (!command.stderr_data.empty()) {
                std::cerr << " (" << command.stderr_data << ")";
            }
            std::cerr << " and the 'ip -4 addr' fallback failed as well.\n";
            client.disconnect();
            return kRemoteCommandFailed;
        }
        command = std::move(fallback);
        source_command = "ip -4 addr";
    }

    DiscoveryReport report;
    report.interface_name = iface.name;
    report.ssh_ip = device.ip;
    report.ssh_banner = device.banner;
    report.host_key_status = client.host_key_status();
    report.discovery_stage = stage;
    report.interfaces = source_command == "ifconfig"
                            ? parse_ifconfig_output(command.stdout_data)
                            : parse_ip_addr_output(command.stdout_data);
    client.disconnect();

    if (report.interfaces.empty()) {
        std::cerr << "Error: Could not parse network interfaces from '" << source_command
                  << "' output.\n";
        return kParseFailed;
    }
    if (report.interfaces.size() != 2) {
        report.warnings.push_back("expected two network interfaces but found " +
                                  std::to_string(report.interfaces.size()));
    }

    emit(options, report);
    return report.interfaces.size() == 2 ? kSuccess : kUnexpectedInterfaceCount;
}

}  // namespace
}  // namespace devdisc

int main(int argc, char** argv) {
    if (!devdisc::ensure_winsock_initialised()) {
        std::cerr << "Error: Winsock could not be initialised.\n";
        return devdisc::kUsageError;
    }

    devdisc::Options options;
    int exit_code = devdisc::kSuccess;
    if (!devdisc::parse_options(argc, argv, options, exit_code)) {
        return exit_code;
    }
    try {
        return devdisc::run(options);
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << "\n";
        return devdisc::kNoDevice;
    }
}
