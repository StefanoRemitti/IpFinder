#include "network/arp_discovery.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

namespace devdisc {
namespace {

constexpr std::size_t kMacLength = 6;
constexpr uint16_t kArpHardwareEthernet = 1;
constexpr uint16_t kArpProtocolIpv4 = 0x0800;
constexpr uint16_t kArpOpRequest = 1;

struct EthernetHeader {
    uint8_t destination[kMacLength];
    uint8_t source[kMacLength];
    uint16_t ethertype;
} __attribute__((packed));

struct ArpPacket {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;
    uint8_t sender_mac[kMacLength];
    uint8_t sender_ip[4];
    uint8_t target_mac[kMacLength];
    uint8_t target_ip[4];
} __attribute__((packed));

std::string format_mac(const uint8_t* mac) {
    std::array<char, 18> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
                  mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer.data());
}

std::string format_ipv4(const uint8_t* bytes) {
    in_addr addr{};
    std::memcpy(&addr, bytes, sizeof(addr));
    std::array<char, INET_ADDRSTRLEN> buffer{};
    if (::inet_ntop(AF_INET, &addr, buffer.data(), buffer.size()) == nullptr) {
        return {};
    }
    return std::string(buffer.data());
}

bool is_zero_mac(const std::string& mac) { return mac == "00:00:00:00:00:00"; }

void add_observation(std::vector<L2Observation>& observations, L2Observation candidate) {
    if (candidate.ip.empty() || candidate.ip == "0.0.0.0" || candidate.ip == "255.255.255.255") {
        return;
    }
    const auto existing = std::find_if(observations.begin(), observations.end(),
                                       [&](const L2Observation& o) { return o.ip == candidate.ip; });
    if (existing != observations.end()) {
        if (existing->mac.empty() || is_zero_mac(existing->mac)) {
            existing->mac = candidate.mac;
        }
        return;
    }
    observations.push_back(std::move(candidate));
}

bool read_interface_mac(int fd, const std::string& name, uint8_t (&out)[kMacLength]) {
    ifreq request{};
    std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, SIOCGIFHWADDR, &request) != 0) {
        return false;
    }
    std::memcpy(out, request.ifr_hwaddr.sa_data, kMacLength);
    return true;
}

void send_arp_announcement(int fd, int ifindex, const uint8_t (&mac)[kMacLength],
                           uint32_t ip_host_order) {
    std::array<uint8_t, sizeof(EthernetHeader) + sizeof(ArpPacket)> frame{};
    auto* ethernet = reinterpret_cast<EthernetHeader*>(frame.data());
    std::memset(ethernet->destination, 0xff, kMacLength);
    std::memcpy(ethernet->source, mac, kMacLength);
    ethernet->ethertype = htons(ETH_P_ARP);

    auto* arp = reinterpret_cast<ArpPacket*>(frame.data() + sizeof(EthernetHeader));
    arp->hardware_type = htons(kArpHardwareEthernet);
    arp->protocol_type = htons(kArpProtocolIpv4);
    arp->hardware_length = kMacLength;
    arp->protocol_length = 4;
    arp->operation = htons(kArpOpRequest);
    std::memcpy(arp->sender_mac, mac, kMacLength);
    const uint32_t ip_network_order = htonl(ip_host_order);
    std::memcpy(arp->sender_ip, &ip_network_order, sizeof(ip_network_order));
    std::memcpy(arp->target_ip, &ip_network_order, sizeof(ip_network_order));

    sockaddr_ll destination{};
    destination.sll_family = AF_PACKET;
    destination.sll_protocol = htons(ETH_P_ARP);
    destination.sll_ifindex = ifindex;
    destination.sll_halen = kMacLength;
    std::memset(destination.sll_addr, 0xff, kMacLength);

    // Best effort: the announcement only helps the peer to speak up, a failure
    // is not fatal for passive discovery.
    (void)::sendto(fd, frame.data(), frame.size(), 0,
                   reinterpret_cast<sockaddr*>(&destination), sizeof(destination));
}

}  // namespace

std::string to_string(L2ObservationSource source) {
    switch (source) {
        case L2ObservationSource::ArpTraffic:
            return "arp";
        case L2ObservationSource::Ipv4Traffic:
            return "ipv4";
        case L2ObservationSource::NeighbourCache:
            break;
    }
    return "neighbour-cache";
}

std::vector<L2Observation> parse_proc_net_arp(const std::string& contents,
                                              const std::string& interface_name) {
    std::vector<L2Observation> observations;
    std::istringstream stream(contents);
    std::string line;
    bool first = true;
    while (std::getline(stream, line)) {
        if (first) {  // Header row.
            first = false;
            continue;
        }
        std::istringstream fields(line);
        std::string ip;
        std::string hw_type;
        std::string flags;
        std::string mac;
        std::string mask;
        std::string device;
        if (!(fields >> ip >> hw_type >> flags >> mac >> mask >> device)) {
            continue;
        }
        if (device != interface_name || is_zero_mac(mac)) {
            continue;
        }
        L2Observation observation;
        observation.ip = ip;
        observation.mac = mac;
        observation.source = L2ObservationSource::NeighbourCache;
        add_observation(observations, std::move(observation));
    }
    return observations;
}

std::vector<L2Observation> read_neighbour_cache(const std::string& interface_name) {
    std::ifstream file("/proc/net/arp");
    if (!file) {
        return {};
    }
    std::ostringstream contents;
    contents << file.rdbuf();
    return parse_proc_net_arp(contents.str(), interface_name);
}

L2DiscoveryResult discover_link_layer_hosts(const NetworkInterface& iface,
                                            std::chrono::milliseconds listen_window) {
    L2DiscoveryResult result;
    for (L2Observation& observation : read_neighbour_cache(iface.name)) {
        if (observation.ip != iface.ipv4) {
            add_observation(result.observations, std::move(observation));
        }
    }

    const int fd = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) {
        result.permission_denied = (errno == EPERM || errno == EACCES);
        result.error = std::string("cannot open AF_PACKET socket on ") + iface.name + ": " +
                       std::strerror(errno);
        if (result.permission_denied) {
            result.error +=
                " (layer-2 discovery needs root or CAP_NET_RAW: "
                "sudo setcap cap_net_raw+ep ./device-discovery)";
        }
        return result;
    }

    struct FdGuard {
        int fd;
        ~FdGuard() { ::close(fd); }
    } guard{fd};

    const unsigned int ifindex = ::if_nametoindex(iface.name.c_str());
    if (ifindex == 0) {
        result.error = "if_nametoindex() failed for " + iface.name;
        return result;
    }

    sockaddr_ll bind_address{};
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = static_cast<int>(ifindex);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&bind_address), sizeof(bind_address)) != 0) {
        result.error = std::string("cannot bind AF_PACKET socket to ") + iface.name + ": " +
                       std::strerror(errno);
        return result;
    }

    uint8_t local_mac[kMacLength] = {};
    const bool have_mac = read_interface_mac(fd, iface.name, local_mac);
    if (have_mac) {
        send_arp_announcement(fd, static_cast<int>(ifindex), local_mac, iface.address);
    }

    const auto deadline = std::chrono::steady_clock::now() + listen_window;
    std::array<uint8_t, 2048> frame{};
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            break;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();

        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int poll_rc = 0;
        do {
            poll_rc = ::poll(&pfd, 1, static_cast<int>(remaining));
        } while (poll_rc < 0 && errno == EINTR);
        if (poll_rc <= 0) {
            break;
        }

        const ssize_t length = ::recv(fd, frame.data(), frame.size(), 0);
        if (length < static_cast<ssize_t>(sizeof(EthernetHeader))) {
            continue;
        }

        const auto* ethernet = reinterpret_cast<const EthernetHeader*>(frame.data());
        if (have_mac && std::memcmp(ethernet->source, local_mac, kMacLength) == 0) {
            continue;  // Our own transmissions.
        }

        const uint16_t ethertype = ntohs(ethernet->ethertype);
        const std::size_t payload_length =
            static_cast<std::size_t>(length) - sizeof(EthernetHeader);
        const uint8_t* payload = frame.data() + sizeof(EthernetHeader);

        if (ethertype == ETH_P_ARP && payload_length >= sizeof(ArpPacket)) {
            const auto* arp = reinterpret_cast<const ArpPacket*>(payload);
            if (ntohs(arp->protocol_type) != kArpProtocolIpv4 || arp->protocol_length != 4) {
                continue;
            }
            L2Observation observation;
            observation.ip = format_ipv4(arp->sender_ip);
            observation.mac = format_mac(arp->sender_mac);
            observation.source = L2ObservationSource::ArpTraffic;
            if (observation.ip != iface.ipv4) {
                add_observation(result.observations, std::move(observation));
            }
        } else if (ethertype == ETH_P_IP && payload_length >= 20) {
            L2Observation observation;
            observation.ip = format_ipv4(payload + 12);  // IPv4 source address.
            observation.mac = format_mac(ethernet->source);
            observation.source = L2ObservationSource::Ipv4Traffic;
            if (observation.ip != iface.ipv4) {
                add_observation(result.observations, std::move(observation));
            }
        }
    }

    if (result.observations.empty() && result.error.empty()) {
        result.error = "no station announced an IPv4 address on " + iface.name +
                       " during the layer-2 listening window";
    }
    return result;
}

}  // namespace devdisc
