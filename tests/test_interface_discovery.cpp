#include "network/interface_discovery.hpp"

#include "test_support.hpp"

using devdisc::filter_candidate_interfaces;
using devdisc::InterfaceSnapshot;
using devdisc::is_virtual_interface_name;
using devdisc::NetworkInterface;

namespace {

InterfaceSnapshot make(const std::string& name, const std::string& ip, const std::string& mask,
                       bool up = true, bool running = true, bool loopback = false,
                       const std::string& description = "") {
    InterfaceSnapshot snapshot;
    snapshot.name = name;
    snapshot.description = description;
    snapshot.ipv4 = ip;
    snapshot.netmask = mask;
    snapshot.has_ipv4 = !ip.empty();
    snapshot.is_up = up;
    snapshot.is_running = running;
    snapshot.is_loopback = loopback;
    return snapshot;
}

void test_single_ethernet_interface() {
    const std::vector<InterfaceSnapshot> snapshots = {
        make("Loopback Pseudo-Interface 1", "127.0.0.1", "255.0.0.0", true, true, true),
        make("Ethernet 2", "192.168.10.20", "255.255.255.0"),
    };
    const std::vector<NetworkInterface> candidates = filter_candidate_interfaces(snapshots);
    CHECK_EQ(candidates.size(), std::size_t{1});
    CHECK_EQ(candidates.front().name, std::string("Ethernet 2"));
    CHECK_EQ(candidates.front().prefix_length(), 24);
    CHECK_EQ(candidates.front().usable_host_count(), uint64_t{254});
}

void test_loopback_only() {
    const std::vector<InterfaceSnapshot> snapshots = {
        make("Loopback Pseudo-Interface 1", "127.0.0.1", "255.0.0.0", true, true, true)};
    CHECK_EQ(filter_candidate_interfaces(snapshots).size(), std::size_t{0});
}

void test_multiple_candidates_are_all_reported() {
    const std::vector<InterfaceSnapshot> snapshots = {
        make("Ethernet", "192.168.1.5", "255.255.255.0"),
        make("Ethernet 3", "10.0.0.5", "255.255.255.0"),
    };
    CHECK_EQ(filter_candidate_interfaces(snapshots).size(), std::size_t{2});
}

void test_interface_without_ipv4_is_ignored() {
    std::vector<InterfaceSnapshot> snapshots = {make("Ethernet 4", "", "")};
    CHECK_EQ(filter_candidate_interfaces(snapshots).size(), std::size_t{0});
}

void test_down_interface_is_ignored() {
    const std::vector<InterfaceSnapshot> snapshots = {
        make("Ethernet", "192.168.1.5", "255.255.255.0", false, false)};
    CHECK_EQ(filter_candidate_interfaces(snapshots).size(), std::size_t{0});

    const std::vector<InterfaceSnapshot> no_carrier = {
        make("Ethernet", "192.168.1.5", "255.255.255.0", true, false)};
    CHECK_EQ(filter_candidate_interfaces(no_carrier).size(), std::size_t{0});
}

void test_virtual_interfaces_are_ignored() {
    CHECK(is_virtual_interface_name("vEthernet (Default Switch)"));
    CHECK(is_virtual_interface_name("VMware Network Adapter VMnet1"));
    CHECK(is_virtual_interface_name("VirtualBox Host-Only Network"));
    CHECK(is_virtual_interface_name("Loopback Pseudo-Interface 1"));
    CHECK(is_virtual_interface_name("TAP-Windows Adapter V9"));
    CHECK(is_virtual_interface_name("Bluetooth Network Connection"));
    CHECK(is_virtual_interface_name("docker0"));
    CHECK(!is_virtual_interface_name("Ethernet"));
    CHECK(!is_virtual_interface_name("Ethernet 2"));
    CHECK(!is_virtual_interface_name("Wi-Fi"));

    // The description is checked as well: Windows names an adapter "Ethernet 5"
    // even when it is a Hyper-V virtual switch port.
    const std::vector<InterfaceSnapshot> snapshots = {
        make("Ethernet 5", "172.17.0.1", "255.255.0.0", true, true, false,
             "Hyper-V Virtual Ethernet Adapter"),
        make("Ethernet 2", "192.168.10.20", "255.255.255.0"),
    };
    const std::vector<NetworkInterface> candidates = filter_candidate_interfaces(snapshots);
    CHECK_EQ(candidates.size(), std::size_t{1});
    CHECK_EQ(candidates.front().name, std::string("Ethernet 2"));
}

void test_network_arithmetic() {
    const std::vector<InterfaceSnapshot> snapshots = {
        make("Ethernet", "192.168.10.20", "255.255.255.128")};
    const NetworkInterface iface = filter_candidate_interfaces(snapshots).front();
    CHECK_EQ(iface.prefix_length(), 25);
    CHECK_EQ(iface.network(), uint32_t{0xC0A80A00});
    CHECK_EQ(iface.broadcast(), uint32_t{0xC0A80A7F});
    CHECK_EQ(iface.usable_host_count(), uint64_t{126});
}

void test_real_enumeration_contains_loopback() {
    // Sanity check against the live system: loopback always exists.
    bool has_loopback = false;
    for (const InterfaceSnapshot& snapshot : devdisc::enumerate_interfaces()) {
        has_loopback = has_loopback || snapshot.is_loopback;
    }
    CHECK(has_loopback);
}

}  // namespace

int main() {
    test_single_ethernet_interface();
    test_loopback_only();
    test_multiple_candidates_are_all_reported();
    test_interface_without_ipv4_is_ignored();
    test_down_interface_is_ignored();
    test_virtual_interfaces_are_ignored();
    test_network_arithmetic();
    test_real_enumeration_contains_loopback();
    return testing::finish("interface_discovery");
}
