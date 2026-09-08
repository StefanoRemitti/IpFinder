#include "network/arp_discovery.hpp"

#include <chrono>
#include <string>
#include <vector>

#include "test_support.hpp"

using devdisc::L2DiscoveryResult;
using devdisc::L2Observation;
using devdisc::L2ObservationSource;
using devdisc::NeighbourEntry;
using devdisc::select_neighbour_entries;

namespace {

std::vector<NeighbourEntry> sample_cache() {
    return {
        NeighbourEntry{11, "192.168.10.50", "00:0c:29:4a:1b:2c", true},
        NeighbourEntry{11, "192.168.10.99", "00:00:00:00:00:00", true},
        NeighbourEntry{11, "192.168.10.77", "00:0c:29:4a:1b:33", false},
        NeighbourEntry{11, "224.0.0.22", "01:00:5e:00:00:16", true},
        NeighbourEntry{11, "255.255.255.255", "ff:ff:ff:ff:ff:ff", true},
        NeighbourEntry{7, "10.0.0.1", "aa:bb:cc:dd:ee:ff", true},
    };
}

void test_selects_resolved_entries_of_the_requested_interface() {
    const std::vector<L2Observation> observations = select_neighbour_entries(sample_cache(), 11);
    CHECK_EQ(observations.size(), std::size_t{1});
    CHECK_EQ(observations.front().ip, std::string("192.168.10.50"));
    CHECK_EQ(observations.front().mac, std::string("00:0c:29:4a:1b:2c"));
    CHECK(observations.front().source == L2ObservationSource::NeighbourCache);
}

void test_unknown_interface_yields_nothing() {
    CHECK_EQ(select_neighbour_entries(sample_cache(), 99).size(), std::size_t{0});
    CHECK_EQ(select_neighbour_entries({}, 11).size(), std::size_t{0});
}

void test_duplicate_addresses_are_merged() {
    const std::vector<NeighbourEntry> entries = {
        NeighbourEntry{11, "192.168.10.50", "00:0c:29:4a:1b:2c", true},
        NeighbourEntry{11, "192.168.10.50", "00:0c:29:4a:1b:2c", true},
    };
    CHECK_EQ(select_neighbour_entries(entries, 11).size(), std::size_t{1});
}

void test_ipv4_source_parsing() {
    unsigned char packet[20] = {};
    packet[0] = 0x45;  // IPv4, 20 byte header.
    packet[12] = 192;
    packet[13] = 168;
    packet[14] = 10;
    packet[15] = 50;
    CHECK_EQ(devdisc::parse_ipv4_source_address(packet, sizeof(packet)),
             std::string("192.168.10.50"));

    // Too short, wrong version and an inconsistent header length are rejected.
    CHECK_EQ(devdisc::parse_ipv4_source_address(packet, 10), std::string());
    CHECK_EQ(devdisc::parse_ipv4_source_address(nullptr, 20), std::string());
    packet[0] = 0x65;  // Version 6 in an IPv4 sized buffer.
    CHECK_EQ(devdisc::parse_ipv4_source_address(packet, sizeof(packet)), std::string());
    packet[0] = 0x4F;  // 60 byte header claimed in a 20 byte buffer.
    CHECK_EQ(devdisc::parse_ipv4_source_address(packet, sizeof(packet)), std::string());
}

void test_layer2_discovery_reports_diagnostic_without_privileges() {
    devdisc::NetworkInterface iface;
    iface.name = "definitely-not-an-adapter";
    iface.ipv4 = "192.168.10.20";
    iface.if_index = 0xFFFFFFFEu;
    const L2DiscoveryResult result =
        devdisc::discover_link_layer_hosts(iface, std::chrono::milliseconds(10));
    // Either the process is not elevated or the adapter does not exist: in both
    // cases a useful diagnostic must be produced instead of silently claiming
    // that no device exists.
    CHECK(result.observations.empty());
    CHECK(!result.error.empty());
}

void test_source_labels() {
    CHECK_EQ(devdisc::to_string(L2ObservationSource::ArpTraffic), std::string("arp"));
    CHECK_EQ(devdisc::to_string(L2ObservationSource::Ipv4Traffic), std::string("ipv4"));
    CHECK_EQ(devdisc::to_string(L2ObservationSource::NeighbourCache),
             std::string("neighbour-cache"));
}

}  // namespace

int main() {
    test_selects_resolved_entries_of_the_requested_interface();
    test_unknown_interface_yields_nothing();
    test_duplicate_addresses_are_merged();
    test_ipv4_source_parsing();
    test_layer2_discovery_reports_diagnostic_without_privileges();
    test_source_labels();
    return testing::finish("arp_discovery");
}
