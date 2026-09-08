#include "network/arp_discovery.hpp"

#include <chrono>

#include "test_support.hpp"

using devdisc::L2DiscoveryResult;
using devdisc::L2Observation;
using devdisc::L2ObservationSource;
using devdisc::parse_proc_net_arp;

namespace {

const char* kProcNetArp =
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.10.50    0x1         0x2         00:0c:29:4a:1b:2c     *        enp3s0\n"
    "192.168.10.99    0x1         0x0         00:00:00:00:00:00     *        enp3s0\n"
    "10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n";

void test_parses_entries_of_the_requested_interface() {
    const std::vector<L2Observation> observations = parse_proc_net_arp(kProcNetArp, "enp3s0");
    CHECK_EQ(observations.size(), std::size_t{1});
    CHECK_EQ(observations.front().ip, std::string("192.168.10.50"));
    CHECK_EQ(observations.front().mac, std::string("00:0c:29:4a:1b:2c"));
    CHECK(observations.front().source == L2ObservationSource::NeighbourCache);
}

void test_unknown_interface_yields_nothing() {
    CHECK_EQ(parse_proc_net_arp(kProcNetArp, "eth9").size(), std::size_t{0});
    CHECK_EQ(parse_proc_net_arp("", "enp3s0").size(), std::size_t{0});
    CHECK_EQ(parse_proc_net_arp("garbage line without fields\n", "enp3s0").size(), std::size_t{0});
}

void test_layer2_discovery_reports_diagnostic_without_privileges() {
    devdisc::NetworkInterface iface;
    iface.name = "definitely-not-an-interface";
    iface.ipv4 = "192.168.10.20";
    const L2DiscoveryResult result =
        devdisc::discover_link_layer_hosts(iface, std::chrono::milliseconds(10));
    // Either we lack CAP_NET_RAW or the interface does not exist: in both cases
    // a useful diagnostic must be produced instead of silently claiming that no
    // device exists.
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
    test_parses_entries_of_the_requested_interface();
    test_unknown_interface_yields_nothing();
    test_layer2_discovery_reports_diagnostic_without_privileges();
    test_source_labels();
    return testing::finish("arp_discovery");
}
