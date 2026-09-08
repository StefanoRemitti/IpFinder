#include "parser/ifconfig_parser.hpp"

#include <string>

#include "test_support.hpp"

using devdisc::parse_ifconfig_output;
using devdisc::parse_ip_addr_output;
using devdisc::RemoteInterface;

namespace {

const char* kNetToolsOutput = R"(eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.10.50  netmask 255.255.255.0  broadcast 192.168.10.255
        inet6 fe80::20c:29ff:fe4a:1b2c  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:4a:1b:2c  txqueuelen 1000  (Ethernet)
        RX packets 1024  bytes 98765 (96.4 KiB)

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.20.30.1  netmask 255.255.255.0  broadcast 10.20.30.255
        ether 00:0c:29:4a:1b:36  txqueuelen 1000  (Ethernet)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
)";

const char* kBusyboxOutput = R"(ens33     Link encap:Ethernet  HWaddr 00:0C:29:4A:1B:2C
          inet addr:192.168.10.50  Bcast:192.168.10.255  Mask:255.255.255.0
          inet6 addr: fe80::20c:29ff:fe4a:1b2c/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1

enp2s0    Link encap:Ethernet  HWaddr 00:0C:29:4A:1B:36
          inet addr:10.20.30.1  Bcast:10.20.30.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
)";

const char* kIpAddrOutput = R"(1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 192.168.10.50/24 brd 192.168.10.255 scope global enp1s0
       valid_lft forever preferred_lft forever
3: enp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 10.20.30.1/24 brd 10.20.30.255 scope global enp2s0
       valid_lft forever preferred_lft forever
)";

void test_net_tools_format() {
    const std::vector<RemoteInterface> interfaces = parse_ifconfig_output(kNetToolsOutput);
    CHECK_EQ(interfaces.size(), std::size_t{2});
    CHECK_EQ(interfaces[0].name, std::string("eth0"));
    CHECK_EQ(interfaces[0].ipv4, std::string("192.168.10.50"));
    CHECK_EQ(interfaces[1].name, std::string("eth1"));
    CHECK_EQ(interfaces[1].ipv4, std::string("10.20.30.1"));
}

void test_busybox_format_and_alternative_names() {
    const std::vector<RemoteInterface> interfaces = parse_ifconfig_output(kBusyboxOutput);
    CHECK_EQ(interfaces.size(), std::size_t{2});
    CHECK_EQ(interfaces[0].name, std::string("ens33"));
    CHECK_EQ(interfaces[0].ipv4, std::string("192.168.10.50"));
    CHECK_EQ(interfaces[1].name, std::string("enp2s0"));
    CHECK_EQ(interfaces[1].ipv4, std::string("10.20.30.1"));
}

void test_ip_addr_fallback_format() {
    const std::vector<RemoteInterface> interfaces = parse_ip_addr_output(kIpAddrOutput);
    CHECK_EQ(interfaces.size(), std::size_t{2});
    CHECK_EQ(interfaces[0].name, std::string("enp1s0"));
    CHECK_EQ(interfaces[0].ipv4, std::string("192.168.10.50"));
    CHECK_EQ(interfaces[1].name, std::string("enp2s0"));
    CHECK_EQ(interfaces[1].ipv4, std::string("10.20.30.1"));
}

void test_ipv6_only_interface_is_ignored() {
    const char* output = R"(eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet6 2001:db8::1  prefixlen 64  scopeid 0x0<global>
        ether 00:0c:29:4a:1b:2c
)";
    CHECK_EQ(parse_ifconfig_output(output).size(), std::size_t{0});
}

void test_interface_without_address_is_ignored() {
    const char* output = R"(eth0: flags=4098<BROADCAST,MULTICAST>  mtu 1500
        ether 00:0c:29:4a:1b:2c  txqueuelen 1000  (Ethernet)

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.7  netmask 255.255.255.0
)";
    const std::vector<RemoteInterface> interfaces = parse_ifconfig_output(output);
    CHECK_EQ(interfaces.size(), std::size_t{1});
    CHECK_EQ(interfaces[0].name, std::string("eth1"));
}

void test_empty_and_garbage_input() {
    CHECK_EQ(parse_ifconfig_output("").size(), std::size_t{0});
    CHECK_EQ(parse_ifconfig_output("command not found\n").size(), std::size_t{0});
    CHECK_EQ(parse_ip_addr_output("").size(), std::size_t{0});
}

void test_more_than_two_interfaces_are_all_reported() {
    const char* output = R"(eth0: flags=4163<UP>  mtu 1500
        inet 192.168.0.2  netmask 255.255.255.0
eth1: flags=4163<UP>  mtu 1500
        inet 192.168.1.2  netmask 255.255.255.0
eth2: flags=4163<UP>  mtu 1500
        inet 192.168.2.2  netmask 255.255.255.0
)";
    CHECK_EQ(parse_ifconfig_output(output).size(), std::size_t{3});
}

void test_aliases_and_multiple_addresses() {
    const char* output = R"(enp1s0: flags=4163<UP>  mtu 1500
        inet 192.168.0.2  netmask 255.255.255.0
        inet 192.168.0.3  netmask 255.255.255.0
)";
    const std::vector<RemoteInterface> interfaces = parse_ifconfig_output(output);
    CHECK_EQ(interfaces.size(), std::size_t{2});
    CHECK_EQ(interfaces[0].ipv4, std::string("192.168.0.2"));
    CHECK_EQ(interfaces[1].ipv4, std::string("192.168.0.3"));
}

}  // namespace

int main() {
    test_net_tools_format();
    test_busybox_format_and_alternative_names();
    test_ip_addr_fallback_format();
    test_ipv6_only_interface_is_ignored();
    test_interface_without_address_is_ignored();
    test_empty_and_garbage_input();
    test_more_than_two_interfaces_are_all_reported();
    test_aliases_and_multiple_addresses();
    return testing::finish("ifconfig_parser");
}
