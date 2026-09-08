#include "output/formatter.hpp"

#include "test_support.hpp"

using devdisc::DiscoveryReport;
using devdisc::format_json;
using devdisc::format_text;

namespace {

DiscoveryReport make_report() {
    DiscoveryReport report;
    report.interface_name = "enp3s0";
    report.ssh_ip = "192.168.10.50";
    report.ssh_banner = "SSH-2.0-OpenSSH_9.6";
    report.host_key_status = "unknown";
    report.discovery_stage = "subnet-scan";
    report.interfaces = {{"eth0", "192.168.10.50"}, {"eth1", "10.20.30.1"}};
    return report;
}

void test_text_output() {
    const std::string text = format_text(make_report());
    CHECK(text.find("Directly connected device discovered") != std::string::npos);
    CHECK(text.find("SSH-2.0-OpenSSH_9.6") != std::string::npos);
    CHECK(text.find("eth0") != std::string::npos);
    CHECK(text.find("10.20.30.1") != std::string::npos);
}

void test_json_output() {
    const std::string json = format_json(make_report());
    CHECK(json.find("\"ssh_ip\": \"192.168.10.50\"") != std::string::npos);
    CHECK(json.find("\"ssh_banner\": \"SSH-2.0-OpenSSH_9.6\"") != std::string::npos);
    CHECK(json.find("\"name\": \"eth1\"") != std::string::npos);
    CHECK(json.find("\"ipv4\": \"10.20.30.1\"") != std::string::npos);
}

void test_warnings_are_reported() {
    DiscoveryReport report = make_report();
    report.interfaces.push_back({"eth2", "172.16.0.1"});
    report.warnings.push_back("expected two network interfaces but found 3");
    const std::string text = format_text(report);
    CHECK(text.find("WARNING: expected two network interfaces but found 3") != std::string::npos);
    const std::string json = format_json(report);
    CHECK(json.find("expected two network interfaces but found 3") != std::string::npos);
}

void test_empty_report_is_valid_json() {
    const std::string json = format_json(DiscoveryReport{});
    CHECK(json.find("\"interfaces\": []") != std::string::npos);
    CHECK(json.find("\"warnings\": []") != std::string::npos);
}

void test_json_escaping() {
    CHECK_EQ(devdisc::json_escape("a\"b\\c"), std::string("a\\\"b\\\\c"));
    CHECK_EQ(devdisc::json_escape("line\nbreak"), std::string("line\\nbreak"));
}

}  // namespace

int main() {
    test_text_output();
    test_json_output();
    test_warnings_are_reported();
    test_empty_report_is_valid_json();
    test_json_escaping();
    return testing::finish("formatter");
}
