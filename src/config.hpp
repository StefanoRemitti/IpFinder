#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace devdisc {

/// Central place for every tunable default. No magic numbers elsewhere.
namespace defaults {

constexpr std::size_t kThreadCount = 32;
constexpr uint16_t kSshPort = 22;

constexpr std::chrono::milliseconds kTcpConnectTimeout{750};
constexpr std::chrono::milliseconds kSshBannerTimeout{1000};
constexpr std::chrono::milliseconds kSshAuthTimeout{5000};
constexpr std::chrono::milliseconds kSshCommandTimeout{5000};
constexpr std::chrono::milliseconds kLayer2ListenWindow{4000};

/// Smallest prefix length (largest subnet) that the stage A sweep will scan.
/// A /22 means at most 1022 probed addresses, which stays bounded even on a
/// misconfigured link.
constexpr int kMinimumScanPrefix = 22;

constexpr const char* kSshUser = "root";
constexpr const char* kPasswordEnvVar = "DEVICE_SSH_PASSWORD";

}  // namespace defaults

/// Process exit codes.
enum ExitCode {
    kSuccess = 0,
    kUsageError = 2,
    kNoInterface = 3,
    kMultipleInterfaces = 4,
    kNoDevice = 5,
    kMultipleDevices = 6,
    kSshConnectionFailed = 7,
    kSshAuthFailed = 8,
    kRemoteCommandFailed = 9,
    kParseFailed = 10,
    kUnexpectedInterfaceCount = 11,
};

}  // namespace devdisc
