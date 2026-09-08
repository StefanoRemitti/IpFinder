#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace devdisc {

/// Host-key verification policy.
///
/// The default policy is Warn: the host key is recorded/compared against
/// %USERPROFILE%\.ssh\known_hosts and a mismatch or an unknown key is reported on stderr,
/// but the connection continues. This is documented in the README: on a
/// directly connected, physically isolated link there is no known key on the
/// first run. Use Strict to abort on unknown or mismatching keys.
enum class HostKeyPolicy {
    Warn,
    Strict,
};

struct SshConfig {
    std::string host;
    uint16_t port = 22;
    std::string username = "root";
    std::string password;  ///< Never logged, never printed.
    HostKeyPolicy host_key_policy = HostKeyPolicy::Warn;
    std::chrono::milliseconds connect_timeout{5000};
    std::chrono::milliseconds auth_timeout{5000};
    std::chrono::milliseconds command_timeout{5000};
    std::string known_hosts_path;  ///< Empty: %USERPROFILE%\.ssh\known_hosts.
    bool verbose = false;
};

struct CommandResult {
    bool ok = false;
    int exit_code = -1;
    std::string stdout_data;
    std::string stderr_data;
    std::string error;  ///< Set when the command could not be run at all.
};

/// Thin RAII wrapper around libssh2 providing password authentication and
/// remote command execution with timeouts.
class SshClient {
public:
    explicit SshClient(SshConfig config);
    ~SshClient();

    SshClient(const SshClient&) = delete;
    SshClient& operator=(const SshClient&) = delete;

    /// Connects, performs the handshake, checks the host key and authenticates.
    /// Returns false and fills last_error() on failure. The error message never
    /// contains the password.
    bool connect_and_authenticate();

    /// Runs `command` on the remote host and captures stdout/stderr.
    CommandResult execute(const std::string& command);

    /// Closes the session cleanly. Safe to call multiple times.
    void disconnect();

    const std::string& last_error() const { return last_error_; }
    const std::string& host_key_status() const { return host_key_status_; }

private:
    struct Impl;
    SshConfig config_;
    std::string last_error_;
    std::string host_key_status_;
    Impl* impl_ = nullptr;
};

}  // namespace devdisc
