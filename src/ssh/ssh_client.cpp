#include "ssh/ssh_client.hpp"

#include <libssh2.h>
#include <unistd.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include "scanner/port_scanner.hpp"

namespace devdisc {
namespace {

std::once_flag g_libssh2_init_flag;
bool g_libssh2_ready = false;

void ensure_libssh2_initialised() {
    std::call_once(g_libssh2_init_flag, []() { g_libssh2_ready = libssh2_init(0) == 0; });
}

std::string libssh2_error_text(LIBSSH2_SESSION* session, const std::string& fallback) {
    if (session == nullptr) {
        return fallback;
    }
    char* message = nullptr;
    int length = 0;
    const int code = libssh2_session_last_error(session, &message, &length, 0);
    if (message == nullptr || length <= 0) {
        return fallback + " (libssh2 error " + std::to_string(code) + ")";
    }
    return fallback + ": " + std::string(message, static_cast<std::size_t>(length));
}

std::string default_known_hosts_path() {
    const char* home = std::getenv("HOME");
    if (home == nullptr || *home == '\0') {
        return {};
    }
    return std::string(home) + "/.ssh/known_hosts";
}

}  // namespace

struct SshClient::Impl {
    int socket_fd = -1;
    LIBSSH2_SESSION* session = nullptr;
};

SshClient::SshClient(SshConfig config) : config_(std::move(config)), impl_(new Impl()) {}

SshClient::~SshClient() {
    disconnect();
    delete impl_;
    impl_ = nullptr;
}

bool SshClient::connect_and_authenticate() {
    ensure_libssh2_initialised();
    if (!g_libssh2_ready) {
        last_error_ = "libssh2 initialisation failed";
        return false;
    }

    int fd = -1;
    const ConnectResult connect_result =
        tcp_connect(config_.host, config_.port, config_.connect_timeout, fd);
    if (connect_result != ConnectResult::Connected) {
        last_error_ = "SSH connection failed (" + to_string(connect_result) + ")";
        return false;
    }
    impl_->socket_fd = fd;

    impl_->session = libssh2_session_init();
    if (impl_->session == nullptr) {
        last_error_ = "could not create SSH session";
        disconnect();
        return false;
    }
    libssh2_session_set_blocking(impl_->session, 1);
    libssh2_session_set_timeout(impl_->session,
                                static_cast<long>(config_.auth_timeout.count()));

    if (libssh2_session_handshake(impl_->session, impl_->socket_fd) != 0) {
        last_error_ = libssh2_error_text(impl_->session, "SSH handshake failed");
        disconnect();
        return false;
    }

    // ---- Host key verification -------------------------------------------
    std::string known_hosts_path = config_.known_hosts_path.empty() ? default_known_hosts_path()
                                                                    : config_.known_hosts_path;
    size_t key_length = 0;
    int key_type = 0;
    const char* host_key = libssh2_session_hostkey(impl_->session, &key_length, &key_type);
    host_key_status_ = "unknown";
    if (host_key != nullptr && !known_hosts_path.empty()) {
        LIBSSH2_KNOWNHOSTS* known_hosts = libssh2_knownhost_init(impl_->session);
        if (known_hosts != nullptr) {
            libssh2_knownhost_readfile(known_hosts, known_hosts_path.c_str(),
                                       LIBSSH2_KNOWNHOST_FILE_OPENSSH);
            const int type_mask =
                LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW |
                ((key_type == LIBSSH2_HOSTKEY_TYPE_RSA) ? LIBSSH2_KNOWNHOST_KEY_SSHRSA : 0);
            const int check =
                libssh2_knownhost_checkp(known_hosts, config_.host.c_str(), config_.port, host_key,
                                         key_length, type_mask, nullptr);
            switch (check) {
                case LIBSSH2_KNOWNHOST_CHECK_MATCH:
                    host_key_status_ = "match";
                    break;
                case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
                    host_key_status_ = "mismatch";
                    break;
                case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
                    host_key_status_ = "unknown";
                    break;
                default:
                    host_key_status_ = "check-failure";
                    break;
            }
            libssh2_knownhost_free(known_hosts);
        }
    }
    if (config_.host_key_policy == HostKeyPolicy::Strict && host_key_status_ != "match") {
        last_error_ = "SSH host key verification failed (status: " + host_key_status_ +
                      "); add the key to known_hosts or run without --strict-host-key";
        disconnect();
        return false;
    }

    // ---- Authentication ---------------------------------------------------
    if (libssh2_userauth_password(impl_->session, config_.username.c_str(),
                                  config_.password.c_str()) != 0) {
        // Deliberately generic: never reveal the credential material.
        last_error_ = "SSH authentication failed for user '" + config_.username + "'";
        disconnect();
        return false;
    }
    return true;
}

CommandResult SshClient::execute(const std::string& command) {
    CommandResult result;
    if (impl_ == nullptr || impl_->session == nullptr) {
        result.error = "no authenticated SSH session";
        return result;
    }

    libssh2_session_set_timeout(impl_->session,
                                static_cast<long>(config_.command_timeout.count()));

    LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(impl_->session);
    if (channel == nullptr) {
        result.error = libssh2_error_text(impl_->session, "could not open SSH channel");
        return result;
    }

    if (libssh2_channel_exec(channel, command.c_str()) != 0) {
        result.error = libssh2_error_text(impl_->session, "remote command execution failed");
        libssh2_channel_free(channel);
        return result;
    }

    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t bytes = libssh2_channel_read(channel, buffer.data(), buffer.size());
        if (bytes > 0) {
            result.stdout_data.append(buffer.data(), static_cast<std::size_t>(bytes));
            continue;
        }
        break;
    }
    for (;;) {
        const ssize_t bytes = libssh2_channel_read_stderr(channel, buffer.data(), buffer.size());
        if (bytes > 0) {
            result.stderr_data.append(buffer.data(), static_cast<std::size_t>(bytes));
            continue;
        }
        break;
    }

    libssh2_channel_close(channel);
    result.exit_code = libssh2_channel_get_exit_status(channel);
    libssh2_channel_free(channel);
    result.ok = true;
    return result;
}

void SshClient::disconnect() {
    if (impl_ == nullptr) {
        return;
    }
    if (impl_->session != nullptr) {
        libssh2_session_disconnect(impl_->session, "device-discovery finished");
        libssh2_session_free(impl_->session);
        impl_->session = nullptr;
    }
    if (impl_->socket_fd >= 0) {
        ::close(impl_->socket_fd);
        impl_->socket_fd = -1;
    }
}

}  // namespace devdisc
