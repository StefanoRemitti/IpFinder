#include "platform/windows_sockets.hpp"

#include <mutex>
#include <vector>

namespace devdisc {
namespace {

/// Owns the WSAStartup()/WSACleanup() pair for the lifetime of the process.
class WinsockRuntime {
public:
    WinsockRuntime() {
        WSADATA data{};
        ready_ = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }
    ~WinsockRuntime() {
        if (ready_) {
            ::WSACleanup();
        }
    }
    WinsockRuntime(const WinsockRuntime&) = delete;
    WinsockRuntime& operator=(const WinsockRuntime&) = delete;

    bool ready() const { return ready_; }

private:
    bool ready_ = false;
};

}  // namespace

bool ensure_winsock_initialised() {
    // Function-local static: thread-safe initialisation, destroyed at exit.
    static WinsockRuntime runtime;
    return runtime.ready();
}

void close_socket(socket_t& handle) {
    if (handle != kInvalidSocket) {
        ::closesocket(handle);
        handle = kInvalidSocket;
    }
}

int last_socket_error() { return ::WSAGetLastError(); }

std::string socket_error_text(int error_code) {
    char* buffer = nullptr;
    const DWORD length = ::FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(error_code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<char*>(&buffer), 0, nullptr);
    if (length == 0 || buffer == nullptr) {
        return "Winsock error " + std::to_string(error_code);
    }
    std::string message(buffer, length);
    ::LocalFree(buffer);
    while (!message.empty() && (message.back() == '\r' || message.back() == '\n' ||
                               message.back() == ' ' || message.back() == '.')) {
        message.pop_back();
    }
    return message + " (error " + std::to_string(error_code) + ")";
}

bool set_non_blocking(socket_t handle) {
    u_long mode = 1;
    return ::ioctlsocket(handle, FIONBIO, &mode) == 0;
}

int wait_for_socket(socket_t handle, bool for_write, std::chrono::milliseconds timeout) {
    WSAPOLLFD descriptor{};
    descriptor.fd = handle;
    descriptor.events = static_cast<SHORT>(for_write ? POLLWRNORM : POLLRDNORM);
    const auto milliseconds = timeout.count() < 0 ? 0 : timeout.count();
    return ::WSAPoll(&descriptor, 1, static_cast<INT>(milliseconds));
}

bool is_process_elevated() {
    HANDLE token = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token) == 0) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    const bool ok =
        ::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != 0;
    ::CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

}  // namespace devdisc
