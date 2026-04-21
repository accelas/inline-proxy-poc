#include "proxy/config.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <cstddef>
#include <charconv>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <filesystem>
#include <iostream>
#include <list>
#include <memory>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>

#include "proxy/admin_http.hpp"
#include "proxy/interface_registry.hpp"
#include "proxy/relay_session.hpp"
#include "proxy/state_reconciler.hpp"
#include "proxy/transparent_listener.hpp"
#include "proxy/transparent_socket.hpp"
#include "shared/event_loop.hpp"
#include "shared/netlink.hpp"
#include "shared/scoped_fd.hpp"
#include "shared/sockaddr.hpp"

#include <linux/rtnetlink.h>

extern char** environ;

namespace inline_proxy {
namespace {

constexpr std::string_view kAdminPortEnv = "INLINE_PROXY_ADMIN_PORT";
constexpr std::string_view kAdminAddressEnv = "INLINE_PROXY_ADMIN_ADDRESS";
constexpr std::string_view kTransparentPortEnv = "INLINE_PROXY_TRANSPARENT_PORT";
constexpr std::string_view kTransparentAddressEnv = "INLINE_PROXY_TRANSPARENT_ADDRESS";
constexpr std::string_view kInterceptPortEnv = "INLINE_PROXY_INTERCEPT_PORT";
constexpr std::string_view kPreserveClientPortEnv = "INLINE_PROXY_PRESERVE_CLIENT_PORT";
constexpr std::string_view kDebugDirectResponseEnv = "INLINE_PROXY_DEBUG_DIRECT_RESPONSE";
constexpr std::string_view kDebugDirectWithUpstreamEnv = "INLINE_PROXY_DEBUG_DIRECT_WITH_UPSTREAM";
constexpr std::string_view kDebugDirectLargeResponseEnv = "INLINE_PROXY_DEBUG_DIRECT_LARGE_RESPONSE";
constexpr std::string_view kDebugDirectFullUpstreamEnv = "INLINE_PROXY_DEBUG_DIRECT_FULL_UPSTREAM";
constexpr std::string_view kDebugDirectHoldOpenMsEnv = "INLINE_PROXY_DEBUG_DIRECT_HOLD_OPEN_MS";
constexpr std::string_view kDebugDirectNonblockingClientEnv = "INLINE_PROXY_DEBUG_DIRECT_NONBLOCKING_CLIENT";
constexpr std::string_view kDebugDirectLocalizeSourceEnv = "INLINE_PROXY_DEBUG_DIRECT_LOCALIZE_SOURCE";
constexpr std::string_view kDebugDirectUpstreamConnectOnlyEnv =
    "INLINE_PROXY_DEBUG_DIRECT_UPSTREAM_CONNECT_ONLY";
constexpr std::string_view kDebugDirectReleaseSourceAfterConnectEnv =
    "INLINE_PROXY_DEBUG_DIRECT_RELEASE_SOURCE_AFTER_CONNECT";
constexpr std::string_view kDebugDirectCloseUpstreamBeforeResponseEnv =
    "INLINE_PROXY_DEBUG_DIRECT_CLOSE_UPSTREAM_BEFORE_RESPONSE";
constexpr std::string_view kDebugDirectCloseUpstreamAfterResponseEnv =
    "INLINE_PROXY_DEBUG_CLOSE_UPSTREAM_AFTER_RESPONSE";
constexpr std::string_view kDebugSyncRelayEnv = "INLINE_PROXY_DEBUG_SYNC_RELAY";
constexpr std::string_view kDebugSyncConnectTimeoutEnv = "INLINE_PROXY_DEBUG_SYNC_CONNECT_TIMEOUT_MS";
constexpr std::string_view kDebugSyncNonblockingClientEnv = "INLINE_PROXY_DEBUG_SYNC_NONBLOCKING_CLIENT";
constexpr std::string_view kDebugSyncHoldOpenMsEnv = "INLINE_PROXY_DEBUG_SYNC_HOLD_OPEN_MS";
constexpr std::string_view kUseProxySourceEnv = "INLINE_PROXY_USE_PROXY_SOURCE";
constexpr std::string_view kSkipLocalSourceEnv = "INLINE_PROXY_SKIP_LOCAL_SOURCE";
constexpr std::string_view kDebugCloseUpstreamOnFirstResponseEnv =
    "INLINE_PROXY_DEBUG_CLOSE_UPSTREAM_ON_FIRST_RESPONSE";
constexpr std::string_view kDebugShutdownUpstreamOnFirstResponseEnv =
    "INLINE_PROXY_DEBUG_SHUTDOWN_UPSTREAM_ON_FIRST_RESPONSE";
constexpr std::string_view kDebugDetachUpstreamOnFirstResponseEnv =
    "INLINE_PROXY_DEBUG_DETACH_UPSTREAM_ON_FIRST_RESPONSE";
constexpr std::string_view kDebugCloseClientOnFirstResponseEnv =
    "INLINE_PROXY_DEBUG_CLOSE_CLIENT_ON_FIRST_RESPONSE";
constexpr std::string_view kAdminAddressPrefix = "--admin-address=";
constexpr std::string_view kAdminPrefix = "--admin-port=";
constexpr std::string_view kTransparentAddressPrefix = "--transparent-address=";
constexpr std::string_view kTransparentPrefix = "--transparent-port=";
constexpr std::string_view kInterceptPrefix = "--intercept-port=";
constexpr std::string_view kInlineProxyPrefix = "INLINE_PROXY_";
constexpr std::uint32_t kTransparentRoutingMark = 0x100;
constexpr std::uint32_t kTransparentRoutingTable = 100;

AdminSendHook& AdminSendHookRef() {
    static AdminSendHook hook = nullptr;
    return hook;
}

struct PlainListener {
    ScopedFd fd;

    bool ok() const noexcept {
        return fd.valid();
    }

    int fd_num() const noexcept {
        return fd.get();
    }

    explicit operator bool() const noexcept {
        return ok();
    }
};

bool EnsureTransparentRoutingRule() {
    // Equivalent of:
    //   ip route replace local 0.0.0.0/0 dev lo table <kTransparentRoutingTable>
    RouteConfig route;
    route.cidr = "default";
    route.oif = "lo";
    route.table = kTransparentRoutingTable;
    route.type = RTN_LOCAL;
    route.scope = RT_SCOPE_HOST;
    const bool route_ok = AddRoute(route, /*replace=*/true);

    // `ip rule add` is not idempotent — repeated calls create duplicates
    // at successive priorities. Drain any existing copies of this rule
    // before adding exactly one. DeleteRule returns false once the kernel
    // is out of matching rules (ENOENT), which terminates the loop.
    RuleConfig rule;
    rule.fwmark = kTransparentRoutingMark;
    rule.table = kTransparentRoutingTable;
    constexpr int kMaxDeleteIters = 256;
    for (int i = 0; i < kMaxDeleteIters; ++i) {
        if (!DeleteRule(rule)) {
            break;
        }
    }
    const bool rule_ok = AddRule(rule);
    return route_ok && rule_ok;
}

std::uint16_t ParsePortOrThrow(std::string_view value, std::string_view source) {
    unsigned int parsed = 0;
    const char* begin = value.data();
    const char* end = value.data() + value.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end || parsed == 0 || parsed > 65535U) {
        throw std::invalid_argument(std::string(source) + " must be a port number between 1 and 65535");
    }
    return static_cast<std::uint16_t>(parsed);
}

std::string ParseAddressOrThrow(std::string_view value, std::string_view source) {
    if (value.empty()) {
        throw std::invalid_argument(std::string(source) + " must not be empty");
    }
    in_addr ipv4{};
    if (::inet_pton(AF_INET, std::string(value).c_str(), &ipv4) != 1) {
        throw std::invalid_argument(std::string(source) + " must be a valid IPv4 address");
    }
    return std::string(value);
}

struct CliParseResult {
    bool admin_address_seen = false;
    bool admin_seen = false;
    bool transparent_address_seen = false;
    bool transparent_seen = false;
    bool intercept_seen = false;
};

CliParseResult ParseCliOverrides(ProxyConfig& cfg, int argc, char** argv) {
    CliParseResult seen;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i] ? argv[i] : "");
        if (arg.rfind(kAdminAddressPrefix, 0) == 0) {
            cfg.admin_address =
                ParseAddressOrThrow(arg.substr(kAdminAddressPrefix.size()), kAdminAddressPrefix);
            seen.admin_address_seen = true;
            continue;
        }
        if (arg.rfind(kAdminPrefix, 0) == 0) {
            cfg.admin_port = ParsePortOrThrow(arg.substr(kAdminPrefix.size()), kAdminPrefix);
            seen.admin_seen = true;
            continue;
        }
        if (arg.rfind(kTransparentAddressPrefix, 0) == 0) {
            cfg.transparent_address = ParseAddressOrThrow(
                arg.substr(kTransparentAddressPrefix.size()), kTransparentAddressPrefix);
            seen.transparent_address_seen = true;
            continue;
        }
        if (arg.rfind(kTransparentPrefix, 0) == 0) {
            cfg.transparent_port = ParsePortOrThrow(arg.substr(kTransparentPrefix.size()), kTransparentPrefix);
            seen.transparent_seen = true;
            continue;
        }
        if (arg.rfind(kInterceptPrefix, 0) == 0) {
            cfg.intercept_port = ParsePortOrThrow(arg.substr(kInterceptPrefix.size()), kInterceptPrefix);
            seen.intercept_seen = true;
            continue;
        }
        throw std::invalid_argument(std::string("unknown CLI flag: ") + std::string(arg));
    }
    return seen;
}

void ApplyOverride(ProxyConfig& cfg, std::string_view name, std::string_view value) {
    if (name == kAdminAddressEnv) {
        cfg.admin_address = ParseAddressOrThrow(value, kAdminAddressEnv);
        return;
    }
    if (name == kAdminPortEnv) {
        cfg.admin_port = ParsePortOrThrow(value, kAdminPortEnv);
        return;
    }
    if (name == kTransparentAddressEnv) {
        cfg.transparent_address = ParseAddressOrThrow(value, kTransparentAddressEnv);
        return;
    }
    if (name == kTransparentPortEnv) {
        cfg.transparent_port = ParsePortOrThrow(value, kTransparentPortEnv);
        return;
    }
    if (name == kInterceptPortEnv) {
        cfg.intercept_port = ParsePortOrThrow(value, kInterceptPortEnv);
        return;
    }
    if (name == kPreserveClientPortEnv) {
        return;
    }
    if (name == kDebugDirectResponseEnv) {
        return;
    }
    if (name == kDebugDirectWithUpstreamEnv) {
        return;
    }
    if (name == kDebugDirectLargeResponseEnv) {
        return;
    }
    if (name == kDebugDirectFullUpstreamEnv) {
        return;
    }
    if (name == kDebugDirectHoldOpenMsEnv) {
        return;
    }
    if (name == kDebugDirectNonblockingClientEnv) {
        return;
    }
    if (name == kDebugDirectLocalizeSourceEnv) {
        return;
    }
    if (name == kDebugDirectUpstreamConnectOnlyEnv) {
        return;
    }
    if (name == kDebugDirectReleaseSourceAfterConnectEnv) {
        return;
    }
    if (name == kDebugDirectCloseUpstreamBeforeResponseEnv) {
        return;
    }
    if (name == kDebugDirectCloseUpstreamAfterResponseEnv) {
        return;
    }
    if (name == kDebugShutdownUpstreamOnFirstResponseEnv) {
        return;
    }
    if (name == kDebugDetachUpstreamOnFirstResponseEnv) {
        return;
    }
    if (name == kDebugCloseClientOnFirstResponseEnv) {
        return;
    }
    if (name == kDebugSyncRelayEnv) {
        return;
    }
    if (name == kDebugSyncConnectTimeoutEnv) {
        return;
    }
    if (name == kDebugSyncNonblockingClientEnv) {
        return;
    }
    if (name == kDebugSyncHoldOpenMsEnv) {
        return;
    }
    if (name == kDebugCloseUpstreamOnFirstResponseEnv) {
        return;
    }
    if (name == kUseProxySourceEnv) {
        return;
    }
    if (name == kSkipLocalSourceEnv) {
        return;
    }
    throw std::invalid_argument(std::string("unknown env key: ") + std::string(name));
}

void ApplyEnvOverrides(ProxyConfig& cfg, std::initializer_list<ProxyConfig::EnvOverride> env) {
    for (const auto& [name, value] : env) {
        ApplyOverride(cfg, name, value);
    }
}

void ApplyProcessEnvOverrides(ProxyConfig& cfg, const CliParseResult& cli) {
    for (char** env = environ; env != nullptr && *env != nullptr; ++env) {
        std::string_view entry(*env);
        const std::size_t eq = entry.find('=');
        if (eq == std::string_view::npos) {
            continue;
        }

        const std::string_view name = entry.substr(0, eq);
        const std::string_view value = entry.substr(eq + 1);
        if (name.rfind(kInlineProxyPrefix, 0) != 0) {
            continue;
        }

        if (name == kAdminAddressEnv) {
            if (!cli.admin_address_seen) {
                cfg.admin_address = ParseAddressOrThrow(value, kAdminAddressEnv);
            }
            continue;
        }
        if (name == kAdminPortEnv) {
            if (!cli.admin_seen) {
                cfg.admin_port = ParsePortOrThrow(value, kAdminPortEnv);
            }
            continue;
        }

        if (name == kTransparentAddressEnv) {
            if (!cli.transparent_address_seen) {
                cfg.transparent_address = ParseAddressOrThrow(value, kTransparentAddressEnv);
            }
            continue;
        }
        if (name == kTransparentPortEnv) {
            if (!cli.transparent_seen) {
                cfg.transparent_port = ParsePortOrThrow(value, kTransparentPortEnv);
            }
            continue;
        }
        if (name == kInterceptPortEnv) {
            if (!cli.intercept_seen) {
                cfg.intercept_port = ParsePortOrThrow(value, kInterceptPortEnv);
            }
            continue;
        }
        if (name == kPreserveClientPortEnv) {
            continue;
        }
        if (name == kDebugDirectResponseEnv) {
            continue;
        }
        if (name == kDebugDirectWithUpstreamEnv) {
            continue;
        }
        if (name == kDebugDirectLargeResponseEnv) {
            continue;
        }
        if (name == kDebugDirectFullUpstreamEnv) {
            continue;
        }
        if (name == kDebugDirectHoldOpenMsEnv) {
            continue;
        }
        if (name == kDebugDirectNonblockingClientEnv) {
            continue;
        }
        if (name == kDebugDirectLocalizeSourceEnv) {
            continue;
        }
        if (name == kDebugDirectUpstreamConnectOnlyEnv) {
            continue;
        }
        if (name == kDebugDirectReleaseSourceAfterConnectEnv) {
            continue;
        }
        if (name == kDebugDirectCloseUpstreamBeforeResponseEnv) {
            continue;
        }
        if (name == kDebugDirectCloseUpstreamAfterResponseEnv) {
            continue;
        }
        if (name == kDebugShutdownUpstreamOnFirstResponseEnv) {
            continue;
        }
        if (name == kDebugDetachUpstreamOnFirstResponseEnv) {
            continue;
        }
        if (name == kDebugCloseClientOnFirstResponseEnv) {
            continue;
        }
        if (name == kDebugSyncRelayEnv) {
            continue;
        }
        if (name == kDebugSyncConnectTimeoutEnv) {
            continue;
        }
        if (name == kDebugSyncNonblockingClientEnv) {
            continue;
        }
        if (name == kDebugSyncHoldOpenMsEnv) {
            continue;
        }
        if (name == kDebugCloseUpstreamOnFirstResponseEnv) {
            continue;
        }
        if (name == kUseProxySourceEnv) {
            continue;
        }
        if (name == kSkipLocalSourceEnv) {
            continue;
        }

        throw std::invalid_argument(std::string("unknown env key: ") + std::string(name));
    }
}

bool DebugDirectResponseEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectResponseEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugDirectWithUpstreamEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectWithUpstreamEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugDirectLargeResponseEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectLargeResponseEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugDirectFullUpstreamEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectFullUpstreamEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

int DebugDirectHoldOpenMs() {
    const char* value = std::getenv(std::string(kDebugDirectHoldOpenMsEnv).c_str());
    if (value == nullptr || *value == '\0') {
        return 0;
    }
    try {
        const int parsed = std::stoi(value);
        return parsed > 0 ? parsed : 0;
    } catch (...) {
        return 0;
    }
}

bool DebugDirectNonblockingClientEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectNonblockingClientEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugDirectLocalizeSourceEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectLocalizeSourceEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugDirectUpstreamConnectOnlyEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectUpstreamConnectOnlyEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugDirectReleaseSourceAfterConnectEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectReleaseSourceAfterConnectEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugDirectCloseUpstreamBeforeResponseEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectCloseUpstreamBeforeResponseEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugDirectCloseUpstreamAfterResponseEnabled() {
    const char* value = std::getenv(std::string(kDebugDirectCloseUpstreamAfterResponseEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugSyncRelayEnabled() {
    const char* value = std::getenv(std::string(kDebugSyncRelayEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

int DebugSyncConnectTimeoutMs() {
    const char* value = std::getenv(std::string(kDebugSyncConnectTimeoutEnv).c_str());
    if (value == nullptr || *value == '\0') {
        return 3000;
    }
    try {
        const int parsed = std::stoi(value);
        return parsed > 0 ? parsed : 3000;
    } catch (...) {
        return 3000;
    }
}

bool DebugSyncNonblockingClientEnabled() {
    const char* value = std::getenv(std::string(kDebugSyncNonblockingClientEnv).c_str());
    return value != nullptr && std::string_view(value) == "1";
}

int DebugSyncHoldOpenMs() {
    const char* value = std::getenv(std::string(kDebugSyncHoldOpenMsEnv).c_str());
    if (value == nullptr || *value == '\0') {
        return 0;
    }
    try {
        const int parsed = std::stoi(value);
        return parsed > 0 ? parsed : 0;
    } catch (...) {
        return 0;
    }
}

bool CompleteDebugConnect(int fd) {
    pollfd pfd{
        .fd = fd,
        .events = POLLOUT,
        .revents = 0,
    };
    const int ready = ::poll(&pfd, 1, DebugSyncConnectTimeoutMs());
    std::cerr << "debug connect poll"
              << " fd=" << fd
              << " ready=" << ready
              << " revents=" << pfd.revents
              << '\n';
    if (ready != 1) {
        return false;
    }
    int socket_error = 0;
    socklen_t len = sizeof(socket_error);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &len) != 0) {
        std::cerr << "debug connect getsockopt failed"
                  << " fd=" << fd
                  << " errno=" << errno
                  << " error=" << std::strerror(errno)
                  << '\n';
        return false;
    }
    std::cerr << "debug connect so_error"
              << " fd=" << fd
              << " so_error=" << socket_error
              << '\n';
    return socket_error == 0;
}

bool WaitReadable(int fd, int timeout_ms) {
    pollfd pfd{.fd = fd, .events = POLLIN, .revents = 0};
    return ::poll(&pfd, 1, timeout_ms) == 1;
}

bool SendAllDebug(int fd, const char* data, std::size_t size) {
    std::size_t offset = 0;
    while (offset < size) {
        const ssize_t n = ::send(fd, data + offset, size - offset, MSG_NOSIGNAL);
        if (n > 0) {
            offset += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!WaitReadable(fd, 1000)) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

std::vector<std::string> DebugWanInterfaces() {
    std::vector<std::string> interfaces;
    for (const auto& entry : std::filesystem::directory_iterator("/sys/class/net")) {
        const auto name = entry.path().filename().string();
        if (name.rfind("wan_", 0) == 0) {
            interfaces.push_back(name);
        }
    }
    return interfaces;
}

std::vector<std::string> DebugAcquireLocalSource(const sockaddr_storage& addr) {
    std::vector<std::string> installed;
    if (addr.ss_family != AF_INET) {
        return installed;
    }

    const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(addr);
    for (const auto& ifname : DebugWanInterfaces()) {
        if (!AddLocalAddress(ifname, ipv4.sin_addr, 32)) {
            for (const auto& added : installed) {
                (void)RemoveLocalAddress(added, ipv4.sin_addr, 32);
            }
            installed.clear();
            break;
        }
        installed.push_back(ifname);
    }
    return installed;
}

void DebugReleaseLocalSource(const sockaddr_storage& addr,
                             const std::vector<std::string>& interfaces) {
    if (addr.ss_family != AF_INET) {
        return;
    }
    const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(addr);
    for (const auto& ifname : interfaces) {
        (void)RemoveLocalAddress(ifname, ipv4.sin_addr, 32);
    }
}

bool DriveDebugSyncRelay(ScopedFd& accepted, const SessionEndpoints& endpoints) {
    if (DebugSyncNonblockingClientEnabled() && !SetNonBlocking(accepted.get())) {
        std::cerr << "debug sync relay failed to set nonblocking client"
                  << " errno=" << errno
                  << " error=" << std::strerror(errno)
                  << '\n';
        return false;
    }
    char request[4096];
    if (!WaitReadable(accepted.get(), 3000)) {
        std::cerr << "debug sync relay client wait timeout"
                  << " client=" << FormatSockaddr(endpoints.client)
                  << " original_dst=" << FormatSockaddr(endpoints.original_dst)
                  << '\n';
        return false;
    }
    const ssize_t request_n = ::recv(accepted.get(), request, sizeof(request), 0);
    if (request_n <= 0) {
        std::cerr << "debug sync relay client recv failed"
                  << " request_n=" << request_n
                  << " errno=" << errno
                  << " error=" << std::strerror(errno)
                  << '\n';
        return false;
    }
    std::cerr << "debug sync relay client recv"
              << " bytes=" << request_n
              << '\n';

    const auto debug_local_source = DebugAcquireLocalSource(endpoints.client);
    auto upstream = CreateTransparentSocket(endpoints.client, endpoints.original_dst);
    if (!upstream) {
        std::cerr << "debug sync relay upstream create failed"
                  << " client=" << FormatSockaddr(endpoints.client)
                  << " original_dst=" << FormatSockaddr(endpoints.original_dst)
                  << " errno=" << errno
                  << " error=" << std::strerror(errno)
                  << '\n';
        DebugReleaseLocalSource(endpoints.client, debug_local_source);
        return false;
    }
    if (upstream.connecting && !CompleteDebugConnect(upstream.fd.get())) {
        std::cerr << "debug sync relay upstream connect incomplete"
                  << " local=" << FormatSockaddr(GetSockName(upstream.fd.get()))
                  << " peer=" << FormatSockaddr(GetPeer(upstream.fd.get()))
                  << '\n';
        DebugReleaseLocalSource(endpoints.client, debug_local_source);
        return false;
    }
    if (!SendAllDebug(upstream.fd.get(), request, static_cast<std::size_t>(request_n))) {
        std::cerr << "debug sync relay upstream send failed"
                  << " errno=" << errno
                  << " error=" << std::strerror(errno)
                  << '\n';
        DebugReleaseLocalSource(endpoints.client, debug_local_source);
        return false;
    }
    std::cerr << "debug sync relay upstream send ok"
              << " bytes=" << request_n
              << '\n';

    std::string response;
    response.reserve(32768);
    char buffer[4096];
    while (WaitReadable(upstream.fd.get(), 1000)) {
        const ssize_t n = ::recv(upstream.fd.get(), buffer, sizeof(buffer), 0);
        if (n > 0) {
            response.append(buffer, buffer + n);
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
        DebugReleaseLocalSource(endpoints.client, debug_local_source);
        return false;
    }
    std::cerr << "debug sync relay upstream recv"
              << " bytes=" << response.size()
              << '\n';

    if (response.empty()) {
        DebugReleaseLocalSource(endpoints.client, debug_local_source);
        return false;
    }
    const bool sent = SendAllDebug(accepted.get(), response.data(), response.size());
    std::cerr << "debug sync relay downstream send"
              << " bytes=" << response.size()
              << " ok=" << sent
              << " errno=" << errno
              << " error=" << std::strerror(errno)
              << '\n';
    if (sent) {
        if (const int hold_open_ms = DebugSyncHoldOpenMs(); hold_open_ms > 0) {
            ::poll(nullptr, 0, hold_open_ms);
        }
    }
    DebugReleaseLocalSource(endpoints.client, debug_local_source);
    return sent;
}

struct DebugUpstreamContext {
    ScopedFd fd;
    sockaddr_storage local_source{};
    std::vector<std::string> interfaces;
};

void DriveDebugUpstream(DebugUpstreamContext& ctx, const SessionEndpoints& endpoints) {
    if (DebugDirectLocalizeSourceEnabled()) {
        ctx.local_source = endpoints.client;
        ctx.interfaces = DebugAcquireLocalSource(endpoints.client);
    }

    auto upstream = CreateTransparentSocket(endpoints.client, endpoints.original_dst);
    if (!upstream) {
        return;
    }
    if (upstream.connecting && !CompleteDebugConnect(upstream.fd.get())) {
        return;
    }
    if (!ctx.interfaces.empty() && DebugDirectReleaseSourceAfterConnectEnabled()) {
        DebugReleaseLocalSource(ctx.local_source, ctx.interfaces);
        ctx.interfaces.clear();
        ctx.local_source = {};
    }
    if (DebugDirectUpstreamConnectOnlyEnabled()) {
        ctx.fd = std::move(upstream.fd);
        return;
    }

    static constexpr char kDebugRequest[] =
        "GET / HTTP/1.1\r\n"
        "Host: debug\r\n"
        "Connection: close\r\n"
        "\r\n";
    (void)::send(upstream.fd.get(),
                 kDebugRequest,
                 sizeof(kDebugRequest) - 1,
                 MSG_NOSIGNAL);

    std::string buffer(4096, '\0');
    pollfd pfd{
        .fd = upstream.fd.get(),
        .events = POLLIN,
        .revents = 0,
    };
    if (::poll(&pfd, 1, 3000) == 1) {
        (void)::recv(upstream.fd.get(), buffer.data(), buffer.size(), 0);
    }

    if (DebugDirectCloseUpstreamBeforeResponseEnabled()) {
        upstream.fd.reset();
    }
    ctx.fd = std::move(upstream.fd);
}

PlainListener CreatePlainListener(const std::string& address, std::uint16_t port) {
    PlainListener listener;
    listener.fd.reset(::socket(AF_INET, SOCK_STREAM, 0));
    if (!listener.fd) {
        return listener;
    }

    const int reuse = 1;
    if (::setsockopt(listener.fd.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        return PlainListener{};
    }

    const auto bind_addr = MakeSockaddr4(address, port);
    if (bind_addr.ss_family != AF_INET) {
        return PlainListener{};
    }

    if (::bind(listener.fd.get(),
               reinterpret_cast<const sockaddr*>(&bind_addr),
               sizeof(sockaddr_in)) != 0) {
        return PlainListener{};
    }

    if (::listen(listener.fd.get(), 128) != 0) {
        return PlainListener{};
    }

    if (!SetNonBlocking(listener.fd.get())) {
        return PlainListener{};
    }

    return listener;
}

std::string HttpStatusText(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 503: return "Service Unavailable";
        default: return "Unknown";
    }
}

std::string FormatHttpResponse(const AdminResponse& response) {
    std::string out;
    out += "HTTP/1.1 ";
    out += std::to_string(response.status);
    out += ' ';
    out += HttpStatusText(response.status);
    out += "\r\n";
    out += "Content-Type: ";
    out += response.content_type;
    out += "\r\n";
    out += "Content-Length: ";
    out += std::to_string(response.body.size());
    out += "\r\n";
    out += "Connection: close\r\n\r\n";
    out += response.body;
    return out;
}

bool RequestComplete(const std::string& request) {
    return request.find("\r\n\r\n") != std::string::npos || request.find("\n\n") != std::string::npos;
}

std::pair<std::string_view, std::string_view> ParseRequestLine(const std::string& request) {
    const auto line_end = request.find('\n');
    const std::string_view line = line_end == std::string::npos
        ? std::string_view(request)
        : std::string_view(request.data(), line_end);

    const auto method_end = line.find(' ');
    if (method_end == std::string_view::npos) {
        return {};
    }
    const auto path_end = line.find(' ', method_end + 1);
    if (path_end == std::string_view::npos) {
        return {};
    }
    return {line.substr(0, method_end), line.substr(method_end + 1, path_end - method_end - 1)};
}

class AdminConnection : public std::enable_shared_from_this<AdminConnection> {
public:
    AdminConnection(EventLoop& loop, ScopedFd fd, AdminHttp& admin_http)
        : loop_(loop), fd_(std::move(fd)), admin_http_(admin_http) {}

    void Arm() {
        auto weak = weak_from_this();
        handle_ = loop_.Register(
            fd_.get(),
            true,
            false,
            [weak] {
                if (auto self = weak.lock()) {
                    self->OnReadable();
                }
            },
            [weak] {
                if (auto self = weak.lock()) {
                    self->OnWritable();
                }
            },
            [weak](int) {
                if (auto self = weak.lock()) {
                    self->Close();
                }
            });
    }

    bool closed() const noexcept {
        return closed_;
    }

private:
    void OnReadable() {
        char buffer[4096];
        while (true) {
            const ssize_t n = ::read(fd_.get(), buffer, sizeof(buffer));
            if (n > 0) {
                request_.append(buffer, buffer + n);
                if (request_.size() > 16 * 1024) {
                    PrepareResponse(400, "request too large\n");
                    return;
                }
                if (RequestComplete(request_)) {
                    PrepareResponse();
                    return;
                }
                continue;
            }
            if (n == 0) {
                if (!request_.empty()) {
                    PrepareResponse();
                } else {
                    Close();
                }
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            Close();
            return;
        }
    }

    void OnWritable() {
        while (response_offset_ < response_.size()) {
            const ssize_t n = DoAdminSend(fd_.get(),
                                          response_.data() + response_offset_,
                                          response_.size() - response_offset_,
                                          MSG_NOSIGNAL);
            if (n > 0) {
                response_offset_ += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
            Close();
            return;
        }
        Close();
    }

    void PrepareResponse(int status, std::string body) {
        response_ = FormatHttpResponse(AdminResponse{
            .status = status,
            .content_type = "text/plain; charset=utf-8",
            .body = std::move(body),
        });
        response_offset_ = 0;
        if (handle_) {
            handle_->Update(false, true);
        }
    }

    void PrepareResponse() {
        const auto [method, path] = ParseRequestLine(request_);
        if (method.empty() || path.empty()) {
            PrepareResponse(400, "bad request\n");
            return;
        }

        auto response = admin_http_.Handle(method, path);
        response_ = FormatHttpResponse(response);
        response_offset_ = 0;
        if (handle_) {
            handle_->Update(false, true);
        }
    }

    void Close() {
        if (closed_) {
            return;
        }
        closed_ = true;
        if (handle_) {
            handle_.reset();
        }
        fd_.reset();
    }

    EventLoop& loop_;
    ScopedFd fd_;
    AdminHttp& admin_http_;
    std::unique_ptr<EventLoop::Handle> handle_;
    std::string request_;
    std::string response_;
    std::size_t response_offset_ = 0;
    bool closed_ = false;
};

void PruneClosedSessions(std::list<std::shared_ptr<RelaySession>>& sessions) {
    for (auto it = sessions.begin(); it != sessions.end();) {
        if (!*it || (*it)->closed()) {
            it = sessions.erase(it);
            continue;
        }
        ++it;
    }
}

template <typename T>
void PruneClosedConnections(std::list<std::shared_ptr<T>>& items) {
    for (auto it = items.begin(); it != items.end();) {
        if (!*it || (*it)->closed()) {
            it = items.erase(it);
            continue;
        }
        ++it;
    }
}

}  // namespace

void SetAdminSendHookForTesting(AdminSendHook hook) {
    AdminSendHookRef() = hook;
}

ssize_t DoAdminSend(int fd, const void* buffer, size_t length, int flags) {
    if (auto hook = AdminSendHookRef()) {
        return hook(fd, buffer, length, flags);
    }
    return ::send(fd, buffer, length, flags);
}

ProxyConfig ProxyConfig::FromEnv(std::initializer_list<EnvOverride> env) {
    ProxyConfig cfg;
    ApplyEnvOverrides(cfg, env);
    return cfg;
}

ProxyConfig ProxyConfig::FromArgs(int argc, char** argv) {
    ProxyConfig cfg;
    const CliParseResult cli = ParseCliOverrides(cfg, argc, argv);
    ApplyProcessEnvOverrides(cfg, cli);
    return cfg;
}

bool InstallTransparentRoutingRule() {
    return EnsureTransparentRoutingRule();
}

int RunProxyDaemon(const ProxyConfig& cfg) {
    ProxyState state;
    state.set_ready(false);

    if (!EnsureTransparentRoutingRule()) {
        std::cerr << "failed to install transparent routing rule\n";
        return 1;
    }

    InterfaceRegistry registry;
    StateReconciler state_reconciler;
    auto admin_listener = CreatePlainListener(cfg.admin_address, cfg.admin_port);
    if (!admin_listener) {
        std::cerr << "failed to create admin listener on port " << cfg.admin_port << '\n';
        return 1;
    }

    auto transparent_listener = CreateTransparentListener(cfg.transparent_address, cfg.transparent_port);
    if (!transparent_listener) {
        std::cerr << "failed to create transparent listener on port " << cfg.transparent_port << '\n';
        return 1;
    }

    if (!registry.ConfigureIngressListener(transparent_listener.fd(), cfg.intercept_port)) {
        std::cerr << "failed to configure ingress listener for transparent port " << cfg.transparent_port << '\n';
        return 1;
    }

    const std::string admin_interface_name = "lan_listener_" + std::to_string(cfg.admin_port);
    if (!registry.RecordInterface(admin_interface_name)) {
        std::cerr << "failed to record admin interface " << admin_interface_name << '\n';
        return 1;
    }

    auto admin_http = BuildAdminHttp(state, registry);
    state_reconciler.Sync(registry);

    state.set_ready(true);
    auto& loop = state.loop();

    std::list<std::shared_ptr<RelaySession>> sessions;
    std::list<std::shared_ptr<AdminConnection>> admin_connections;
    std::list<DebugUpstreamContext> debug_upstreams;

    std::function<void()> sweep;
    sweep = [&] {
        state_reconciler.Sync(registry);
        PruneClosedSessions(sessions);
        PruneClosedConnections(admin_connections);
        loop.Schedule(std::chrono::seconds(1), sweep);
    };
    loop.Schedule(std::chrono::seconds(1), sweep);

    auto admin_handle = loop.Register(
        admin_listener.fd_num(),
        true,
        false,
        [&] {
            while (true) {
                const int accepted_fd = ::accept(admin_listener.fd_num(), nullptr, nullptr);
                if (accepted_fd < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    break;
                }

                ScopedFd accepted(accepted_fd);
                if (!SetNonBlocking(accepted.get())) {
                    continue;
                }

                auto connection = std::make_shared<AdminConnection>(
                    loop, std::move(accepted), admin_http);
                connection->Arm();
                admin_connections.push_back(std::move(connection));
            }
        },
        {},
        {});

    auto transparent_handle = loop.Register(
        transparent_listener.fd(),
        true,
        false,
        [&] {
            while (true) {
                const int accepted_fd = ::accept(transparent_listener.fd(), nullptr, nullptr);
                if (accepted_fd < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    break;
                }

                ScopedFd accepted(accepted_fd);
                SessionEndpoints endpoints{
                    .client = GetPeer(accepted.get()),
                    .original_dst = GetSockName(accepted.get()),
                };
                std::cerr << "accepted transparent connection"
                          << " client=" << FormatSockaddr(endpoints.client)
                          << " original_dst=" << FormatSockaddr(endpoints.original_dst)
                          << '\n';
                if (DebugDirectResponseEnabled() && DebugDirectNonblockingClientEnabled() &&
                    !SetNonBlocking(accepted.get())) {
                    accepted.reset();
                    continue;
                }
                if (DebugSyncRelayEnabled()) {
                    (void)DriveDebugSyncRelay(accepted, endpoints);
                    accepted.reset();
                    continue;
                }
                if (!SetNonBlocking(accepted.get())) {
                    continue;
                }
                if (DebugDirectResponseEnabled()) {
                    if (DebugDirectWithUpstreamEnabled()) {
                        DebugUpstreamContext debug_upstream;
                        if (DebugDirectFullUpstreamEnabled()) {
                            DriveDebugUpstream(debug_upstream, endpoints);
                        } else {
                            auto upstream = CreateTransparentSocket(endpoints.client, endpoints.original_dst);
                            if (upstream) {
                                debug_upstream.fd = std::move(upstream.fd);
                            }
                        }
                        if (debug_upstream.fd) {
                            debug_upstreams.push_back(std::move(debug_upstream));
                        }
                    }
                    std::string body = DebugDirectLargeResponseEnabled()
                        ? std::string(18880, 'x')
                        : std::string("ok");
                    std::string response = "HTTP/1.1 200 OK\r\nContent-Length: " +
                                           std::to_string(body.size()) +
                                           "\r\nConnection: close\r\n\r\n" + body;
                    (void)::send(accepted.get(),
                                 response.data(),
                                 response.size(),
                                 MSG_NOSIGNAL);
                    if (DebugDirectCloseUpstreamAfterResponseEnabled()) {
                        debug_upstreams.clear();
                    }
                    if (const int hold_open_ms = DebugDirectHoldOpenMs(); hold_open_ms > 0) {
                        ::poll(nullptr, 0, hold_open_ms);
                    }
                    accepted.reset();
                    continue;
                }
                auto session = CreateRelaySession(
                    loop,
                    std::move(accepted),
                    endpoints,
                    [&loop, &sessions, &state, &registry] {
                        state.decrement_sessions();
                        registry.DecrementSessions();
                        loop.Defer([&sessions] { PruneClosedSessions(sessions); });
                    });
                if (!session) {
                    continue;
                }

                state.increment_sessions();
                registry.IncrementSessions();
                sessions.push_back(std::move(session));
            }
        },
        {},
        {});

    (void)admin_handle;
    (void)transparent_handle;

    loop.Run();
    for (auto& ctx : debug_upstreams) {
        DebugReleaseLocalSource(ctx.local_source, ctx.interfaces);
    }
    state.set_ready(false);
    bool cleanup_ok = true;
    if (!registry.RemoveInterface(admin_interface_name)) {
        std::cerr << "failed to remove admin interface " << admin_interface_name << '\n';
        cleanup_ok = false;
    }
    return cleanup_ok ? 0 : 1;
}

}  // namespace inline_proxy
