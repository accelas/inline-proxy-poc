#include "proxy/relay_session.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <ifaddrs.h>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>
#include <unordered_map>
#include <sys/socket.h>
#include <unistd.h>

#include <utility>

#include "shared/netlink.hpp"
#include "shared/sockaddr.hpp"

namespace inline_proxy {
namespace {

constexpr std::size_t kReadChunkBytes = 16 * 1024;
constexpr std::size_t kMaxBufferedBytes = 128 * 1024;

SendHook& SendHookRef() {
    static SendHook hook = nullptr;
    return hook;
}

ShutdownHook& ShutdownHookRef() {
    static ShutdownHook hook = nullptr;
    return hook;
}

AcquireLocalSourceHook& AcquireLocalSourceHookRef() {
    static AcquireLocalSourceHook hook = nullptr;
    return hook;
}

ReleaseLocalSourceHook& ReleaseLocalSourceHookRef() {
    static ReleaseLocalSourceHook hook = nullptr;
    return hook;
}

ssize_t DoSend(int fd, const void* buffer, size_t length, int flags) {
    if (auto hook = SendHookRef()) {
        return hook(fd, buffer, length, flags);
    }
    return ::send(fd, buffer, length, flags);
}

int DoShutdown(int fd, int how) {
    if (auto hook = ShutdownHookRef()) {
        return hook(fd, how);
    }
    return ::shutdown(fd, how);
}

std::size_t PendingBytes(const std::string& buffer, std::size_t offset) {
    return offset < buffer.size() ? buffer.size() - offset : 0;
}

bool DebugCloseUpstreamOnFirstResponseEnabled() {
    const char* value = std::getenv("INLINE_PROXY_DEBUG_CLOSE_UPSTREAM_ON_FIRST_RESPONSE");
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugShutdownUpstreamOnFirstResponseEnabled() {
    const char* value = std::getenv("INLINE_PROXY_DEBUG_SHUTDOWN_UPSTREAM_ON_FIRST_RESPONSE");
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugDetachUpstreamOnFirstResponseEnabled() {
    const char* value = std::getenv("INLINE_PROXY_DEBUG_DETACH_UPSTREAM_ON_FIRST_RESPONSE");
    return value != nullptr && std::string_view(value) == "1";
}

bool DebugCloseClientOnFirstResponseEnabled() {
    const char* value = std::getenv("INLINE_PROXY_DEBUG_CLOSE_CLIENT_ON_FIRST_RESPONSE");
    return value != nullptr && std::string_view(value) == "1";
}

void CompactBuffer(std::string& buffer, std::size_t& offset) {
    if (offset == 0) {
        return;
    }
    if (offset >= buffer.size()) {
        buffer.clear();
        offset = 0;
        return;
    }
    if (offset >= kReadChunkBytes || offset * 2 >= buffer.size()) {
        buffer.erase(0, offset);
        offset = 0;
    }
}

class LocalSourceManager {
public:
    bool Acquire(const sockaddr_storage& addr) {
        if (addr.ss_family != AF_INET) {
            return true;
        }

        const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(addr);
        const std::uint32_t key = ipv4.sin_addr.s_addr;

        std::lock_guard<std::mutex> lock(mu_);
        auto& entry = refs_[key];
        if (entry.refs == 0) {
            // Do not add a /32 copy of the client IP if it is already
            // locally assigned in this netns, or if it is a next-hop
            // gateway referenced in any route (meaning the IP lives in
            // another netns — for example the cni0 bridge IP in k3s —
            // and adding a /32 here would break ARP resolution for every
            // pod in the netns).
            if (IsLocallyAssigned(ipv4.sin_addr) ||
                IsGatewayAddress(ipv4.sin_addr)) {
                entry.interfaces.clear();
                ++entry.refs;
                return true;
            }
            entry.interfaces = CandidateInterfaces();
            if (entry.interfaces.empty()) {
                entry.interfaces = {"lo"};
            }
            for (const auto& ifname : entry.interfaces) {
                if (AddLocalAddress(ifname, ipv4.sin_addr, 32)) {
                    continue;
                }
                for (const auto& added : entry.interfaces) {
                    if (added == ifname) {
                        break;
                    }
                    (void)RemoveLocalAddress(added, ipv4.sin_addr, 32);
                }
                entry.interfaces.clear();
                refs_.erase(key);
                return false;
            }
        }
        ++entry.refs;
        return true;
    }

    void Release(const sockaddr_storage& addr) {
        if (addr.ss_family != AF_INET) {
            return;
        }

        const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(addr);
        const std::uint32_t key = ipv4.sin_addr.s_addr;

        std::lock_guard<std::mutex> lock(mu_);
        const auto it = refs_.find(key);
        if (it == refs_.end()) {
            return;
        }

        if (it->second.refs > 1) {
            --it->second.refs;
            return;
        }

        // interfaces is empty iff Acquire short-circuited because the IP was
        // already locally assigned; nothing to remove in that case.
        for (const auto& ifname : it->second.interfaces) {
            (void)RemoveLocalAddress(ifname, ipv4.sin_addr, 32);
        }
        refs_.erase(it);
    }

private:
    struct RefEntry {
        std::size_t refs = 0;
        std::vector<std::string> interfaces;
    };

    // True if the given IP is assigned locally to any interface in this
    // netns. Same-netns lookup via getifaddrs.
    static bool IsLocallyAssigned(const in_addr& address) {
        ifaddrs* interfaces = nullptr;
        if (::getifaddrs(&interfaces) != 0) {
            return false;
        }
        bool found = false;
        for (ifaddrs* c = interfaces; c != nullptr; c = c->ifa_next) {
            if (c->ifa_addr == nullptr || c->ifa_addr->sa_family != AF_INET) {
                continue;
            }
            const auto& v4 = reinterpret_cast<const sockaddr_in&>(*c->ifa_addr);
            if (v4.sin_addr.s_addr == address.s_addr) {
                found = true;
                break;
            }
        }
        ::freeifaddrs(interfaces);
        return found;
    }

    // True if the given IP is a next-hop gateway referenced in any IPv4
    // route in this netns. Reads /proc/net/route, which is netns-local.
    // Used to avoid AddLocalAddress for IPs that are actually OFF-netns
    // (e.g. the cni0 bridge gateway IP 10.42.0.1 in k3s) — assigning a /32
    // of such an IP to wan_ causes the kernel to suppress ARP replies for
    // every address whose subnet overlaps the conflicting /32, breaking
    // host↔pod connectivity throughout the netns.
    static bool IsGatewayAddress(const in_addr& address) {
        // Use /proc/self/net/route to read the CURRENT THREAD'S netns
        // view (not the host's). /proc/net/route is an alias for
        // /proc/self/net/route in most kernels but we prefer to be
        // explicit.
        std::ifstream route("/proc/self/net/route");
        if (!route) return false;
        std::string line;
        std::getline(route, line);  // header
        while (std::getline(route, line)) {
            // Fields: Iface Destination Gateway Flags RefCnt Use Metric ...
            std::istringstream is(line);
            std::string iface, dst_hex, gw_hex;
            if (!(is >> iface >> dst_hex >> gw_hex)) continue;
            if (gw_hex.size() != 8) continue;
            // Gateway field is stored as 8-hex little-endian (host byte
            // order). Parse it to a uint32 and compare to in_addr.s_addr
            // (which is already in network byte order — but reading
            // /proc/net/route gives LE → reverse). Simpler: reverse the
            // hex string to LE→BE then compare.
            std::uint32_t gw_le = 0;
            try {
                gw_le = static_cast<std::uint32_t>(std::stoul(gw_hex, nullptr, 16));
            } catch (...) {
                continue;
            }
            // /proc/net/route stores the gateway as the kernel's in_addr
            // (network byte order), printed byte-reversed as hex. For
            // example 0x0100002A is 10.0.0.42 in network order.
            if (gw_le == address.s_addr) {
                return true;
            }
        }
        return false;
    }

    // Enumerate `wan_*` interfaces in the CURRENT netns. Uses getifaddrs
    // rather than scanning /sys/class/net because sysfs is not remounted
    // when a process enters a new netns via setns (it still reflects the
    // initial namespace), so a sysfs scan returns an empty or wrong
    // result for processes that joined a netns after startup — notably
    // the test harness, which calls ScopedNetns::Enter before
    // RecordInterface. getifaddrs invokes a netlink RTM_GETADDR in the
    // calling thread's netns and therefore sees the correct interface
    // list regardless of how the thread arrived in that netns.
    static std::vector<std::string> CandidateInterfaces() {
        std::vector<std::string> interfaces;
        ifaddrs* all = nullptr;
        if (::getifaddrs(&all) != 0) {
            return interfaces;
        }
        std::set<std::string> seen;
        for (ifaddrs* c = all; c != nullptr; c = c->ifa_next) {
            if (c->ifa_name == nullptr) continue;
            const std::string name(c->ifa_name);
            if (name.rfind("wan_", 0) == 0 && seen.insert(name).second) {
                interfaces.push_back(name);
            }
        }
        ::freeifaddrs(all);
        return interfaces;
    }

    std::mutex mu_;
    std::unordered_map<std::uint32_t, RefEntry> refs_;
};

LocalSourceManager& LocalSourceManagerRef() {
    static LocalSourceManager manager;
    return manager;
}

bool AcquireLocalSourceAddress(const sockaddr_storage& addr) {
    if (auto hook = AcquireLocalSourceHookRef()) {
        return hook(addr);
    }
    return LocalSourceManagerRef().Acquire(addr);
}

void ReleaseLocalSourceAddress(const sockaddr_storage& addr) {
    if (auto hook = ReleaseLocalSourceHookRef()) {
        hook(addr);
        return;
    }
    LocalSourceManagerRef().Release(addr);
}

}  // namespace

void SetSendHookForTesting(SendHook hook) {
    SendHookRef() = hook;
}

void SetShutdownHookForTesting(ShutdownHook hook) {
    ShutdownHookRef() = hook;
}

void SetAcquireLocalSourceHookForTesting(AcquireLocalSourceHook hook) {
    AcquireLocalSourceHookRef() = hook;
}

void SetReleaseLocalSourceHookForTesting(ReleaseLocalSourceHook hook) {
    ReleaseLocalSourceHookRef() = hook;
}

std::size_t RelaySessionBufferHighWaterMark() noexcept {
    return kMaxBufferedBytes;
}

RelaySession::RelaySession(EventLoop& loop, ScopedFd client_fd, ScopedFd upstream_fd)
    : loop_(&loop), client_fd_(std::move(client_fd)), upstream_fd_(std::move(upstream_fd)) {}

RelaySession::~RelaySession() {
    Close();
}

bool RelaySession::closed() const noexcept {
    return closed_;
}

std::shared_ptr<RelaySession> RelaySession::Create(EventLoop& loop,
                                                   ScopedFd client_fd,
                                                   const SessionEndpoints& endpoints,
                                                   CloseCallback on_close) {
    if (!client_fd) {
        return {};
    }

    if (!SetNonBlocking(client_fd.get())) {
        return {};
    }

    if (!AcquireLocalSourceAddress(endpoints.client)) {
        std::cerr << "relay session local source acquire failed"
                  << " client=" << FormatSockaddr(endpoints.client)
                  << " original_dst=" << FormatSockaddr(endpoints.original_dst)
                  << '\n';
        return {};
    }

    auto upstream = CreateTransparentSocket(endpoints.client, endpoints.original_dst);
    if (!upstream) {
        std::cerr << "relay session upstream create failed"
                  << " client=" << FormatSockaddr(endpoints.client)
                  << " original_dst=" << FormatSockaddr(endpoints.original_dst)
                  << " errno=" << errno
                  << " error=" << std::strerror(errno) << '\n';
        ReleaseLocalSourceAddress(endpoints.client);
        return {};
    }

    auto session = std::shared_ptr<RelaySession>(
        new RelaySession(loop, std::move(client_fd), std::move(upstream.fd)));
    session->upstream_connecting_ = upstream.connecting;
    session->owns_local_source_ = true;
    session->local_source_ = endpoints.client;
    session->on_close_ = std::move(on_close);
    session->Arm();
    session->UpdateInterest();
    return session;
}

void RelaySession::Arm() {
    auto weak = weak_from_this();
    client_handle_ = loop_->Register(
        client_fd_.get(),
        true,
        false,
        [weak] {
            if (auto self = weak.lock()) {
                self->OnClientReadable();
            }
        },
        [weak] {
            if (auto self = weak.lock()) {
                self->OnClientWritable();
            }
        },
        [weak](int) {
            if (auto self = weak.lock()) {
                self->Close();
            }
        });

    upstream_handle_ = loop_->Register(
        upstream_fd_.get(),
        true,
        false,
        [weak] {
            if (auto self = weak.lock()) {
                self->OnUpstreamReadable();
            }
        },
        [weak] {
            if (auto self = weak.lock()) {
                self->OnUpstreamWritable();
            }
        },
        [weak](int) {
            if (auto self = weak.lock()) {
                self->Close();
            }
        });
}

void RelaySession::OnClientReadable() {
    if (!PumpRead(client_fd_.get(), client_to_upstream_, client_to_upstream_offset_, client_closed_)) {
        Close();
        return;
    }
    if (!MaybePropagateHalfClose()) {
        Close();
        return;
    }
    if (MaybeFinish()) {
        return;
    }
    UpdateInterest();
}

void RelaySession::OnClientWritable() {
    if (!PumpWrite(client_fd_.get(), upstream_to_client_, upstream_to_client_offset_)) {
        Close();
        return;
    }
    if (!MaybePropagateHalfClose()) {
        Close();
        return;
    }
    if (MaybeFinish()) {
        return;
    }
    UpdateInterest();
}

void RelaySession::OnUpstreamReadable() {
    if (upstream_connecting_) {
        return;
    }
    if (!PumpRead(upstream_fd_.get(), upstream_to_client_, upstream_to_client_offset_, upstream_closed_)) {
        Close();
        return;
    }
    if (!upstream_closed_ &&
        DebugShutdownUpstreamOnFirstResponseEnabled() &&
        PendingBytes(upstream_to_client_, upstream_to_client_offset_) > 0) {
        (void)DoShutdown(upstream_fd_.get(), SHUT_RDWR);
        upstream_closed_ = true;
    }
    if (!upstream_closed_ &&
        DebugDetachUpstreamOnFirstResponseEnabled() &&
        PendingBytes(upstream_to_client_, upstream_to_client_offset_) > 0) {
        upstream_closed_ = true;
        upstream_handle_.reset();
    }
    if (!upstream_closed_ &&
        DebugCloseUpstreamOnFirstResponseEnabled() &&
        PendingBytes(upstream_to_client_, upstream_to_client_offset_) > 0) {
        upstream_closed_ = true;
        upstream_handle_.reset();
        upstream_fd_.reset();
    }
    if (!client_closed_ &&
        DebugCloseClientOnFirstResponseEnabled() &&
        PendingBytes(upstream_to_client_, upstream_to_client_offset_) > 0) {
        client_closed_ = true;
        client_handle_.reset();
        client_fd_.reset();
    }
    if (!MaybePropagateHalfClose()) {
        Close();
        return;
    }
    if (MaybeFinish()) {
        return;
    }
    UpdateInterest();
}

void RelaySession::OnUpstreamWritable() {
    if (upstream_connecting_) {
        if (!CompleteUpstreamConnect()) {
            Close();
            return;
        }
    }
    if (!PumpWrite(upstream_fd_.get(), client_to_upstream_, client_to_upstream_offset_)) {
        Close();
        return;
    }
    if (!MaybePropagateHalfClose()) {
        Close();
        return;
    }
    if (MaybeFinish()) {
        return;
    }
    UpdateInterest();
}

bool RelaySession::CompleteUpstreamConnect() {
    int socket_error = 0;
    socklen_t len = sizeof(socket_error);
    if (::getsockopt(upstream_fd_.get(), SOL_SOCKET, SO_ERROR, &socket_error, &len) != 0) {
        std::cerr << "relay session upstream getsockopt failed"
                  << " local=" << FormatSockaddr(GetSockName(upstream_fd_.get()))
                  << " peer=" << FormatSockaddr(GetPeer(upstream_fd_.get()))
                  << " errno=" << errno
                  << " error=" << std::strerror(errno) << '\n';
        return false;
    }
    if (socket_error != 0) {
        std::cerr << "relay session upstream connect failed"
                  << " local=" << FormatSockaddr(GetSockName(upstream_fd_.get()))
                  << " peer=" << FormatSockaddr(GetPeer(upstream_fd_.get()))
                  << " so_error=" << socket_error
                  << " error=" << std::strerror(socket_error) << '\n';
        errno = socket_error;
        return false;
    }
    upstream_connecting_ = false;
    return true;
}

bool RelaySession::MaybePropagateHalfClose() {
    if (client_closed_ &&
        PendingBytes(client_to_upstream_, client_to_upstream_offset_) == 0 &&
        !upstream_connecting_ &&
        !upstream_write_shutdown_) {
        if (DoShutdown(upstream_fd_.get(), SHUT_WR) != 0) {
            return false;
        }
        upstream_write_shutdown_ = true;
    }

    if (upstream_closed_ &&
        PendingBytes(upstream_to_client_, upstream_to_client_offset_) == 0 &&
        !client_write_shutdown_) {
        if (DoShutdown(client_fd_.get(), SHUT_WR) != 0) {
            return false;
        }
        client_write_shutdown_ = true;
    }

    return true;
}

bool RelaySession::MaybeFinish() {
    const bool client_to_upstream_done =
        client_closed_ &&
        PendingBytes(client_to_upstream_, client_to_upstream_offset_) == 0 &&
        upstream_write_shutdown_;
    const bool upstream_to_client_done =
        upstream_closed_ &&
        PendingBytes(upstream_to_client_, upstream_to_client_offset_) == 0 &&
        client_write_shutdown_;

    if (client_to_upstream_done && upstream_to_client_done) {
        Close();
        return true;
    }
    return false;
}

bool RelaySession::PumpRead(int fd,
                            std::string& buffer,
                            std::size_t offset,
                            bool& peer_closed) {
    const std::size_t pending = PendingBytes(buffer, offset);
    if (pending >= kMaxBufferedBytes) {
        return true;
    }

    char chunk[kReadChunkBytes];
    while (true) {
        const std::size_t space_left = kMaxBufferedBytes - PendingBytes(buffer, offset);
        if (space_left == 0) {
            return true;
        }

        const ssize_t n = ::read(fd, chunk, std::min<std::size_t>(sizeof(chunk), space_left));
        if (n > 0) {
            buffer.append(chunk, chunk + n);
            continue;
        }
        if (n == 0) {
            peer_closed = true;
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return true;
        }
        return false;
    }
}

bool RelaySession::PumpWrite(int fd, std::string& buffer, std::size_t& offset) {
    while (offset < buffer.size()) {
        const ssize_t n = DoSend(fd,
                                 buffer.data() + offset,
                                 buffer.size() - offset,
                                 MSG_NOSIGNAL);
        if (n > 0) {
            offset += static_cast<std::size_t>(n);
            CompactBuffer(buffer, offset);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return true;
        }
        return false;
    }

    buffer.clear();
    offset = 0;
    return true;
}

void RelaySession::UpdateInterest() {
    if (closed_) {
        return;
    }

    if (client_handle_) {
        client_handle_->Update(!client_closed_ &&
                                   PendingBytes(client_to_upstream_, client_to_upstream_offset_) < kMaxBufferedBytes,
                               PendingBytes(upstream_to_client_, upstream_to_client_offset_) > 0);
    }
    if (upstream_handle_) {
        upstream_handle_->Update(!upstream_closed_ &&
                                     !upstream_connecting_ &&
                                     PendingBytes(upstream_to_client_, upstream_to_client_offset_) < kMaxBufferedBytes,
                                 upstream_connecting_ ||
                                     PendingBytes(client_to_upstream_, client_to_upstream_offset_) > 0);
    }
}

void RelaySession::Close() {
    if (closed_) {
        return;
    }
    closed_ = true;
    if (client_handle_) {
        client_handle_.reset();
    }
    if (upstream_handle_) {
        upstream_handle_.reset();
    }
    client_fd_.reset();
    upstream_fd_.reset();
    if (owns_local_source_) {
        ReleaseLocalSourceAddress(local_source_);
        owns_local_source_ = false;
        local_source_ = {};
    }
    if (on_close_) {
        on_close_();
        on_close_ = {};
    }
}

std::shared_ptr<RelaySession> CreateRelaySession(EventLoop& loop,
                                                 ScopedFd client_fd,
                                                 const SessionEndpoints& endpoints,
                                                 CloseCallback on_close) {
    return RelaySession::Create(loop, std::move(client_fd), endpoints, std::move(on_close));
}

}  // namespace inline_proxy
