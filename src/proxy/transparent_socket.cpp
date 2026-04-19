#include "proxy/transparent_socket.hpp"

#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <netinet/in.h>
#include <string_view>
#include <unistd.h>

namespace inline_proxy {
namespace {

SetSockOptHook& SetSockOptHookRef() {
    static SetSockOptHook hook = nullptr;
    return hook;
}

BindHook& BindHookRef() {
    static BindHook hook = nullptr;
    return hook;
}

ConnectHook& ConnectHookRef() {
    static ConnectHook hook = nullptr;
    return hook;
}

FcntlHook& FcntlHookRef() {
    static FcntlHook hook = nullptr;
    return hook;
}

}  // namespace

int DoSetSockOpt(int fd, int level, int optname, const void* optval, socklen_t optlen) {
    if (auto hook = SetSockOptHookRef()) {
        return hook(fd, level, optname, optval, optlen);
    }
    return ::setsockopt(fd, level, optname, optval, optlen);
}

int DoBind(int fd, const sockaddr* addr, socklen_t addrlen) {
    if (auto hook = BindHookRef()) {
        return hook(fd, addr, addrlen);
    }
    return ::bind(fd, addr, addrlen);
}

int DoConnect(int fd, const sockaddr* addr, socklen_t addrlen) {
    if (auto hook = ConnectHookRef()) {
        return hook(fd, addr, addrlen);
    }
    return ::connect(fd, addr, addrlen);
}

int DoFcntl(int fd, int cmd, int arg) {
    if (auto hook = FcntlHookRef()) {
        return hook(fd, cmd, arg);
    }
    switch (cmd) {
        case F_GETFL:
            return ::fcntl(fd, cmd);
        default:
            return ::fcntl(fd, cmd, arg);
    }
}

namespace {

bool PreserveClientPort() {
    const char* value = std::getenv("INLINE_PROXY_PRESERVE_CLIENT_PORT");
    if (value == nullptr) {
        return true;
    }
    return std::string_view(value) != "0";
}

bool SetSocketOptionInt(int fd, int level, int name, int value) {
    return DoSetSockOpt(fd, level, name, &value, sizeof(value)) == 0;
}

socklen_t SockaddrLength(const sockaddr_storage& addr) {
    switch (addr.ss_family) {
        case AF_INET:
            return sizeof(sockaddr_in);
        case AF_INET6:
            return sizeof(sockaddr_in6);
        default:
            return sizeof(sockaddr_storage);
    }
}

TransparentConnectResult MakeSocket() {
    TransparentConnectResult result;
    result.fd.reset(::socket(AF_INET, SOCK_STREAM, 0));
    if (!result.fd) {
        return {};
    }

    const int reuse = 1;
    if (!SetSocketOptionInt(result.fd.get(), SOL_SOCKET, SO_REUSEADDR, reuse)) {
        return {};
    }
    if (!SetSocketOptionInt(result.fd.get(), IPPROTO_IP, IP_TRANSPARENT, 1)) {
        return {};
    }
    if (!SetSocketOptionInt(result.fd.get(), IPPROTO_IP, IP_FREEBIND, 1)) {
        return {};
    }

    return result;
}

}  // namespace

bool TransparentConnectResult::ok() const noexcept {
    return fd.valid();
}

TransparentConnectResult::operator bool() const noexcept {
    return ok();
}

void SetSetSockOptHookForTesting(SetSockOptHook hook) {
    SetSockOptHookRef() = hook;
}

void SetBindHookForTesting(BindHook hook) {
    BindHookRef() = hook;
}

void SetConnectHookForTesting(ConnectHook hook) {
    ConnectHookRef() = hook;
}

void SetFcntlHookForTesting(FcntlHook hook) {
    FcntlHookRef() = hook;
}

sockaddr_storage GetPeer(int fd) {
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (::getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        addr.ss_family = AF_UNSPEC;
    }
    return addr;
}

sockaddr_storage GetSockName(int fd) {
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        addr.ss_family = AF_UNSPEC;
    }
    return addr;
}

bool SetNonBlocking(int fd) {
    const int flags = DoFcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return DoFcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

TransparentConnectResult CreateTransparentSocket(const sockaddr_storage& original_src,
                                                 const sockaddr_storage& original_dst) {
    if (original_src.ss_family != AF_INET || original_dst.ss_family != AF_INET) {
        return {};
    }

    auto result = MakeSocket();
    if (!result) {
        return {};
    }

    auto bind_src = original_src;
    if (!PreserveClientPort()) {
        auto* v4 = reinterpret_cast<sockaddr_in*>(&bind_src);
        v4->sin_port = 0;
    }

    if (!SetNonBlocking(result.fd.get())) {
        return {};
    }

    if (DoBind(result.fd.get(),
               reinterpret_cast<const sockaddr*>(&bind_src),
               SockaddrLength(bind_src)) != 0) {
        return {};
    }

    if (DoConnect(result.fd.get(),
                  reinterpret_cast<const sockaddr*>(&original_dst),
                  SockaddrLength(original_dst)) != 0) {
        if (errno != EINPROGRESS && errno != EWOULDBLOCK) {
            return {};
        }
        result.connecting = true;
    }

    return result;
}

}  // namespace inline_proxy
