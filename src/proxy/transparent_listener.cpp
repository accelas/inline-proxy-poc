#include "proxy/transparent_listener.hpp"

#include <netinet/in.h>
#include <utility>

#include "proxy/transparent_socket.hpp"
#include "shared/sockaddr.hpp"

namespace inline_proxy {
namespace {

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

}  // namespace

TransparentListener::TransparentListener(ScopedFd fd) noexcept : fd_(std::move(fd)) {}

bool TransparentListener::ok() const noexcept {
    return fd_.valid();
}

int TransparentListener::fd() const noexcept {
    return fd_.get();
}

TransparentListener::operator bool() const noexcept {
    return ok();
}

TransparentListener CreateTransparentListener(const std::string& address, std::uint16_t port) {
    ScopedFd fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd) {
        return TransparentListener{};
    }

    const int reuse = 1;
    if (DoSetSockOpt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        return TransparentListener{};
    }
    const int enabled = 1;
    if (DoSetSockOpt(fd.get(), IPPROTO_IP, IP_TRANSPARENT, &enabled, sizeof(enabled)) != 0) {
        return TransparentListener{};
    }
    if (DoSetSockOpt(fd.get(), IPPROTO_IP, IP_FREEBIND, &enabled, sizeof(enabled)) != 0) {
        return TransparentListener{};
    }

    auto bind_addr = MakeSockaddr4(address, port);
    if (bind_addr.ss_family != AF_INET) {
        return TransparentListener{};
    }

    if (DoBind(fd.get(),
               reinterpret_cast<const sockaddr*>(&bind_addr),
               SockaddrLength(bind_addr)) != 0) {
        return TransparentListener{};
    }

    if (::listen(fd.get(), 128) != 0) {
        return TransparentListener{};
    }

    return TransparentListener(std::move(fd));
}

}  // namespace inline_proxy
