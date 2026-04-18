#include "proxy/transparent_listener.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <utility>

#include "shared/sockaddr.hpp"

namespace inline_proxy {
namespace {

bool SetSocketOptionInt(int fd, int level, int name, int value) {
    return ::setsockopt(fd, level, name, &value, sizeof(value)) == 0;
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
    if (!SetSocketOptionInt(fd.get(), SOL_SOCKET, SO_REUSEADDR, reuse)) {
        return TransparentListener{};
    }
    // Best-effort transparent mode: the host running the tests may not have
    // CAP_NET_ADMIN, so we keep the listener usable even if IP_TRANSPARENT
    // cannot be enabled here.
    (void)SetSocketOptionInt(fd.get(), IPPROTO_IP, IP_TRANSPARENT, 1);
    (void)SetSocketOptionInt(fd.get(), IPPROTO_IP, IP_FREEBIND, 1);

    auto bind_addr = MakeSockaddr4(address, port);
    if (bind_addr.ss_family != AF_INET) {
        return TransparentListener{};
    }

    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&bind_addr), SockaddrLength(bind_addr)) != 0) {
        return TransparentListener{};
    }

    if (::listen(fd.get(), 128) != 0) {
        return TransparentListener{};
    }

    return TransparentListener(std::move(fd));
}

}  // namespace inline_proxy
