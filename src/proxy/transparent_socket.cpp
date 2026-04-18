#include "proxy/transparent_socket.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

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

ScopedFd MakeSocket() {
    ScopedFd fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd) {
        return {};
    }
    const int reuse = 1;
    if (!SetSocketOptionInt(fd.get(), SOL_SOCKET, SO_REUSEADDR, reuse)) {
        return {};
    }
    (void)SetSocketOptionInt(fd.get(), IPPROTO_IP, IP_TRANSPARENT, 1);
    (void)SetSocketOptionInt(fd.get(), IPPROTO_IP, IP_FREEBIND, 1);
    return fd;
}

}  // namespace

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
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

ScopedFd CreateTransparentSocket(const sockaddr_storage& original_src,
                                 const sockaddr_storage& original_dst) {
    if (original_src.ss_family != AF_INET || original_dst.ss_family != AF_INET) {
        return {};
    }

    ScopedFd fd = MakeSocket();
    if (!fd) {
        return {};
    }

    if (::bind(fd.get(), reinterpret_cast<const sockaddr*>(&original_src), SockaddrLength(original_src)) != 0) {
        // Best-effort fallback for environments without CAP_NET_ADMIN.
        // The upstream connection still works with an ephemeral local source.
    }

    if (::connect(fd.get(), reinterpret_cast<const sockaddr*>(&original_dst), SockaddrLength(original_dst)) != 0) {
        return {};
    }

    if (!SetNonBlocking(fd.get())) {
        return {};
    }

    return fd;
}

}  // namespace inline_proxy
