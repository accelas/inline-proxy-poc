#include <gtest/gtest.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

#include "proxy/transparent_socket.hpp"
#include "shared/scoped_fd.hpp"
#include "shared/sockaddr.hpp"

namespace {

inline_proxy::ScopedFd MakeClientSocket(const sockaddr_storage& addr) {
    inline_proxy::ScopedFd sock(::socket(AF_INET, SOCK_STREAM, 0));
    if (!sock) {
        return sock;
    }
    const int reuse = 1;
    ::setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (::connect(sock.get(), reinterpret_cast<const sockaddr*>(&addr), sizeof(sockaddr_in)) != 0) {
        return inline_proxy::ScopedFd();
    }
    return sock;
}

}  // namespace

TEST(TransparentSocketTest, ListenerConfigCreatesLoopbackListener) {
    auto listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
    EXPECT_TRUE(listener.ok());
}

TEST(TransparentSocketTest, AcceptedSocketHelpersReportPeerAndLocalAddresses) {
    auto listener = inline_proxy::CreateTransparentListener("127.0.0.1", 0);
    ASSERT_TRUE(listener.ok());

    const auto listener_addr = inline_proxy::GetSockName(listener.fd());
    ASSERT_EQ(listener_addr.ss_family, AF_INET);

    auto client = MakeClientSocket(listener_addr);
    ASSERT_TRUE(client);

    const int accepted_fd = ::accept(listener.fd(), nullptr, nullptr);
    ASSERT_GE(accepted_fd, 0);
    inline_proxy::ScopedFd accepted(accepted_fd);

    const auto peer = inline_proxy::GetPeer(accepted.get());
    const auto local = inline_proxy::GetSockName(accepted.get());
    const auto client_local = inline_proxy::GetSockName(client.get());

    EXPECT_EQ(inline_proxy::FormatSockaddr(peer), inline_proxy::FormatSockaddr(client_local));
    EXPECT_EQ(inline_proxy::FormatSockaddr(local), inline_proxy::FormatSockaddr(listener_addr));
}

