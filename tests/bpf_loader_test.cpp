#include <gtest/gtest.h>

#include <cstdint>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bpf/loader.hpp"

TEST(BpfLoaderTest, RejectsMissingInterfaceName) {
    inline_proxy::BpfLoader loader;
    EXPECT_FALSE(loader.AttachIngress(""));
}

TEST(BpfLoaderTest, RejectsNonWanInterfaceNames) {
    inline_proxy::BpfLoader loader;

    const int listener_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(listener_fd, 0);
    EXPECT_TRUE(loader.ConfigureListenerSocket(listener_fd));

    EXPECT_FALSE(loader.AttachIngress("lan_eth1"));
    EXPECT_FALSE(loader.IsIngressAttached("lan_eth1"));

    ::close(listener_fd);
}

TEST(BpfLoaderTest, CapturesListenerPortFromConfiguredSocket) {
    inline_proxy::BpfLoader loader;

    const int listener_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(listener_fd, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(listener_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    socklen_t len = sizeof(addr);
    ASSERT_EQ(::getsockname(listener_fd, reinterpret_cast<sockaddr*>(&addr), &len), 0);
    const std::uint16_t expected_port = ntohs(addr.sin_port);

    EXPECT_TRUE(loader.ConfigureListenerSocket(listener_fd));
    EXPECT_EQ(loader.listener_port(), expected_port);

    ::close(listener_fd);
}
