#include <gtest/gtest.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <string>

#include "proxy/interface_registry.hpp"

TEST(InterfaceRegistryTest, TracksAndRemovesLanInterfaces) {
    inline_proxy::InterfaceRegistry registry;

    EXPECT_EQ(registry.SummaryText(), "wan_interfaces=none\nlan_interfaces=none\nactive_sessions=0\n");

    EXPECT_TRUE(registry.RecordInterface("lan_eth1"));
    registry.IncrementSessions();

    const auto added = registry.SummaryText();
    EXPECT_NE(added.find("lan_eth1"), std::string::npos);
    EXPECT_NE(added.find("active_sessions=1"), std::string::npos);

    EXPECT_TRUE(registry.RemoveInterface("lan_eth1"));
    registry.DecrementSessions();

    EXPECT_EQ(registry.SummaryText(), "wan_interfaces=none\nlan_interfaces=none\nactive_sessions=0\n");
}

TEST(InterfaceRegistryTest, ConfiguresIngressListenerOnLoader) {
    inline_proxy::InterfaceRegistry registry;

    const int listener_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(listener_fd, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(listener_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    EXPECT_TRUE(registry.ConfigureIngressListener(listener_fd));
    EXPECT_EQ(registry.bpf_loader().listener_socket_fd(), listener_fd);

    ::close(listener_fd);
}

TEST(InterfaceRegistryTest, ReplaysRecordedWanInterfacesWhenListenerIsConfigured) {
    inline_proxy::InterfaceRegistry registry;

    EXPECT_FALSE(registry.RecordInterface("wan_missing0"));
    EXPECT_NE(std::find(registry.wan_interfaces().begin(), registry.wan_interfaces().end(), "wan_missing0"),
              registry.wan_interfaces().end());

    const int listener_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(listener_fd, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(listener_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    EXPECT_TRUE(registry.ConfigureIngressListener(listener_fd));
    EXPECT_EQ(registry.bpf_loader().listener_socket_fd(), listener_fd);
    EXPECT_NE(registry.bpf_loader().listener_port(), 0U);
    EXPECT_FALSE(registry.bpf_loader().IsIngressAttached("wan_missing0"));

    ::close(listener_fd);
}

TEST(InterfaceRegistryTest, RejectsInvalidIngressListenerConfiguration) {
    inline_proxy::InterfaceRegistry registry;

    int pipe_fds[2];
    ASSERT_EQ(::pipe(pipe_fds), 0);

    EXPECT_FALSE(registry.ConfigureIngressListener(pipe_fds[0]));
    EXPECT_FALSE(registry.bpf_loader().listener_socket_fd().has_value());
    EXPECT_EQ(registry.bpf_loader().listener_port(), 0U);

    ::close(pipe_fds[0]);
    ::close(pipe_fds[1]);
}

TEST(InterfaceRegistryTest, ReturnsFailureWhenWanIngressAttachFailsButRetainsInterfaceForRetry) {
    inline_proxy::InterfaceRegistry registry;

    EXPECT_FALSE(registry.RecordInterface("wan_eth0"));
    EXPECT_NE(std::find(registry.wan_interfaces().begin(), registry.wan_interfaces().end(), "wan_eth0"),
              registry.wan_interfaces().end());
    EXPECT_NE(registry.SummaryText().find("wan_eth0"), std::string::npos);

    EXPECT_TRUE(registry.RemoveInterface("wan_eth0"));
    EXPECT_TRUE(registry.wan_interfaces().empty());
    EXPECT_EQ(registry.SummaryText(), "wan_interfaces=none\nlan_interfaces=none\nactive_sessions=0\n");
}

TEST(InterfaceRegistryTest, KeepsWanInterfaceWhenDetachFailsAfterLoaderHadBeenAttached) {
    inline_proxy::InterfaceRegistry registry;

    EXPECT_FALSE(registry.RecordInterface("wan_eth1"));
    auto& loader = const_cast<inline_proxy::BpfLoader&>(registry.bpf_loader());
    loader.MarkIngressAttachedForTesting("wan_eth1");

    EXPECT_FALSE(registry.RemoveInterface("wan_eth1"));
    EXPECT_NE(std::find(registry.wan_interfaces().begin(), registry.wan_interfaces().end(), "wan_eth1"),
              registry.wan_interfaces().end());
    EXPECT_TRUE(loader.IsIngressAttached("wan_eth1"));
}
