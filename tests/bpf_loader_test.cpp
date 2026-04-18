#include <gtest/gtest.h>

#include <cstdint>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "bpf/loader.hpp"

TEST(BpfLoaderTest, RejectsMissingInterfaceName) {
    inline_proxy::BpfLoader loader;
    EXPECT_FALSE(loader.AttachIngress(""));
}

TEST(BpfLoaderTest, RejectsNonWanInterfaceNamesAfterListenerConfiguration) {
    inline_proxy::BpfLoader loader;

    const int listener_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(listener_fd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(listener_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
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

TEST(BpfLoaderTest, RejectsConfigureListenerSocketWhenGetsocknameFails) {
    inline_proxy::BpfLoader loader;

    int pipe_fds[2];
    ASSERT_EQ(::pipe(pipe_fds), 0);

    EXPECT_FALSE(loader.ConfigureListenerSocket(pipe_fds[0]));
    EXPECT_FALSE(loader.listener_socket_fd().has_value());
    EXPECT_EQ(loader.listener_port(), 0U);

    ::close(pipe_fds[0]);
    ::close(pipe_fds[1]);
}

TEST(BpfLoaderTest, GeneratedProgramUsesConfiguredListenerPort) {
    inline_proxy::BpfLoader loader;
    const auto insns = loader.BuildIngressProgramForTesting();

    bool saw_listener_port_load = false;
    for (std::size_t i = 0; i + 5 < insns.size(); ++i) {
        if (insns[i + 5].code == (BPF_JMP | BPF_CALL) && insns[i + 5].imm == 26 &&
            insns[i + 1].code == (BPF_ALU64 | BPF_MOV | BPF_K) &&
            insns[i + 1].dst_reg == BPF_REG_2 && insns[i + 1].imm == 36) {
            saw_listener_port_load = true;
            break;
        }
    }

    EXPECT_TRUE(saw_listener_port_load);
}
