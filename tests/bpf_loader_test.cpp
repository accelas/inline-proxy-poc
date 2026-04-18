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

TEST(BpfLoaderTest, PreservesAttachedStateWhenDetachFails) {
    inline_proxy::BpfLoader loader;
    loader.MarkIngressAttachedForTesting("wan_eth0");

    EXPECT_TRUE(loader.IsIngressAttached("wan_eth0"));
    EXPECT_FALSE(loader.DetachIngress("wan_eth0"));
    EXPECT_TRUE(loader.IsIngressAttached("wan_eth0"));
}

TEST(BpfLoaderTest, GeneratedProgramUsesConfiguredListenerPort) {
    inline_proxy::BpfLoader loader;
    const auto insns = loader.BuildIngressProgramForTesting();

    bool saw_ihl_byte_load = false;
    bool saw_ihl_mask = false;
    bool saw_ihl_shift = false;
    bool saw_dynamic_tcp_offset = false;
    bool saw_listener_port_load = false;
    bool saw_listener_port_bswap = false;
    bool saw_hardcoded_tcp_offset = false;
    bool saw_listener_port_direct_compare = false;
    std::size_t packet_port_load_index = 0;
    std::size_t listener_port_load_index = 0;
    std::size_t listener_port_bswap_index = 0;
    std::size_t listener_port_compare_index = 0;

    for (std::size_t i = 0; i < insns.size(); ++i) {
        const auto& insn = insns[i];
        if (insn.code == (BPF_ALU64 | BPF_MOV | BPF_K) && insn.dst_reg == BPF_REG_2 &&
            insn.imm == 36) {
            saw_hardcoded_tcp_offset = true;
        }

        if (i + 5 < insns.size() &&
            insns[i].code == (BPF_ALU64 | BPF_MOV | BPF_X) && insns[i].dst_reg == BPF_REG_1 &&
            insns[i].src_reg == BPF_REG_8 &&
            insns[i + 1].code == (BPF_ALU64 | BPF_MOV | BPF_K) &&
            insns[i + 1].dst_reg == BPF_REG_2 && insns[i + 1].imm == 14 &&
            insns[i + 2].code == (BPF_ALU64 | BPF_MOV | BPF_X) &&
            insns[i + 2].dst_reg == BPF_REG_3 && insns[i + 2].src_reg == BPF_REG_10 &&
            insns[i + 3].code == (BPF_ALU64 | BPF_ADD | BPF_K) &&
            insns[i + 3].dst_reg == BPF_REG_3 && insns[i + 3].imm == -20 &&
            insns[i + 4].code == (BPF_ALU64 | BPF_MOV | BPF_K) &&
            insns[i + 4].dst_reg == BPF_REG_4 && insns[i + 4].imm == 1 &&
            insns[i + 5].code == (BPF_JMP | BPF_CALL) && insns[i + 5].imm == 26) {
            saw_ihl_byte_load = true;
        }

        if (insn.code == (BPF_ALU64 | BPF_AND | BPF_K) && insn.dst_reg == BPF_REG_7 &&
            insn.imm == 15) {
            saw_ihl_mask = true;
        }

        if (insn.code == (BPF_ALU64 | BPF_LSH | BPF_K) && insn.dst_reg == BPF_REG_7 &&
            insn.imm == 2) {
            saw_ihl_shift = true;
        }

        if (insn.code == (BPF_ALU64 | BPF_MOV | BPF_X) && insn.dst_reg == BPF_REG_2 &&
            insn.src_reg == BPF_REG_7 && i + 1 < insns.size() &&
            insns[i + 1].code == (BPF_ALU64 | BPF_ADD | BPF_K) && insns[i + 1].dst_reg == BPF_REG_2 &&
            insns[i + 1].imm == 16) {
            saw_dynamic_tcp_offset = true;
        }

        if (insn.code == (BPF_LDX | BPF_MEM | BPF_H) && insn.dst_reg == BPF_REG_7 &&
            insn.src_reg == BPF_REG_10 && insn.off == -16) {
            packet_port_load_index = i;
        }

        if (insn.code == (BPF_LDX | BPF_MEM | BPF_H) && insn.dst_reg == BPF_REG_1 &&
            insn.src_reg == BPF_REG_6 && insn.off == 4) {
            saw_listener_port_load = true;
            listener_port_load_index = i;
        }

        if (insn.code == (BPF_ALU | BPF_END | BPF_FROM_BE) && insn.dst_reg == BPF_REG_7 &&
            insn.imm == 16) {
            saw_listener_port_bswap = true;
            listener_port_bswap_index = i;
        }

        if (insn.code == (BPF_JMP | BPF_JNE | BPF_X) && insn.dst_reg == BPF_REG_7 &&
            insn.src_reg == BPF_REG_1) {
            saw_listener_port_direct_compare = true;
            listener_port_compare_index = i;
        }
    }

    EXPECT_TRUE(saw_ihl_byte_load);
    EXPECT_TRUE(saw_ihl_mask);
    EXPECT_TRUE(saw_ihl_shift);
    EXPECT_TRUE(saw_dynamic_tcp_offset);
    EXPECT_TRUE(saw_listener_port_load);
    EXPECT_TRUE(saw_listener_port_bswap);
    EXPECT_TRUE(saw_listener_port_direct_compare);
    EXPECT_LT(packet_port_load_index, listener_port_bswap_index);
    EXPECT_LT(listener_port_bswap_index, listener_port_load_index);
    EXPECT_LT(listener_port_load_index, listener_port_compare_index);
    EXPECT_FALSE(saw_hardcoded_tcp_offset);
}
