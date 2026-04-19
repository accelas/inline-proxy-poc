#include "bpf/loader.hpp"

#include "shared/netlink.hpp"
#include "shared/scoped_fd.hpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cerrno>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace inline_proxy {
namespace {

constexpr __u8 kCodeLdxMem = BPF_LDX | BPF_MEM;
constexpr __u8 kCodeStMem = BPF_ST | BPF_MEM;
constexpr __u8 kCodeStxMem = BPF_STX | BPF_MEM;
constexpr __u8 kCodeMovImm = BPF_ALU64 | BPF_MOV | BPF_K;
constexpr __u8 kCodeMovReg = BPF_ALU64 | BPF_MOV | BPF_X;
constexpr __u8 kCodeAddImm = BPF_ALU64 | BPF_ADD | BPF_K;
constexpr __u8 kCodeAndImm = BPF_ALU64 | BPF_AND | BPF_K;
constexpr __u8 kCodeLshImm = BPF_ALU64 | BPF_LSH | BPF_K;
constexpr __u8 kCodeEndianFromBe = BPF_ALU | BPF_END | BPF_FROM_BE;
constexpr __u8 kCodeJmpEq = BPF_JMP | BPF_JEQ | BPF_K;
constexpr __u8 kCodeJmpNeReg = BPF_JMP | BPF_JNE | BPF_X;
constexpr __u8 kCodeJmpNe = BPF_JMP | BPF_JNE | BPF_K;
constexpr __u8 kCodeJmpLt = BPF_JMP | BPF_JLT | BPF_K;
constexpr __u8 kCodeJmpA = BPF_JMP | BPF_JA;
constexpr __u8 kCodeCall = BPF_JMP | BPF_CALL;
constexpr __u8 kCodeExit = BPF_JMP | BPF_EXIT;

constexpr __s32 kIpv4HeaderOffset = 14;
constexpr __s32 kIpv4IhlStackOffset = -40;
constexpr __s32 kTcpFlagsStackOffset = -44;
constexpr __s32 kTupleIpv4StackOffset = -32;
constexpr __s32 kTuplePortsStackOffset = kTupleIpv4StackOffset + 8;
constexpr __s32 kTupleDstPortStackOffset = kTupleIpv4StackOffset + 10;
constexpr __s32 kTraceMessageStackOffset = -80;
constexpr __s32 kTcpPortPacketOffsetBase = 16;
constexpr __s32 kTcpTuplePortPacketOffsetBase = 14;
constexpr __s32 kTcpFlagsPacketOffsetBase = 27;
constexpr __s32 kIpv4MinimumHeaderBytes = 20;
constexpr __s32 kIpv4IhlMask = 0x0f;
constexpr bool kEnableDebugPrintk = true;

static bpf_insn MakeInsn(__u8 code, __u8 dst, __u8 src, __s16 off, __s32 imm) {
    bpf_insn insn{};
    insn.code = code;
    insn.dst_reg = dst;
    insn.src_reg = src;
    insn.off = off;
    insn.imm = imm;
    return insn;
}

static bpf_insn MakeLoadMapFdInsn(__u8 dst, int map_fd) {
    bpf_insn insn{};
    insn.code = static_cast<__u8>(BPF_LD | BPF_DW | BPF_IMM);
    insn.dst_reg = dst;
    insn.src_reg = BPF_PSEUDO_MAP_FD;
    insn.off = 0;
    insn.imm = map_fd;
    return insn;
}

struct ProgramBuilder {
    std::vector<bpf_insn> insns;

    std::size_t Emit(const bpf_insn& insn) {
        insns.push_back(insn);
        return insns.size() - 1;
    }

    std::size_t EmitLoadMapFd(__u8 dst_reg, int map_fd) {
        insns.push_back(MakeLoadMapFdInsn(dst_reg, map_fd));
        insns.push_back(bpf_insn{});
        return insns.size() - 2;
    }

    std::size_t EmitJump(__u8 code, __u8 dst_reg, __s32 imm) {
        return Emit(MakeInsn(code, dst_reg, 0, 0, imm));
    }

    std::size_t EmitJumpReg(__u8 code, __u8 dst_reg, __u8 src_reg) {
        return Emit(MakeInsn(code, dst_reg, src_reg, 0, 0));
    }

    std::size_t EmitCall(__s32 helper_id) {
        return Emit(MakeInsn(kCodeCall, 0, 0, 0, helper_id));
    }

    std::size_t EmitJumpAlways() {
        return Emit(MakeInsn(kCodeJmpA, 0, 0, 0, 0));
    }

    std::size_t EmitExit() {
        return Emit(MakeInsn(kCodeExit, 0, 0, 0, 0));
    }

    void PatchJump(std::size_t index, std::size_t target) {
        insns[index].off = static_cast<__s16>(target - index - 1);
    }
};

void EmitTracePrintk(ProgramBuilder& builder, __s32 stack_offset, std::string_view message) {
    if (!kEnableDebugPrintk) {
        return;
    }

    for (std::size_t i = 0; i < message.size(); ++i) {
        builder.Emit(MakeInsn(kCodeStMem | BPF_B,
                              BPF_REG_10,
                              0,
                              static_cast<__s16>(stack_offset + static_cast<__s32>(i)),
                              static_cast<__s32>(static_cast<unsigned char>(message[i]))));
    }
    builder.Emit(MakeInsn(kCodeStMem | BPF_B,
                          BPF_REG_10,
                          0,
                          static_cast<__s16>(stack_offset + static_cast<__s32>(message.size())),
                          0));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_1, 0, 0, stack_offset));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_2, 0, 0, static_cast<__s32>(message.size() + 1)));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_TRACE_PRINTK);
}

void EmitTracePrintk1(ProgramBuilder& builder,
                      __s32 stack_offset,
                      std::string_view message,
                      __u8 value_reg) {
    if (!kEnableDebugPrintk) {
        return;
    }

    for (std::size_t i = 0; i < message.size(); ++i) {
        builder.Emit(MakeInsn(kCodeStMem | BPF_B,
                              BPF_REG_10,
                              0,
                              static_cast<__s16>(stack_offset + static_cast<__s32>(i)),
                              static_cast<__s32>(static_cast<unsigned char>(message[i]))));
    }
    builder.Emit(MakeInsn(kCodeStMem | BPF_B,
                          BPF_REG_10,
                          0,
                          static_cast<__s16>(stack_offset + static_cast<__s32>(message.size())),
                          0));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_1, 0, 0, stack_offset));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_2, 0, 0, static_cast<__s32>(message.size() + 1)));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_3, value_reg, 0, 0));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_TRACE_PRINTK);
}

void EmitTracePrintk2(ProgramBuilder& builder,
                      __s32 stack_offset,
                      std::string_view message,
                      __u8 value1_reg,
                      __u8 value2_reg) {
    if (!kEnableDebugPrintk) {
        return;
    }

    for (std::size_t i = 0; i < message.size(); ++i) {
        builder.Emit(MakeInsn(kCodeStMem | BPF_B,
                              BPF_REG_10,
                              0,
                              static_cast<__s16>(stack_offset + static_cast<__s32>(i)),
                              static_cast<__s32>(static_cast<unsigned char>(message[i]))));
    }
    builder.Emit(MakeInsn(kCodeStMem | BPF_B,
                          BPF_REG_10,
                          0,
                          static_cast<__s16>(stack_offset + static_cast<__s32>(message.size())),
                          0));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_1, 0, 0, stack_offset));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_2, 0, 0, static_cast<__s32>(message.size() + 1)));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_3, value1_reg, 0, 0));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_4, value2_reg, 0, 0));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_TRACE_PRINTK);
}

std::optional<int> SysBpf(enum bpf_cmd cmd, union bpf_attr* attr) {
    const long result = ::syscall(__NR_bpf, cmd, attr, sizeof(*attr));
    if (result < 0) {
        return std::nullopt;
    }
    return static_cast<int>(result);
}

std::vector<bpf_insn> BuildIngressProgram(int config_map_fd, int listener_map_fd) {
    ProgramBuilder builder;

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_8, BPF_REG_1, 0, 0));
    builder.EmitLoadMapFd(BPF_REG_1, config_map_fd);
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_2, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_2, 0, 0, -4));
    builder.Emit(MakeInsn(kCodeStMem, BPF_REG_2, 0, 0, static_cast<__s32>(INGRESS_REDIRECT_MAP_KEY_ZERO)));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_MAP_LOOKUP_ELEM);
    const std::size_t missing_config_jump = builder.EmitJump(kCodeJmpEq, BPF_REG_0, 0);
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_6, BPF_REG_0, 0, 0));
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_W, BPF_REG_9, BPF_REG_6, 8, 0));

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_2, 0, 0, 12));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_3, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_3, 0, 0, -8));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_4, 0, 0, 2));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SKB_LOAD_BYTES);
    const std::size_t ethertype_load_failed_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_0, 0);

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_2, 0, 0, 23));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_3, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_3, 0, 0, -12));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_4, 0, 0, 1));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SKB_LOAD_BYTES);
    const std::size_t ipproto_load_failed_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_0, 0);

    builder.Emit(MakeInsn(kCodeLdxMem | BPF_H, BPF_REG_7, BPF_REG_10, -8, 0));
    const std::size_t non_ipv4_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_7, static_cast<__s32>(INGRESS_REDIRECT_IPV4_WIRE_VALUE));

    builder.Emit(MakeInsn(kCodeLdxMem | BPF_B, BPF_REG_7, BPF_REG_10, -12, 0));
    const std::size_t non_tcp_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_7, static_cast<__s32>(INGRESS_REDIRECT_TCP_PROTOCOL));

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_2, 0, 0, kIpv4HeaderOffset));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_3, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_3, 0, 0, kIpv4IhlStackOffset));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_4, 0, 0, 1));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SKB_LOAD_BYTES);
    const std::size_t ihl_load_failed_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_0, 0);

    builder.Emit(MakeInsn(kCodeLdxMem | BPF_B, BPF_REG_7, BPF_REG_10, kIpv4IhlStackOffset, 0));
    builder.Emit(MakeInsn(kCodeAndImm, BPF_REG_7, 0, 0, kIpv4IhlMask));
    builder.Emit(MakeInsn(kCodeLshImm, BPF_REG_7, 0, 0, 2));
    const std::size_t short_ipv4_header_jump = builder.EmitJump(kCodeJmpLt, BPF_REG_7,
                                                                static_cast<__s32>(kIpv4MinimumHeaderBytes));

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_2, BPF_REG_7, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_2, 0, 0, kTcpPortPacketOffsetBase));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_3, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_3, 0, 0, kTupleIpv4StackOffset + 10));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_4, 0, 0, 2));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SKB_LOAD_BYTES);
    const std::size_t tcp_port_load_failed_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_0, 0);

    builder.Emit(MakeInsn(kCodeLdxMem | BPF_H, BPF_REG_7, BPF_REG_10, kTupleIpv4StackOffset + 10, 0));
    builder.Emit(MakeInsn(kCodeEndianFromBe, BPF_REG_7, 0, 0, 16));
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_H, BPF_REG_1, BPF_REG_6, 4, 0));
    const std::size_t port_mismatch_jump = builder.EmitJumpReg(kCodeJmpNeReg, BPF_REG_7, BPF_REG_1);
    EmitTracePrintk(builder, kTraceMessageStackOffset, "ipx port80\\n");
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_B, BPF_REG_2, BPF_REG_10, kIpv4IhlStackOffset, 0));
    builder.Emit(MakeInsn(kCodeAndImm, BPF_REG_2, 0, 0, kIpv4IhlMask));
    builder.Emit(MakeInsn(kCodeLshImm, BPF_REG_2, 0, 0, 2));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_2, 0, 0, kTcpFlagsPacketOffsetBase));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_3, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_3, 0, 0, kTcpFlagsStackOffset));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_4, 0, 0, 1));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SKB_LOAD_BYTES);
    const std::size_t tcp_flags_load_failed_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_0, 0);
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_B, BPF_REG_5, BPF_REG_10, kTcpFlagsStackOffset, 0));
    EmitTracePrintk1(builder, kTraceMessageStackOffset, "ipx flags=%d\\n", BPF_REG_5);

    builder.Emit(MakeInsn(kCodeLdxMem | BPF_B, BPF_REG_2, BPF_REG_10, kIpv4IhlStackOffset, 0));
    builder.Emit(MakeInsn(kCodeAndImm, BPF_REG_2, 0, 0, kIpv4IhlMask));
    builder.Emit(MakeInsn(kCodeLshImm, BPF_REG_2, 0, 0, 2));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_2, 0, 0, kTcpTuplePortPacketOffsetBase));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_3, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_3, 0, 0, kTupleIpv4StackOffset + 8));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_4, 0, 0, 4));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SKB_LOAD_BYTES);
    const std::size_t tcp_tuple_ports_load_failed_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_0, 0);

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_2, 0, 0, 26));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_3, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_3, 0, 0, kTupleIpv4StackOffset));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_4, 0, 0, 8));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SKB_LOAD_BYTES);
    const std::size_t ipv4_tuple_load_failed_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_0, 0);
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_W, BPF_REG_3, BPF_REG_10, kTupleIpv4StackOffset, 0));
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_W, BPF_REG_4, BPF_REG_10, kTupleIpv4StackOffset + 4, 0));
    EmitTracePrintk2(builder, kTraceMessageStackOffset, "ipx s=%x d=%x\\n", BPF_REG_3, BPF_REG_4);
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_H, BPF_REG_3, BPF_REG_10, kTuplePortsStackOffset, 0));
    builder.Emit(MakeInsn(kCodeEndianFromBe, BPF_REG_3, 0, 0, 16));
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_H, BPF_REG_4, BPF_REG_10, kTupleDstPortStackOffset, 0));
    builder.Emit(MakeInsn(kCodeEndianFromBe, BPF_REG_4, 0, 0, 16));
    EmitTracePrintk2(builder, kTraceMessageStackOffset, "ipx sp=%d dp=%d\\n", BPF_REG_3, BPF_REG_4);

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_2, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_2, 0, 0, kTupleIpv4StackOffset));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_3, 0, 0, sizeof(bpf_sock_tuple::ipv4)));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_4, 0, 0, -1));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_5, 0, 0, 0));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SKC_LOOKUP_TCP);
    const std::size_t socket_lookup_missing_jump = builder.EmitJump(kCodeJmpEq, BPF_REG_0, 0);
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_6, BPF_REG_0, 0, 0));
    EmitTracePrintk(builder, kTraceMessageStackOffset, "ipx lookup hit\\n");
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_W,
                          BPF_REG_7,
                          BPF_REG_6,
                          static_cast<__s16>(offsetof(bpf_sock, state)),
                          0));
    EmitTracePrintk1(builder, kTraceMessageStackOffset, "ipx state=%d\\n", BPF_REG_7);
    const std::size_t lookup_hit_jump = builder.EmitJumpAlways();

    const std::size_t listener_lookup_start = builder.insns.size();
    EmitTracePrintk(builder, kTraceMessageStackOffset, "ipx listener map\\n");
    builder.EmitLoadMapFd(BPF_REG_1, listener_map_fd);
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_2, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_2, 0, 0, -4));
    builder.Emit(MakeInsn(kCodeStMem, BPF_REG_2, 0, 0, 0));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_MAP_LOOKUP_ELEM);
    const std::size_t listener_lookup_failed_jump = builder.EmitJump(kCodeJmpEq, BPF_REG_0, 0);
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_6, BPF_REG_0, 0, 0));
    EmitTracePrintk(builder, kTraceMessageStackOffset, "ipx listener use\\n");

    const std::size_t assign_start = builder.insns.size();
    builder.Emit(MakeInsn(kCodeStxMem | BPF_W,
                          BPF_REG_8,
                          BPF_REG_9,
                          static_cast<__s16>(offsetof(__sk_buff, mark)),
                          0));

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_2, BPF_REG_6, 0, 0));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_3, 0, 0, 0));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SK_ASSIGN);
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_7, BPF_REG_0, 0, 0));
    EmitTracePrintk1(builder, kTraceMessageStackOffset, "ipx assign=%d\\n", BPF_REG_7);

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_6, 0, 0));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SK_RELEASE);
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_0, BPF_REG_7, 0, 0));
    const std::size_t socket_assign_failed_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_0, 0);
    const std::size_t exit_index = builder.EmitExit();

    builder.PatchJump(missing_config_jump, exit_index);
    builder.PatchJump(ethertype_load_failed_jump, exit_index);
    builder.PatchJump(ipproto_load_failed_jump, exit_index);
    builder.PatchJump(ihl_load_failed_jump, exit_index);
    builder.PatchJump(short_ipv4_header_jump, exit_index);
    builder.PatchJump(tcp_port_load_failed_jump, exit_index);
    builder.PatchJump(tcp_flags_load_failed_jump, exit_index);
    builder.PatchJump(tcp_tuple_ports_load_failed_jump, exit_index);
    builder.PatchJump(ipv4_tuple_load_failed_jump, exit_index);
    builder.PatchJump(non_ipv4_jump, exit_index);
    builder.PatchJump(non_tcp_jump, exit_index);
    builder.PatchJump(port_mismatch_jump, exit_index);
    builder.PatchJump(socket_lookup_missing_jump, listener_lookup_start);
    builder.PatchJump(lookup_hit_jump, assign_start);
    builder.PatchJump(listener_lookup_failed_jump, exit_index);
    builder.PatchJump(socket_assign_failed_jump, exit_index);

    return builder.insns;
}

bool AppendAttr(std::vector<char>& buffer, std::uint16_t type, const void* data, std::size_t size, bool nested = false) {
    constexpr std::size_t kAlignTo = 4;
    const auto align = [](std::size_t value) { return (value + kAlignTo - 1) & ~(kAlignTo - 1); };

    const auto old_size = buffer.size();
    const auto total_size = NLA_HDRLEN + size;
    buffer.resize(old_size + align(total_size));

    auto* attr = reinterpret_cast<nlattr*>(buffer.data() + old_size);
    attr->nla_type = nested ? static_cast<std::uint16_t>(type | NLA_F_NESTED) : type;
    attr->nla_len = static_cast<std::uint16_t>(total_size);
    std::memcpy(reinterpret_cast<char*>(attr) + NLA_HDRLEN, data, size);
    std::memset(reinterpret_cast<char*>(attr) + total_size, 0, align(total_size) - total_size);
    return true;
}

bool AppendStringAttr(std::vector<char>& buffer, std::uint16_t type, const std::string& value, bool nested = false) {
    return AppendAttr(buffer, type, value.c_str(), value.size() + 1, nested);
}

std::vector<char> MakeNetlinkMessage(std::uint16_t type, std::uint16_t flags, unsigned int ifindex = 0) {
    std::vector<char> message(NLMSG_LENGTH(sizeof(tcmsg)));
    auto* header = reinterpret_cast<nlmsghdr*>(message.data());
    header->nlmsg_len = static_cast<std::uint32_t>(message.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = static_cast<std::uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK);
    header->nlmsg_seq = 1;

    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(header));
    std::memset(tc, 0, sizeof(*tc));
    tc->tcm_family = AF_UNSPEC;
    tc->tcm_ifindex = static_cast<int>(ifindex);
    tc->tcm_handle = 0;
    tc->tcm_parent = TC_H_UNSPEC;
    return message;
}

class NetlinkSocket {
public:
    static std::optional<NetlinkSocket> Open() {
        ScopedFd fd(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
        if (!fd) {
            return std::nullopt;
        }

        sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        local.nl_pid = static_cast<unsigned int>(::getpid());
        if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            return std::nullopt;
        }

        return NetlinkSocket(std::move(fd));
    }

    bool Send(const std::vector<char>& request) const {
        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        return ::sendto(fd_.get(), request.data(), request.size(), 0,
                        reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel)) >= 0;
    }

    bool ReceiveAck() const {
        std::array<char, 8192> buffer{};
        while (true) {
            const auto length = ::recv(fd_.get(), buffer.data(), buffer.size(), 0);
            if (length < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return false;
            }

            auto remaining = static_cast<unsigned int>(length);
            for (nlmsghdr* header = reinterpret_cast<nlmsghdr*>(buffer.data());
                 NLMSG_OK(header, remaining);
                 header = NLMSG_NEXT(header, remaining)) {
                if (header->nlmsg_type == NLMSG_ERROR) {
                    const auto* error = reinterpret_cast<nlmsgerr*>(NLMSG_DATA(header));
                    return error->error == 0;
                }
                if (header->nlmsg_type == NLMSG_DONE) {
                    return true;
                }
            }
        }
    }

private:
    explicit NetlinkSocket(ScopedFd fd) : fd_(std::move(fd)) {}

    ScopedFd fd_;
};

bool SendNetlinkRequest(std::vector<char> request) {
    auto socket = NetlinkSocket::Open();
    if (!socket) {
        return false;
    }
    if (!socket->Send(request)) {
        return false;
    }
    return socket->ReceiveAck();
}

void FinalizeNetlinkMessage(std::vector<char>& request) {
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
}

bool EnsureClsactQdisc(unsigned int ifindex) {
    auto request = MakeNetlinkMessage(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_CLSACT;
    tc->tcm_handle = 0;
    AppendStringAttr(request, TCA_KIND, "clsact");
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool RemoveIngressFilter(unsigned int ifindex) {
    auto request = MakeNetlinkMessage(RTM_DELTFILTER, 0, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    tc->tcm_handle = 0;
    tc->tcm_info = htons(ETH_P_ALL);
    AppendStringAttr(request, TCA_KIND, "bpf");
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool AttachIngressFilter(unsigned int ifindex, int program_fd) {
    auto request = MakeNetlinkMessage(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    tc->tcm_handle = 0;
    tc->tcm_info = htons(ETH_P_ALL);

    AppendStringAttr(request, TCA_KIND, "bpf");

    std::vector<char> options;
    AppendAttr(options, TCA_BPF_FD, &program_fd, sizeof(program_fd));
    const std::string name = "ingress_redirect";
    AppendStringAttr(options, TCA_BPF_NAME, name);
    const std::uint32_t flags = TCA_BPF_FLAG_ACT_DIRECT;
    AppendAttr(options, TCA_BPF_FLAGS, &flags, sizeof(flags));

    AppendAttr(request, TCA_OPTIONS, options.data(), options.size(), true);
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool CreateConfigMap(ScopedFd& map_fd) {
    union bpf_attr attr{};
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(std::uint32_t);
    attr.value_size = sizeof(IngressRedirectConfig);
    attr.max_entries = 1;

    auto fd = SysBpf(BPF_MAP_CREATE, &attr);
    if (!fd) {
        return false;
    }

    map_fd.reset(*fd);
    return true;
}

bool CreateListenerMap(ScopedFd& map_fd) {
    union bpf_attr attr{};
    attr.map_type = BPF_MAP_TYPE_SOCKMAP;
    attr.key_size = sizeof(std::uint32_t);
    attr.value_size = sizeof(std::uint32_t);
    attr.max_entries = 1;

    auto fd = SysBpf(BPF_MAP_CREATE, &attr);
    if (!fd) {
        return false;
    }

    map_fd.reset(*fd);
    return true;
}

bool LoadProgram(const ScopedFd& config_map_fd,
                 const ScopedFd& listener_map_fd,
                 ScopedFd& program_fd) {
    const std::vector<bpf_insn> insns =
        BuildIngressProgram(config_map_fd.get(), listener_map_fd.get());
    std::array<char, 16384> log_buffer{};

    auto try_load = [&](std::uint32_t log_level,
                        char* log_buf,
                        std::uint32_t log_size) -> std::optional<int> {
        union bpf_attr attr{};
        attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
        attr.insn_cnt = static_cast<std::uint32_t>(insns.size());
        attr.insns = reinterpret_cast<std::uint64_t>(insns.data());
        attr.license = reinterpret_cast<std::uint64_t>("GPL");
        attr.log_level = log_level;
        attr.log_size = log_size;
        attr.log_buf = reinterpret_cast<std::uint64_t>(log_buf);
        return SysBpf(BPF_PROG_LOAD, &attr);
    };

    auto fd = try_load(1, log_buffer.data(), static_cast<std::uint32_t>(log_buffer.size()));
    int saved_errno = errno;
    if (!fd && saved_errno == ENOSPC) {
        fd = try_load(0, nullptr, 0);
        saved_errno = errno;
    }
    if (!fd) {
        std::fprintf(stderr,
                     "bpf prog load failed errno=%d (%s)\n",
                     saved_errno,
                     std::strerror(saved_errno));
        if (!log_buffer.empty() && log_buffer[0] != '\0') {
            std::fprintf(stderr, "%s", log_buffer.data());
        }
        return false;
    }

    program_fd.reset(*fd);
    return true;
}

bool UpdateConfigMap(const ScopedFd& map_fd, const IngressRedirectConfig& config) {
    const std::uint32_t key = 0;

    union bpf_attr attr{};
    attr.map_fd = map_fd.get();
    attr.key = reinterpret_cast<std::uint64_t>(&key);
    attr.value = reinterpret_cast<std::uint64_t>(&config);
    attr.flags = BPF_ANY;

    return SysBpf(BPF_MAP_UPDATE_ELEM, &attr).has_value();
}

bool UpdateListenerMap(const ScopedFd& map_fd, int listener_fd) {
    const std::uint32_t key = 0;
    const std::uint32_t value = static_cast<std::uint32_t>(listener_fd);

    union bpf_attr attr{};
    attr.map_fd = map_fd.get();
    attr.key = reinterpret_cast<std::uint64_t>(&key);
    attr.value = reinterpret_cast<std::uint64_t>(&value);
    attr.flags = BPF_ANY;

    return SysBpf(BPF_MAP_UPDATE_ELEM, &attr).has_value();
}

}  // namespace

bool BpfLoader::AttachIngress(std::string_view interface_name) {
    if (interface_name.empty() || interface_name.rfind("wan_", 0) != 0) {
        std::cerr << "attach-ingress rejected invalid interface name: " << interface_name << '\n';
        return false;
    }
    if (!listener_socket_fd_ || listener_port_ == 0) {
        std::cerr << "attach-ingress missing configured listener socket/port for "
                  << interface_name << '\n';
        return false;
    }
    if (IsIngressAttached(interface_name)) {
        return true;
    }

    const std::string iface_name(interface_name);
    const auto ifindex = LinkIndex(iface_name);
    if (!ifindex || *ifindex == 0) {
        std::cerr << "attach-ingress failed to resolve ifindex for " << iface_name << '\n';
        return false;
    }

    if (!config_map_.valid() && !CreateConfigMap(config_map_)) {
        std::cerr << "attach-ingress failed to create config map for " << iface_name << '\n';
        return false;
    }
    if (!listener_map_.valid() && !CreateListenerMap(listener_map_)) {
        std::cerr << "attach-ingress failed to create listener map for " << iface_name << '\n';
        return false;
    }
    if (!UpdateListenerMap(listener_map_, *listener_socket_fd_)) {
        std::cerr << "attach-ingress failed to update listener map for " << iface_name
                  << " fd=" << *listener_socket_fd_ << '\n';
        return false;
    }
    if (!program_fd_.valid() && !LoadProgram(config_map_, listener_map_, program_fd_)) {
        std::cerr << "attach-ingress failed to load tc program for " << iface_name << '\n';
        return false;
    }

    if (!UpdateConfigMap(config_map_, runtime_config_)) {
        std::cerr << "attach-ingress failed to update runtime config map for " << iface_name
                  << " intercept_port=" << runtime_config_.listener_port
                  << " mark=" << runtime_config_.skb_mark << '\n';
        return false;
    }
    if (!EnsureClsactQdisc(*ifindex)) {
        std::cerr << "attach-ingress failed to ensure clsact qdisc for " << iface_name
                  << " ifindex=" << *ifindex << '\n';
        return false;
    }
    if (!AttachIngressFilter(*ifindex, program_fd_.get())) {
        std::cerr << "attach-ingress failed to attach tc filter for " << iface_name
                  << " ifindex=" << *ifindex << " program_fd=" << program_fd_.get() << '\n';
        return false;
    }

    std::cerr << "attach-ingress ok iface=" << iface_name
              << " ifindex=" << *ifindex
              << " intercept_port=" << runtime_config_.listener_port
              << " listener_fd=" << *listener_socket_fd_ << '\n';
    attached_interfaces_.insert(iface_name);
    return true;
}

bool BpfLoader::DetachIngress(std::string_view interface_name) {
    if (interface_name.empty() || interface_name.rfind("wan_", 0) != 0) {
        return false;
    }

    const std::string iface_name(interface_name);
    const auto attached = attached_interfaces_.find(iface_name);
    if (attached == attached_interfaces_.end()) {
        return false;
    }

    const auto ifindex = LinkIndex(iface_name);
    if (!ifindex || *ifindex == 0) {
        return false;
    }

    if (!RemoveIngressFilter(*ifindex)) {
        return false;
    }

    attached_interfaces_.erase(attached);
    return true;
}

bool BpfLoader::ConfigureListenerSocket(int listener_fd, std::uint32_t intercept_port) {
    if (listener_fd < 0) {
        return false;
    }

    sockaddr_storage addr{};
    socklen_t addrlen = sizeof(addr);
    if (::getsockname(listener_fd, reinterpret_cast<sockaddr*>(&addr), &addrlen) != 0) {
        return false;
    }

    std::uint32_t listener_port = 0;
    if (addr.ss_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(&addr);
        listener_port = ntohs(v4->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        listener_port = ntohs(v6->sin6_port);
    }
    if (listener_port == 0) {
        return false;
    }
    if (intercept_port == 0) {
        intercept_port = listener_port;
    }

    IngressRedirectConfig new_runtime_config{};
    new_runtime_config.enabled = 1;
    new_runtime_config.listener_port = intercept_port;
    new_runtime_config.skb_mark = 0x100;

    if (config_map_.valid() && !UpdateConfigMap(config_map_, new_runtime_config)) {
        return false;
    }
    if (listener_map_.valid() && !UpdateListenerMap(listener_map_, listener_fd)) {
        return false;
    }

    listener_socket_fd_ = listener_fd;
    listener_port_ = listener_port;
    runtime_config_ = new_runtime_config;

    return true;
}

std::optional<int> BpfLoader::listener_socket_fd() const noexcept {
    return listener_socket_fd_;
}

std::uint32_t BpfLoader::listener_port() const noexcept {
    return listener_port_;
}

std::vector<bpf_insn> BpfLoader::BuildIngressProgramForTesting() const {
    return BuildIngressProgram(0, 0);
}

void BpfLoader::MarkIngressAttachedForTesting(std::string_view interface_name) {
    attached_interfaces_.insert(std::string(interface_name));
}

bool BpfLoader::IsIngressAttached(std::string_view interface_name) const {
    return attached_interfaces_.find(std::string(interface_name)) != attached_interfaces_.end();
}

}  // namespace inline_proxy
