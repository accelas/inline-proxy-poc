#include "bpf/loader.hpp"

#include "shared/netlink.hpp"
#include "shared/scoped_fd.hpp"

#include <array>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstring>
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
constexpr __u8 kCodeCall = BPF_JMP | BPF_CALL;
constexpr __u8 kCodeExit = BPF_JMP | BPF_EXIT;

constexpr __s32 kIpv4HeaderOffset = 14;
constexpr __s32 kIpv4IhlStackOffset = -20;
constexpr __s32 kTcpPortStackOffset = -16;
constexpr __s32 kTcpPortPacketOffsetBase = 16;
constexpr __s32 kIpv4MinimumHeaderBytes = 20;
constexpr __s32 kIpv4IhlMask = 0x0f;

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

    std::size_t EmitExit() {
        return Emit(MakeInsn(kCodeExit, 0, 0, 0, 0));
    }

    void PatchJump(std::size_t index, std::size_t target) {
        insns[index].off = static_cast<__s16>(target - index - 1);
    }
};

std::optional<int> SysBpf(enum bpf_cmd cmd, union bpf_attr* attr) {
    const long result = ::syscall(__NR_bpf, cmd, attr, sizeof(*attr));
    if (result < 0) {
        return std::nullopt;
    }
    return static_cast<int>(result);
}

std::vector<bpf_insn> BuildIngressProgram(int map_fd) {
    ProgramBuilder builder;

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_8, BPF_REG_1, 0, 0));
    builder.EmitLoadMapFd(BPF_REG_1, map_fd);
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_2, BPF_REG_10, 0, 0));
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_2, 0, 0, -4));
    builder.Emit(MakeInsn(kCodeStMem, BPF_REG_2, 0, 0, static_cast<__s32>(INGRESS_REDIRECT_MAP_KEY_ZERO)));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_MAP_LOOKUP_ELEM);
    const std::size_t missing_config_jump = builder.EmitJump(kCodeJmpEq, BPF_REG_0, 0);
    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_6, BPF_REG_0, 0, 0));

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
    builder.Emit(MakeInsn(kCodeAddImm, BPF_REG_3, 0, 0, kTcpPortStackOffset));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_4, 0, 0, 2));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_SKB_LOAD_BYTES);
    const std::size_t tcp_port_load_failed_jump = builder.EmitJump(kCodeJmpNe, BPF_REG_0, 0);

    builder.Emit(MakeInsn(kCodeLdxMem | BPF_H, BPF_REG_7, BPF_REG_10, -16, 0));
    builder.Emit(MakeInsn(kCodeEndianFromBe, BPF_REG_7, 0, 0, 16));
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_H, BPF_REG_1, BPF_REG_6, 4, 0));
    const std::size_t port_mismatch_jump = builder.EmitJumpReg(kCodeJmpNeReg, BPF_REG_7, BPF_REG_1);

    builder.Emit(MakeInsn(kCodeMovReg, BPF_REG_1, BPF_REG_8, 0, 0));
    builder.Emit(MakeInsn(kCodeLdxMem | BPF_W, BPF_REG_1, BPF_REG_6, 8, 0));
    builder.Emit(MakeInsn(kCodeMovImm, BPF_REG_2, 0, 0, static_cast<__s32>(INGRESS_REDIRECT_INGRESS_FLAG)));
    builder.EmitCall(INGRESS_REDIRECT_HELPER_REDIRECT);
    const std::size_t exit_index = builder.EmitExit();

    builder.PatchJump(missing_config_jump, exit_index);
    builder.PatchJump(ethertype_load_failed_jump, exit_index);
    builder.PatchJump(ipproto_load_failed_jump, exit_index);
    builder.PatchJump(ihl_load_failed_jump, exit_index);
    builder.PatchJump(short_ipv4_header_jump, exit_index);
    builder.PatchJump(tcp_port_load_failed_jump, exit_index);
    builder.PatchJump(non_ipv4_jump, exit_index);
    builder.PatchJump(non_tcp_jump, exit_index);
    builder.PatchJump(port_mismatch_jump, exit_index);

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

bool LoadProgram(const ScopedFd& map_fd, ScopedFd& program_fd) {
    const std::vector<bpf_insn> insns = BuildIngressProgram(map_fd.get());
    std::array<char, 16384> log_buffer{};

    union bpf_attr attr{};
    attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    attr.insn_cnt = static_cast<std::uint32_t>(insns.size());
    attr.insns = reinterpret_cast<std::uint64_t>(insns.data());
    attr.license = reinterpret_cast<std::uint64_t>("GPL");
    attr.log_level = 1;
    attr.log_size = static_cast<std::uint32_t>(log_buffer.size());
    attr.log_buf = reinterpret_cast<std::uint64_t>(log_buffer.data());

    auto fd = SysBpf(BPF_PROG_LOAD, &attr);
    if (!fd) {
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

}  // namespace

bool BpfLoader::AttachIngress(std::string_view interface_name) {
    if (interface_name.empty() || interface_name.rfind("wan_", 0) != 0) {
        return false;
    }
    if (!listener_socket_fd_ || listener_port_ == 0 || runtime_config_.redirect_ifindex == 0) {
        return false;
    }
    if (IsIngressAttached(interface_name)) {
        return true;
    }

    const std::string iface_name(interface_name);
    const auto ifindex = LinkIndex(iface_name);
    if (!ifindex || *ifindex == 0) {
        return false;
    }

    if (!config_map_.valid() && !CreateConfigMap(config_map_)) {
        return false;
    }
    if (!program_fd_.valid() && !LoadProgram(config_map_, program_fd_)) {
        return false;
    }

    if (!UpdateConfigMap(config_map_, runtime_config_)) {
        return false;
    }
    if (!EnsureClsactQdisc(*ifindex)) {
        return false;
    }
    if (!AttachIngressFilter(*ifindex, program_fd_.get())) {
        return false;
    }

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
        attached_interfaces_.erase(attached);
        return false;
    }

    if (!RemoveIngressFilter(*ifindex)) {
        attached_interfaces_.erase(attached);
        return false;
    }

    attached_interfaces_.erase(attached);
    return true;
}

bool BpfLoader::ConfigureListenerSocket(int listener_fd) {
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

    const std::uint32_t redirect_ifindex = LinkIndex("lo").value_or(0);
    IngressRedirectConfig new_runtime_config{};
    new_runtime_config.enabled = 1;
    new_runtime_config.listener_port = listener_port;
    new_runtime_config.redirect_ifindex = redirect_ifindex;

    if (config_map_.valid() && !UpdateConfigMap(config_map_, new_runtime_config)) {
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
    return BuildIngressProgram(0);
}

void BpfLoader::MarkIngressAttachedForTesting(std::string_view interface_name) {
    attached_interfaces_.insert(std::string(interface_name));
}

bool BpfLoader::IsIngressAttached(std::string_view interface_name) const {
    return attached_interfaces_.find(std::string(interface_name)) != attached_interfaces_.end();
}

}  // namespace inline_proxy
