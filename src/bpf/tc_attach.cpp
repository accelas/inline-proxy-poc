#include "bpf/tc_attach.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "shared/netlink.hpp"
#include "shared/netlink_builder.hpp"

namespace inline_proxy {
namespace {

using netlink::AppendAttr;
using netlink::AppendStringAttr;

std::vector<char> MakeTcRequest(std::uint16_t type, std::uint16_t flags,
                                unsigned int ifindex = 0) {
    std::vector<char> message(NLMSG_LENGTH(sizeof(tcmsg)));
    auto* header = reinterpret_cast<nlmsghdr*>(message.data());
    header->nlmsg_len = static_cast<std::uint32_t>(message.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = static_cast<std::uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK);
    header->nlmsg_seq = 1;

    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(message.data()));
    std::memset(tc, 0, sizeof(*tc));
    tc->tcm_family = AF_UNSPEC;
    tc->tcm_ifindex = static_cast<int>(ifindex);
    tc->tcm_handle = 0;
    tc->tcm_parent = TC_H_UNSPEC;
    return message;
}

bool SendNetlinkRequest(std::vector<char> request) {
    auto socket = netlink::Socket::Open();
    if (!socket) return false;
    if (!socket->Send(request)) return false;
    return socket->ReceiveAck();
}

void FinalizeNetlinkMessage(std::vector<char>& request) {
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
}

// `bpf_obj_get` via raw syscall — keeps CNI binary free of libbpf.
int BpfObjGet(const std::string& path) {
    union bpf_attr attr{};
    std::memset(&attr, 0, sizeof(attr));
    attr.pathname = reinterpret_cast<std::uint64_t>(path.c_str());
    return static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr)));
}

}  // namespace

TcAttacher::TcAttacher(std::string pin_dir) : pin_dir_(std::move(pin_dir)) {}

ScopedFd TcAttacher::OpenPinnedProg() const {
    const std::string prog_path = pin_dir_ + "/prog";
    const int fd = BpfObjGet(prog_path);
    if (fd < 0) {
        std::cerr << "tc_attach: bpf_obj_get failed path=" << prog_path
                  << " errno=" << errno << '\n';
    }
    return ScopedFd(fd);
}

bool TcAttacher::EnsureClsact(unsigned int ifindex) const {
    auto request = MakeTcRequest(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_CLSACT;
    tc->tcm_handle = 0;
    AppendStringAttr(request, TCA_KIND, "clsact");
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool TcAttacher::AttachIngressFilter(unsigned int ifindex, int prog_fd) const {
    auto request = MakeTcRequest(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    tc->tcm_handle = 0;
    tc->tcm_info = htons(ETH_P_ALL);

    AppendStringAttr(request, TCA_KIND, "bpf");

    std::vector<char> options;
    AppendAttr(options, TCA_BPF_FD, &prog_fd, sizeof(prog_fd));
    const std::string name = "ingress_redirect";
    AppendStringAttr(options, TCA_BPF_NAME, name);
    const std::uint32_t flags = TCA_BPF_FLAG_ACT_DIRECT;
    AppendAttr(options, TCA_BPF_FLAGS, &flags, sizeof(flags));

    AppendAttr(request, TCA_OPTIONS, options.data(), options.size(), true);
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool TcAttacher::AttachToInterface(std::string_view ifname) {
    if (ifname.empty()) {
        std::cerr << "tc_attach: empty ifname\n";
        return false;
    }
    const std::string name(ifname);
    const auto ifindex = LinkIndex(name);
    if (!ifindex || *ifindex == 0) {
        std::cerr << "tc_attach: LinkIndex failed iface=" << name << '\n';
        return false;
    }

    auto prog_fd = OpenPinnedProg();
    if (prog_fd.get() < 0) return false;

    const bool ok = EnsureClsact(*ifindex) &&
                    AttachIngressFilter(*ifindex, prog_fd.get());

    if (ok) {
        std::cerr << "tc_attach ok iface=" << name << " ifindex=" << *ifindex << '\n';
    } else {
        std::cerr << "tc_attach failed iface=" << name << " ifindex=" << *ifindex << '\n';
    }
    return ok;
}

}  // namespace inline_proxy
