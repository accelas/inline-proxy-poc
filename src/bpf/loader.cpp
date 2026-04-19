#include "bpf/loader.hpp"

#include "bpf/ingress_redirect_skel.skel.h"
#include "shared/netlink.hpp"
#include "shared/scoped_fd.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace inline_proxy {
namespace {

// ---------------------------------------------------------------------------
// Netlink TC attach/detach helpers (copied verbatim from the pre-skeleton
// loader; unchanged by this rewrite).
// ---------------------------------------------------------------------------

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
                if (errno == EINTR) continue;
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
                if (header->nlmsg_type == NLMSG_DONE) return true;
            }
        }
    }

private:
    explicit NetlinkSocket(ScopedFd fd) : fd_(std::move(fd)) {}
    ScopedFd fd_;
};

bool SendNetlinkRequest(std::vector<char> request) {
    auto socket = NetlinkSocket::Open();
    if (!socket) return false;
    if (!socket->Send(request)) return false;
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

}  // namespace

// ---------------------------------------------------------------------------
// BpfLoader public API
// ---------------------------------------------------------------------------

BpfLoader::~BpfLoader() {
    if (skel_ != nullptr) {
        ingress_redirect_skel__destroy(skel_);
        skel_ = nullptr;
    }
}

bool BpfLoader::EnsureSkeletonLoaded() {
    if (skel_ != nullptr) {
        return true;
    }
    skel_ = ingress_redirect_skel__open();
    if (skel_ == nullptr) {
        std::cerr << "ingress_redirect_skel__open failed errno=" << errno << '\n';
        return false;
    }
    if (int err = ingress_redirect_skel__load(skel_); err != 0) {
        std::cerr << "ingress_redirect_skel__load failed errno=" << -err << " ("
                  << std::strerror(-err) << ")\n";
        ingress_redirect_skel__destroy(skel_);
        skel_ = nullptr;
        return false;
    }
    return true;
}

bool BpfLoader::UpdateConfigAndListenerMaps(const IngressRedirectConfig& config,
                                            std::optional<int> listener_fd) {
    if (skel_ == nullptr) return false;

    const std::uint32_t key = 0;
    if (int err = bpf_map__update_elem(skel_->maps.config_map,
                                       &key, sizeof(key),
                                       &config, sizeof(config),
                                       BPF_ANY);
        err != 0) {
        std::cerr << "bpf_map__update_elem(config_map) failed err=" << err << '\n';
        return false;
    }
    if (listener_fd) {
        const std::uint32_t fd_value = static_cast<std::uint32_t>(*listener_fd);
        if (int err = bpf_map__update_elem(skel_->maps.listener_map,
                                           &key, sizeof(key),
                                           &fd_value, sizeof(fd_value),
                                           BPF_ANY);
            err != 0) {
            std::cerr << "bpf_map__update_elem(listener_map) failed err=" << err << '\n';
            return false;
        }
    }
    return true;
}

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

    if (!EnsureSkeletonLoaded()) {
        std::cerr << "attach-ingress failed to load skeleton for " << iface_name << '\n';
        return false;
    }
    if (!UpdateConfigAndListenerMaps(runtime_config_, listener_socket_fd_)) {
        std::cerr << "attach-ingress failed to populate maps for " << iface_name << '\n';
        return false;
    }
    if (!EnsureClsactQdisc(*ifindex)) {
        std::cerr << "attach-ingress failed to ensure clsact qdisc for " << iface_name
                  << " ifindex=" << *ifindex << '\n';
        return false;
    }
    const int program_fd = bpf_program__fd(skel_->progs.ingress_redirect);
    if (program_fd < 0) {
        std::cerr << "attach-ingress could not obtain program fd for " << iface_name << '\n';
        return false;
    }
    if (!AttachIngressFilter(*ifindex, program_fd)) {
        std::cerr << "attach-ingress failed to attach tc filter for " << iface_name
                  << " ifindex=" << *ifindex << " program_fd=" << program_fd << '\n';
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

    // Push into the live maps only if the skeleton has already been
    // loaded; otherwise cache and we flush at lazy AttachIngress load.
    // Mirrors today's loader, which also does not roll back cached state
    // on partial map-update failure.
    if (skel_ != nullptr) {
        if (!UpdateConfigAndListenerMaps(new_runtime_config, listener_fd)) {
            return false;
        }
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

bool BpfLoader::IsIngressAttached(std::string_view interface_name) const {
    return attached_interfaces_.find(std::string(interface_name)) != attached_interfaces_.end();
}

bool BpfLoader::LoadProgramForTesting() {
    return EnsureSkeletonLoaded();
}

}  // namespace inline_proxy
