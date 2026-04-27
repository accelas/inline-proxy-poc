#include "bpf/loader.hpp"

#include "bpf/ingress_redirect_skel.skel.h"
#include "shared/netlink.hpp"
#include "shared/netlink_builder.hpp"
#include "shared/scoped_fd.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace inline_proxy {
namespace {

// ---------------------------------------------------------------------------
// Netlink TC attach/detach helpers. Low-level primitives (attribute
// serialisation, the RAII socket wrapper) come from shared/netlink_builder;
// only the tc-specific message builder and the tc-specific request flow
// live here.
// ---------------------------------------------------------------------------

using netlink::AppendAttr;
using netlink::AppendStringAttr;

std::vector<char> MakeTcRequest(std::uint16_t type, std::uint16_t flags, unsigned int ifindex = 0) {
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

bool EnsureClsactQdisc(unsigned int ifindex) {
    auto request = MakeTcRequest(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_CLSACT;
    tc->tcm_handle = 0;
    AppendStringAttr(request, TCA_KIND, "clsact");
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool RemoveIngressFilter(unsigned int ifindex) {
    auto request = MakeTcRequest(RTM_DELTFILTER, 0, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    tc->tcm_handle = 0;
    tc->tcm_info = htons(ETH_P_ALL);
    AppendStringAttr(request, TCA_KIND, "bpf");
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool AttachIngressFilter(unsigned int ifindex, int program_fd) {
    auto request = MakeTcRequest(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
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

namespace {

bool MakeDirRecursive(std::string_view path) {
    std::error_code ec;
    std::filesystem::create_directories(std::string(path), ec);
    return !ec;
}

}  // namespace

void BpfLoader::UnlinkAllPins(std::string_view pin_dir) {
    const std::string dir(pin_dir);
    for (const char* name : {"prog", "config_map", "listener_map"}) {
        const std::string path = dir + "/" + name;
        if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
            std::cerr << "BpfLoader::UnlinkAllPins unlink failed path=" << path
                      << " errno=" << errno << '\n';
        }
    }
}

std::optional<std::array<std::uint8_t, 8>> BpfLoader::ProgTag(int prog_fd) {
    struct bpf_prog_info info{};
    std::memset(&info, 0, sizeof(info));
    std::uint32_t info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0) {
        std::cerr << "bpf_obj_get_info_by_fd failed errno=" << errno << '\n';
        return std::nullopt;
    }
    std::array<std::uint8_t, 8> tag{};
    static_assert(sizeof(info.tag) == tag.size(),
                  "bpf_prog_info::tag size mismatch");
    std::memcpy(tag.data(), info.tag, tag.size());
    return tag;
}

bool BpfLoader::PinFresh(std::string_view pin_dir) {
    if (skel_ == nullptr) return false;
    const std::string dir(pin_dir);

    UnlinkAllPins(pin_dir);

    auto pin_one = [&](const std::string& name, int fd) -> bool {
        const std::string path = dir + "/" + name;
        if (bpf_obj_pin(fd, path.c_str()) != 0) {
            std::cerr << "bpf_obj_pin failed path=" << path
                      << " errno=" << errno << '\n';
            return false;
        }
        return true;
    };

    if (!pin_one("prog", bpf_program__fd(skel_->progs.ingress_redirect))) return false;
    if (!pin_one("config_map", bpf_map__fd(skel_->maps.config_map))) return false;
    if (!pin_one("listener_map", bpf_map__fd(skel_->maps.listener_map))) return false;

    auto bpf_obj_get_path = [](const std::string& path) -> int {
        union bpf_attr a{};
        std::memset(&a, 0, sizeof(a));
        a.pathname = reinterpret_cast<std::uint64_t>(path.c_str());
        return static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &a, sizeof(a)));
    };

    int new_cfg_fd = bpf_obj_get_path(dir + "/config_map");
    if (new_cfg_fd < 0) {
        std::cerr << "bpf_obj_get(config_map) failed errno=" << errno << '\n';
        return false;
    }
    int new_listener_fd = bpf_obj_get_path(dir + "/listener_map");
    if (new_listener_fd < 0) {
        std::cerr << "bpf_obj_get(listener_map) failed errno=" << errno << '\n';
        ::close(new_cfg_fd);
        return false;
    }

    config_map_fd_ = ScopedFd(new_cfg_fd);
    listener_map_fd_ = ScopedFd(new_listener_fd);
    return true;
}

bool BpfLoader::TryReuseExistingPin(
    std::string_view pin_dir,
    const std::array<std::uint8_t, 8>& fresh_tag) {
    const std::string dir(pin_dir);
    const std::string prog_path = dir + "/prog";
    const std::string config_path = dir + "/config_map";
    const std::string listener_path = dir + "/listener_map";

    auto bpf_obj_get_path = [](const std::string& path) -> int {
        union bpf_attr a{};
        std::memset(&a, 0, sizeof(a));
        a.pathname = reinterpret_cast<std::uint64_t>(path.c_str());
        return static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &a, sizeof(a)));
    };

    const int existing_prog_fd = bpf_obj_get_path(prog_path);
    if (existing_prog_fd < 0) {
        return false;
    }
    auto existing_tag = ProgTag(existing_prog_fd);
    ::close(existing_prog_fd);
    if (!existing_tag) return false;
    if (*existing_tag != fresh_tag) {
        std::cerr << "BpfLoader: tag mismatch on existing pin; will replace\n";
        return false;
    }

    int cfg_fd = bpf_obj_get_path(config_path);
    if (cfg_fd < 0) return false;
    int listener_fd = bpf_obj_get_path(listener_path);
    if (listener_fd < 0) {
        ::close(cfg_fd);
        return false;
    }

    config_map_fd_ = ScopedFd(cfg_fd);
    listener_map_fd_ = ScopedFd(listener_fd);
    std::cerr << "BpfLoader: tag match; reusing existing pin at " << dir << '\n';
    return true;
}

bool BpfLoader::LoadAndPin(std::string_view pin_dir) {
    if (!MakeDirRecursive(pin_dir)) {
        std::cerr << "LoadAndPin: mkdir " << pin_dir << " failed errno=" << errno << '\n';
        return false;
    }
    pin_dir_ = std::string(pin_dir);

    if (!EnsureSkeletonLoaded()) return false;

    const int fresh_prog_fd = bpf_program__fd(skel_->progs.ingress_redirect);
    auto fresh_tag = ProgTag(fresh_prog_fd);
    if (!fresh_tag) {
        std::cerr << "LoadAndPin: failed to query freshly-loaded prog tag\n";
        return false;
    }

    if (TryReuseExistingPin(pin_dir, *fresh_tag)) {
        ingress_redirect_skel__destroy(skel_);
        skel_ = nullptr;
        return true;
    }

    if (!PinFresh(pin_dir)) {
        ingress_redirect_skel__destroy(skel_);
        skel_ = nullptr;
        return false;
    }
    ingress_redirect_skel__destroy(skel_);
    skel_ = nullptr;
    return true;
}

bool BpfLoader::WriteConfig(std::uint32_t listener_port, std::uint32_t skb_mark) {
    if (config_map_fd_.get() < 0) {
        std::cerr << "WriteConfig: config_map_fd_ not initialised\n";
        return false;
    }
    IngressRedirectConfig cfg{};
    cfg.enabled = 1;
    cfg.listener_port = listener_port;
    cfg.skb_mark = skb_mark;
    runtime_config_ = cfg;

    const std::uint32_t key = 0;
    union bpf_attr a{};
    std::memset(&a, 0, sizeof(a));
    a.map_fd = static_cast<__u32>(config_map_fd_.get());
    a.key = reinterpret_cast<std::uint64_t>(&key);
    a.value = reinterpret_cast<std::uint64_t>(&cfg);
    a.flags = BPF_ANY;
    if (::syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &a, sizeof(a)) != 0) {
        std::cerr << "WriteConfig: BPF_MAP_UPDATE_ELEM failed errno=" << errno << '\n';
        return false;
    }
    return true;
}

bool BpfLoader::WriteListenerFd(int listener_fd) {
    if (listener_map_fd_.get() < 0 || listener_fd < 0) {
        std::cerr << "WriteListenerFd: invalid map fd or listener fd\n";
        return false;
    }
    const std::uint32_t key = 0;
    const std::uint32_t fd_value = static_cast<std::uint32_t>(listener_fd);
    union bpf_attr a{};
    std::memset(&a, 0, sizeof(a));
    a.map_fd = static_cast<__u32>(listener_map_fd_.get());
    a.key = reinterpret_cast<std::uint64_t>(&key);
    a.value = reinterpret_cast<std::uint64_t>(&fd_value);
    a.flags = BPF_ANY;
    if (::syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &a, sizeof(a)) != 0) {
        std::cerr << "WriteListenerFd: BPF_MAP_UPDATE_ELEM failed errno=" << errno << '\n';
        return false;
    }
    listener_socket_fd_ = listener_fd;
    return true;
}

bool BpfLoader::PinProgForTesting(std::string_view pin_dir) {
    if (!EnsureSkeletonLoaded()) return false;
    if (!MakeDirRecursive(pin_dir)) return false;
    const std::string path = std::string(pin_dir) + "/prog";
    ::unlink(path.c_str());
    return bpf_obj_pin(bpf_program__fd(skel_->progs.ingress_redirect),
                       path.c_str()) == 0;
}

}  // namespace inline_proxy
