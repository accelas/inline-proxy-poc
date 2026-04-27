#include "bpf/loader.hpp"

#include "bpf/ingress_redirect_skel.skel.h"
#include "shared/scoped_fd.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/bpf.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace inline_proxy {

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

    if (!EnsureSkeletonLoaded()) return false;

    const int fresh_prog_fd = bpf_program__fd(skel_->progs.ingress_redirect);
    auto fresh_tag = ProgTag(fresh_prog_fd);
    if (!fresh_tag) {
        std::cerr << "LoadAndPin: failed to query freshly-loaded prog tag\n";
        ingress_redirect_skel__destroy(skel_);
        skel_ = nullptr;
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
