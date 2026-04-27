#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "bpf/ingress_redirect_common.h"
#include "shared/scoped_fd.hpp"

// Forward declaration of the bpftool-generated skeleton struct; the
// concrete definition lives in bazel-bin/.../ingress_redirect_skel.skel.h
// and is only included from loader.cpp.
struct ingress_redirect_skel;

namespace inline_proxy {

class BpfLoader {
public:
    BpfLoader() = default;
    ~BpfLoader();

    BpfLoader(const BpfLoader&) = delete;
    BpfLoader& operator=(const BpfLoader&) = delete;

    bool AttachIngress(std::string_view interface_name);
    bool DetachIngress(std::string_view interface_name);

    bool ConfigureListenerSocket(int listener_fd, std::uint32_t intercept_port = 0);
    std::optional<int> listener_socket_fd() const noexcept;
    std::uint32_t listener_port() const noexcept;

    bool IsIngressAttached(std::string_view interface_name) const;

    // Test-only hook: opens and loads the skeleton without attaching to any
    // interface. Returns true on success. Skipped in tests that lack
    // CAP_BPF. See tests/bpf_loader_test.cpp.
    bool LoadProgramForTesting();

    // New API (replaces AttachIngress + ConfigureListenerSocket).
    //
    // Idempotent. If pins already exist at <pin_dir> and the pinned
    // program's tag matches the embedded program's tag, reuses the
    // existing pinned objects without relinking (so already-attached
    // TC filters keep firing the same program and reading the same
    // maps we now write to). Otherwise loads the embedded skeleton,
    // unlinks any stale pins, and pins the fresh program/maps.
    //
    // After a successful return: <pin_dir>/prog, <pin_dir>/config_map,
    // and <pin_dir>/listener_map exist; this->config_map_fd_ and
    // this->listener_map_fd_ hold raw fds usable for map writes.
    bool LoadAndPin(std::string_view pin_dir);

    // Writes config_map[0] = {enabled=1, listener_port, skb_mark}
    // via raw bpf_map_update_elem on config_map_fd_. Safe to call
    // repeatedly. Requires LoadAndPin to have succeeded.
    bool WriteConfig(std::uint32_t listener_port, std::uint32_t skb_mark);

    // Writes listener_map[0] = listener_fd via raw bpf_map_update_elem
    // on listener_map_fd_. The fd must refer to a TCP socket in the
    // LISTEN state at the moment of update; the kernel rejects
    // sockmap inserts of non-listening sockets.
    bool WriteListenerFd(int listener_fd);

    // Test-only: pin the loaded prog at <pin_dir>/prog. Used by the
    // tc_attach integration test (no maps pinned, no tag check).
    bool PinProgForTesting(std::string_view pin_dir);

private:
    bool EnsureSkeletonLoaded();
    bool UpdateConfigAndListenerMaps(const IngressRedirectConfig& config,
                                     std::optional<int> listener_fd);

    // Returns the prog tag for an open prog fd, or nullopt on syscall
    // failure. The tag is bpf_prog_info::tag, an 8-byte SHA1 prefix
    // over the program's verifier IR.
    static std::optional<std::array<std::uint8_t, 8>> ProgTag(int prog_fd);

    // Tag-match path: open existing pinned prog/maps, store map fds,
    // close prog fd (the pin keeps prog alive). Returns true on
    // tag-match success; false on any failure (caller falls back to
    // load+pin).
    bool TryReuseExistingPin(std::string_view pin_dir,
                             const std::array<std::uint8_t, 8>& fresh_tag);

    // Load+pin path: unlink any stale pins, pin the freshly-loaded
    // skel.prog/skel.maps under pin_dir, store map fds.
    bool PinFresh(std::string_view pin_dir);

    // Best-effort unlink of <pin_dir>/{prog,config_map,listener_map}.
    static void UnlinkAllPins(std::string_view pin_dir);

    std::set<std::string> attached_interfaces_;
    std::optional<int> listener_socket_fd_;
    std::uint32_t listener_port_ = 0;
    IngressRedirectConfig runtime_config_{};
    struct ingress_redirect_skel* skel_ = nullptr;
    ScopedFd config_map_fd_;
    ScopedFd listener_map_fd_;
    std::string pin_dir_;
};

}  // namespace inline_proxy
