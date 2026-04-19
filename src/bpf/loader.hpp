#pragma once

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

private:
    bool EnsureSkeletonLoaded();
    bool UpdateConfigAndListenerMaps(const IngressRedirectConfig& config,
                                     std::optional<int> listener_fd);

    std::set<std::string> attached_interfaces_;
    std::optional<int> listener_socket_fd_;
    std::uint32_t listener_port_ = 0;
    IngressRedirectConfig runtime_config_{};
    struct ingress_redirect_skel* skel_ = nullptr;
};

}  // namespace inline_proxy
