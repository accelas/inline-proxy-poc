#pragma once

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <linux/bpf.h>

#include "shared/scoped_fd.hpp"

namespace inline_proxy {

struct IngressRedirectConfig {
    std::uint32_t enabled = 0;
    std::uint32_t listener_port = 0;
    std::uint32_t redirect_ifindex = 0;
};

class BpfLoader {
public:
    BpfLoader() = default;

    bool AttachIngress(std::string_view interface_name);
    bool DetachIngress(std::string_view interface_name);

    bool ConfigureListenerSocket(int listener_fd);
    std::optional<int> listener_socket_fd() const noexcept;
    std::uint32_t listener_port() const noexcept;

    bool IsIngressAttached(std::string_view interface_name) const;

    std::vector<bpf_insn> BuildIngressProgramForTesting() const;

private:
    std::set<std::string> attached_interfaces_;
    std::optional<int> listener_socket_fd_;
    std::uint32_t listener_port_ = 0;
    IngressRedirectConfig runtime_config_{};
    ScopedFd config_map_;
    ScopedFd program_fd_;
};

}  // namespace inline_proxy
