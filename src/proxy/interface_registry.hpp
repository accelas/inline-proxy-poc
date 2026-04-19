#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "bpf/loader.hpp"

namespace inline_proxy {

class InterfaceRegistry {
public:
    bool ConfigureIngressListener(int listener_fd);

    bool RecordInterface(std::string_view name);
    bool RemoveInterface(std::string_view name);

    void IncrementSessions() noexcept;
    void DecrementSessions();

    std::size_t active_sessions() const noexcept;
    const std::vector<std::string>& wan_interfaces() const noexcept;
    const std::vector<std::string>& lan_interfaces() const noexcept;
    const BpfLoader& bpf_loader() const noexcept;

    std::string SummaryText() const;

private:
    static bool HasPrefix(std::string_view name, std::string_view prefix);
    static void AppendList(std::string& out,
                           std::string_view label,
                           const std::vector<std::string>& values);
    static void AppendUnique(std::vector<std::string>& values, std::string_view name);

    std::vector<std::string> wan_interfaces_;
    std::vector<std::string> lan_interfaces_;
    std::size_t active_sessions_ = 0;
    BpfLoader bpf_loader_;
};

}  // namespace inline_proxy
