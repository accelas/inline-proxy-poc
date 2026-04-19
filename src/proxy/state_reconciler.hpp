#pragma once

#include <filesystem>
#include <set>
#include <string>

namespace inline_proxy {

class InterfaceRegistry;

class StateReconciler {
public:
    explicit StateReconciler(std::filesystem::path state_root = "/var/run/inline-proxy-cni");

    void Sync(InterfaceRegistry& registry);

private:
    std::set<std::string> LoadInterfaceNames(const std::string& field_name) const;

    std::filesystem::path state_root_;
    std::set<std::string> tracked_wan_interfaces_;
    std::set<std::string> tracked_lan_interfaces_;
};

}  // namespace inline_proxy
