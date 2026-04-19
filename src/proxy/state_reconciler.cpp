#include "proxy/state_reconciler.hpp"

#include <utility>

#include "proxy/interface_registry.hpp"
#include "shared/state_store.hpp"

namespace inline_proxy {

StateReconciler::StateReconciler(std::filesystem::path state_root)
    : state_root_(std::move(state_root)) {}

std::set<std::string> StateReconciler::LoadInterfaceNames(
    const std::string& field_name) const {
    std::set<std::string> names;
    if (!std::filesystem::exists(state_root_) || !std::filesystem::is_directory(state_root_)) {
        return names;
    }

    for (const auto& entry : std::filesystem::directory_iterator(state_root_)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        const auto fields = StateStore(entry.path()).Read();
        if (!fields.has_value()) {
            continue;
        }

        const auto it = fields->find(field_name);
        if (it != fields->end() && !it->second.empty()) {
            names.insert(it->second);
        }
    }

    return names;
}

void StateReconciler::Sync(InterfaceRegistry& registry) {
    const auto desired_wan = LoadInterfaceNames("wan_name");
    const auto desired_lan = LoadInterfaceNames("lan_name");

    for (const auto& name : desired_wan) {
        if (registry.RecordInterface(name)) {
            tracked_wan_interfaces_.insert(name);
        } else {
            tracked_wan_interfaces_.erase(name);
        }
    }

    for (const auto& name : desired_lan) {
        if (registry.RecordInterface(name)) {
            tracked_lan_interfaces_.insert(name);
        } else {
            tracked_lan_interfaces_.erase(name);
        }
    }

    const auto current_wan = registry.wan_interfaces();
    for (const auto& name : current_wan) {
        if (desired_wan.find(name) != desired_wan.end()) {
            continue;
        }
        if (registry.RemoveInterface(name)) {
            tracked_wan_interfaces_.erase(name);
        }
    }

    const auto current_lan = registry.lan_interfaces();
    for (const auto& name : current_lan) {
        if (desired_lan.find(name) != desired_lan.end()) {
            continue;
        }
        if (registry.RemoveInterface(name)) {
            tracked_lan_interfaces_.erase(name);
        }
    }
}

}  // namespace inline_proxy
