#include "proxy/interface_registry.hpp"

#include <stdexcept>
#include <string>

namespace inline_proxy {
bool InterfaceRegistry::ConfigureIngressListener(int listener_fd) {
    return bpf_loader_.ConfigureListenerSocket(listener_fd);
}

bool InterfaceRegistry::HasPrefix(std::string_view name, std::string_view prefix) {
    return name.size() >= prefix.size() && name.substr(0, prefix.size()) == prefix;
}

void InterfaceRegistry::AppendUnique(std::vector<std::string>& values, std::string_view name) {
    for (const auto& value : values) {
        if (value == name) {
            return;
        }
    }
    values.emplace_back(name);
}

void InterfaceRegistry::AppendList(std::string& out,
                                   std::string_view label,
                                   const std::vector<std::string>& values) {
    out += label;
    out += '=';
    if (values.empty()) {
        out += "none";
        out += '\n';
        return;
    }

    bool first = true;
    for (const auto& value : values) {
        if (!first) {
            out += ',';
        }
        out += value;
        first = false;
    }
    out += '\n';
}

bool InterfaceRegistry::RecordInterface(std::string_view name) {
    if (HasPrefix(name, "wan_")) {
        (void)bpf_loader_.AttachIngress(name);
        AppendUnique(wan_interfaces_, name);
        return true;
    }
    if (HasPrefix(name, "lan_")) {
        AppendUnique(lan_interfaces_, name);
        return true;
    }
    return false;
}

bool InterfaceRegistry::RemoveInterface(std::string_view name) {
    auto remove_from = [name](std::vector<std::string>& values) {
        for (auto it = values.begin(); it != values.end(); ++it) {
            if (*it == name) {
                values.erase(it);
                return true;
            }
        }
        return false;
    };

    if (HasPrefix(name, "wan_")) {
        const bool loader_thinks_attached = bpf_loader_.IsIngressAttached(name);
        const bool detached = bpf_loader_.DetachIngress(name);
        if (loader_thinks_attached && !detached) {
            return false;
        }
        return remove_from(wan_interfaces_);
    }
    if (HasPrefix(name, "lan_")) {
        return remove_from(lan_interfaces_);
    }
    return false;
}

void InterfaceRegistry::IncrementSessions() noexcept {
    ++active_sessions_;
}

void InterfaceRegistry::DecrementSessions() {
    if (active_sessions_ == 0) {
        throw std::logic_error("interface session underflow");
    }
    --active_sessions_;
}

std::size_t InterfaceRegistry::active_sessions() const noexcept {
    return active_sessions_;
}

const std::vector<std::string>& InterfaceRegistry::wan_interfaces() const noexcept {
    return wan_interfaces_;
}

const std::vector<std::string>& InterfaceRegistry::lan_interfaces() const noexcept {
    return lan_interfaces_;
}

const BpfLoader& InterfaceRegistry::bpf_loader() const noexcept {
    return bpf_loader_;
}

std::string InterfaceRegistry::SummaryText() const {
    std::string out;
    AppendList(out, "wan_interfaces", wan_interfaces_);
    AppendList(out, "lan_interfaces", lan_interfaces_);
    out += "active_sessions=";
    out += std::to_string(active_sessions_);
    out += '\n';
    return out;
}

}  // namespace inline_proxy
