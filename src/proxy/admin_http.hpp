#pragma once

#include <string>
#include <string_view>

#include "proxy/interface_registry.hpp"
#include "proxy/proxy_state.hpp"

namespace inline_proxy {

struct AdminResponse {
    int status;
    std::string content_type;
    std::string body;
};

class AdminHttp {
public:
    AdminHttp(ProxyState& state, InterfaceRegistry& interfaces) noexcept;

    AdminResponse Handle(std::string_view method, std::string_view path) const;

private:
    ProxyState& state_;
    InterfaceRegistry& interfaces_;
};

AdminHttp BuildAdminHttp(ProxyState& state, InterfaceRegistry& interfaces) noexcept;

}  // namespace inline_proxy
