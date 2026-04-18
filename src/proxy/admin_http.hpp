#pragma once

#include <string>
#include <string_view>

#include "proxy/proxy_state.hpp"

namespace inline_proxy {

struct AdminResponse {
    int status;
    std::string content_type;
    std::string body;
};

class AdminHttp {
public:
    explicit AdminHttp(ProxyState& state) noexcept;

    AdminResponse Handle(std::string_view method, std::string_view path) const;

private:
    ProxyState& state_;
};

AdminHttp BuildAdminHttp(ProxyState& state) noexcept;

}  // namespace inline_proxy
