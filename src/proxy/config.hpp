#pragma once

#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <utility>

namespace inline_proxy {

struct ProxyConfig {
    using EnvOverride = std::pair<std::string_view, std::string_view>;

    std::uint16_t admin_port = 8080;
    std::uint16_t transparent_port = 15001;

    static ProxyConfig FromEnv(std::initializer_list<EnvOverride> env = {});
    static ProxyConfig FromEnv(int argc, char** argv);
};

int RunProxyDaemon(const ProxyConfig& cfg);

}  // namespace inline_proxy
