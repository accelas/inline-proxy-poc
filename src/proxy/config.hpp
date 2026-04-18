#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <utility>
#include <sys/types.h>

namespace inline_proxy {

struct ProxyConfig {
    using EnvOverride = std::pair<std::string_view, std::string_view>;

    std::uint16_t admin_port = 8080;
    std::uint16_t transparent_port = 15001;

    // Injected env overrides for tests or callers that already resolved env state.
    static ProxyConfig FromEnv(std::initializer_list<EnvOverride> env = {});
    // Runtime path: reads process env and CLI flags, then applies CLI overrides last.
    static ProxyConfig FromArgs(int argc, char** argv);
};

using AdminSendHook = ssize_t (*)(int fd, const void* buffer, size_t length, int flags);

void SetAdminSendHookForTesting(AdminSendHook hook);
ssize_t DoAdminSend(int fd, const void* buffer, size_t length, int flags);

int RunProxyDaemon(const ProxyConfig& cfg);

}  // namespace inline_proxy
