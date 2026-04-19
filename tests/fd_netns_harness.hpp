#pragma once

#include <atomic>
#include <future>
#include <optional>
#include <string>

#include "bpf/loader.hpp"
#include "proxy/interface_registry.hpp"
#include "shared/netns.hpp"

namespace inline_proxy {

struct TransparentFlowObservation {
    std::string server_peer;
    std::string proxy_client;
    std::string proxy_original_dst;
    std::atomic<int> accepted_connections{0};

    TransparentFlowObservation() = default;
    TransparentFlowObservation(const TransparentFlowObservation&) = delete;
    TransparentFlowObservation& operator=(const TransparentFlowObservation&) = delete;
    TransparentFlowObservation(TransparentFlowObservation&& other) noexcept
        : server_peer(std::move(other.server_peer)),
          proxy_client(std::move(other.proxy_client)),
          proxy_original_dst(std::move(other.proxy_original_dst)),
          accepted_connections(other.accepted_connections.load(std::memory_order_relaxed)) {}
    TransparentFlowObservation& operator=(TransparentFlowObservation&& other) noexcept {
        if (this != &other) {
            server_peer = std::move(other.server_peer);
            proxy_client = std::move(other.proxy_client);
            proxy_original_dst = std::move(other.proxy_original_dst);
            accepted_connections.store(other.accepted_connections.load(std::memory_order_relaxed),
                                       std::memory_order_relaxed);
        }
        return *this;
    }
};

class FdNetnsHarness {
public:
    ~FdNetnsHarness();

    FdNetnsHarness(const FdNetnsHarness&) = delete;
    FdNetnsHarness& operator=(const FdNetnsHarness&) = delete;
    FdNetnsHarness(FdNetnsHarness&& other) noexcept;
    FdNetnsHarness& operator=(FdNetnsHarness&& other) noexcept;

    static bool HasRequiredPrivileges();
    static std::optional<FdNetnsHarness> Create();

    bool RunInterceptEchoScenario();
    const TransparentFlowObservation& observation() const noexcept;

private:
    FdNetnsHarness(NetnsHandle client, NetnsHandle proxy, NetnsHandle server) noexcept;

    bool SetupTopology();

    NetnsHandle client_;
    NetnsHandle proxy_;
    NetnsHandle server_;
    std::string wan_ifname_ = "wan_fdh0";
    std::string lan_ifname_ = "lan_fdh0";
    TransparentFlowObservation observation_;
};

}  // namespace inline_proxy
