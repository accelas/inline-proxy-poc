#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace inline_proxy {

class NetnsFixture {
public:
    ~NetnsFixture();

    NetnsFixture(const NetnsFixture&) = delete;
    NetnsFixture& operator=(const NetnsFixture&) = delete;
    NetnsFixture(NetnsFixture&& other) noexcept;
    NetnsFixture& operator=(NetnsFixture&& other) noexcept;

    static bool HasRequiredPrivileges();
    static std::optional<NetnsFixture> Create();

    bool RunTransparentRelayScenario();
    bool RunSpliceExecutorScenario();

private:
    NetnsFixture(std::string prefix,
                 std::filesystem::path state_root) noexcept;

    bool CreateNamespaces();
    bool ResetNamespaces();
    bool RunCommand(const std::string& command) const;
    bool BuildBridgeBackedWorkloadTopology(const std::string& workload_ip_cidr,
                                           const std::string& client_ip_cidr,
                                           const std::string& gateway_ip);
    bool RootLinkExists(const std::string& ifname) const;
    bool RootRouteContains(const std::string& destination, const std::string& needle) const;

    std::string prefix_;
    std::string client_ns_;
    std::string proxy_ns_;
    std::string workload_ns_;
    std::filesystem::path state_root_;
    std::vector<std::string> root_links_;
    bool namespaces_created_ = false;
};

}  // namespace inline_proxy
