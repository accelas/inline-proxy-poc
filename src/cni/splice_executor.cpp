#include "cni/splice_executor.hpp"

#include <fcntl.h>
#include <fstream>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sstream>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "cni/netns_resolver.hpp"
#include "shared/netlink.hpp"
#include "shared/netns.hpp"
#include "shared/scoped_fd.hpp"
#include "shared/state_store.hpp"

namespace inline_proxy {
namespace {

enum class SpliceStage {
    kInitial,
    kRenamedWorkload,
    kMovedWanToProxy,
    kCreatedReplacementPair,
    kMovedPeerToWorkload,
    kConfiguredProxyLan,
    kInstalledReplacement,
    kConfiguredWorkloadRoutes,
    kConfiguredProxyRoutes,
};

using Json = nlohmann::json;

ScopedFd OpenNetnsFd(const std::filesystem::path& path) {
    return ScopedFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
}

std::string PeerNameForPlan(const SplicePlan& plan) {
    return "peer_" + plan.wan_name.substr(4);
}

struct RouteConfig {
    std::string dst;
    std::optional<std::string> gw;
};

struct WorkloadNetworkConfig {
    std::vector<std::string> addresses;
    std::vector<RouteConfig> routes;
    std::vector<std::string> pod_ips;
};

std::optional<unsigned int> WorkloadInterfaceIndex(const CniInvocation& invocation) {
    if (!invocation.request.prev_result.has_value()) {
        return std::nullopt;
    }

    const auto& interfaces = invocation.request.prev_result->interfaces;
    for (std::size_t index = 0; index < interfaces.size(); ++index) {
        if (interfaces[index].name == invocation.ifname) {
            return static_cast<unsigned int>(index);
        }
    }

    return std::nullopt;
}

std::optional<WorkloadNetworkConfig> ParseWorkloadNetworkConfig(
    const CniInvocation& invocation) {
    if (!invocation.request.prev_result_json.has_value()) {
        return std::nullopt;
    }

    const auto parsed = Json::parse(*invocation.request.prev_result_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        return std::nullopt;
    }

    const auto interface_index = WorkloadInterfaceIndex(invocation);
    WorkloadNetworkConfig config;

    if (const auto ips_it = parsed.find("ips"); ips_it != parsed.end() && ips_it->is_array()) {
        for (const auto& entry : *ips_it) {
            if (!entry.is_object()) {
                continue;
            }
            if (interface_index.has_value()) {
                const auto iface_it = entry.find("interface");
                if (iface_it != entry.end() && iface_it->is_number_unsigned() &&
                    iface_it->get<unsigned int>() != *interface_index) {
                    continue;
                }
            }

            const auto address_it = entry.find("address");
            if (address_it == entry.end() || !address_it->is_string()) {
                continue;
            }

            const auto address = address_it->get<std::string>();
            config.addresses.push_back(address);
            const auto slash = address.find('/');
            config.pod_ips.push_back(
                slash == std::string::npos ? address : address.substr(0, slash));
        }
    }

    if (const auto routes_it = parsed.find("routes");
        routes_it != parsed.end() && routes_it->is_array()) {
        for (const auto& entry : *routes_it) {
            if (!entry.is_object()) {
                continue;
            }
            const auto dst_it = entry.find("dst");
            if (dst_it == entry.end() || !dst_it->is_string()) {
                continue;
            }
            RouteConfig route{.dst = dst_it->get<std::string>()};
            if (const auto gw_it = entry.find("gw");
                gw_it != entry.end() && gw_it->is_string()) {
                route.gw = gw_it->get<std::string>();
            }
            config.routes.push_back(std::move(route));
        }
    }

    if (config.addresses.empty()) {
        return std::nullopt;
    }

    return config;
}

bool RunIp(const std::vector<std::string>& args) {
    if (args.empty()) {
        return false;
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 2);
    argv.push_back(const_cast<char*>("/usr/bin/ip"));
    for (const auto& arg : args) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);

    const pid_t child = ::fork();
    if (child < 0) {
        return false;
    }
    if (child == 0) {
        ::execv("/usr/bin/ip", argv.data());
        _exit(127);
    }

    int status = 0;
    if (::waitpid(child, &status, 0) < 0) {
        return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool SetLinkMtu(const std::string& ifname, unsigned int mtu) {
    return RunIp({"link", "set", "dev", ifname, "mtu", std::to_string(mtu)});
}

bool AddInterfaceAddress(const std::string& ifname, const std::string& cidr) {
    return RunIp({"addr", "add", cidr, "dev", ifname});
}

bool FlushInterfaceAddresses(const std::string& ifname) {
    return RunIp({"addr", "flush", "dev", ifname});
}

bool AddRouteVia(const std::string& destination,
                const std::string& via,
                const std::string& ifname) {
    return RunIp({"route", "add", destination, "via", via, "dev", ifname});
}

bool EnableIpv4Forwarding() {
    std::ofstream stream("/proc/sys/net/ipv4/ip_forward");
    if (!stream) {
        return false;
    }
    stream << "1\n";
    return static_cast<bool>(stream);
}

bool SetInterfaceProxyArp(std::string_view ifname, bool enabled) {
    std::ofstream stream("/proc/sys/net/ipv4/conf/" + std::string(ifname) + "/proxy_arp");
    if (!stream) {
        return false;
    }
    stream << (enabled ? "1\n" : "0\n");
    return static_cast<bool>(stream);
}

std::string StripPrefix(std::string_view cidr) {
    const auto slash = cidr.find('/');
    return std::string(cidr.substr(0, slash));
}

std::string ForceHostMask(std::string_view cidr) {
    return StripPrefix(cidr) + "/32";
}

struct RoutedLinkConfig {
    std::string proxy_lan_cidr;
    std::string proxy_lan_ip;
    std::string workload_lan_cidr;
    std::string workload_lan_ip;
};

RoutedLinkConfig RoutedLinkConfigForPlan(const SplicePlan& plan) {
    const auto suffix = plan.wan_name.substr(4);
    unsigned int seed = 0;
    try {
        seed = std::stoul(suffix.substr(0, 4), nullptr, 16);
    } catch (...) {
        seed = 1;
    }
    const unsigned int block = seed % (254U * 64U);
    const unsigned int octet2 = 1U + (block / 64U);
    const unsigned int octet3_base = (block % 64U) * 4U;
    RoutedLinkConfig cfg;
    cfg.proxy_lan_ip = "169.254." + std::to_string(octet2) + "." + std::to_string(octet3_base + 1U);
    cfg.workload_lan_ip =
        "169.254." + std::to_string(octet2) + "." + std::to_string(octet3_base + 2U);
    cfg.proxy_lan_cidr = cfg.proxy_lan_ip + "/30";
    cfg.workload_lan_cidr = cfg.workload_lan_ip + "/30";
    return cfg;
}

int RouteTableForPlan(const SplicePlan& plan) {
    const auto suffix = plan.wan_name.substr(4);
    unsigned int seed = 0;
    try {
        seed = std::stoul(suffix.substr(0, 4), nullptr, 16);
    } catch (...) {
        seed = 1;
    }
    return 1000 + static_cast<int>(seed % 30000U);
}

bool AddDirectRouteInTable(const std::string& destination,
                           const std::string& ifname,
                           int table) {
    return RunIp({"route", "replace", destination, "dev", ifname, "table", std::to_string(table)});
}

bool AddRouteViaInTable(const std::string& destination,
                        const std::string& via,
                        const std::string& ifname,
                        int table) {
    return RunIp({"route", "replace", destination, "via", via, "dev", ifname, "table",
                  std::to_string(table)});
}

bool FlushRouteTable(int table) {
    return RunIp({"route", "flush", "table", std::to_string(table)});
}

bool ReplaceSourceRule(const std::string& source_cidr, int table) {
    RunIp({"rule", "del", "from", source_cidr, "table", std::to_string(table)});
    return RunIp({"rule", "add", "from", source_cidr, "table", std::to_string(table)});
}

bool DeleteSourceRule(const std::string& source_cidr, int table) {
    return RunIp({"rule", "del", "from", source_cidr, "table", std::to_string(table)});
}

std::optional<unsigned int> ReadLinkMtu(const std::string& ifname) {
    ScopedFd fd(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (!fd) {
        return std::nullopt;
    }

    ifreq request{};
    std::snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", ifname.c_str());
    if (::ioctl(fd.get(), SIOCGIFMTU, &request) != 0) {
        return std::nullopt;
    }

    return static_cast<unsigned int>(request.ifr_mtu);
}

void BestEffortRollback(const SplicePlan& plan,
                        std::string_view peer_name,
                        const std::filesystem::path& workload_netns_path,
                        const std::filesystem::path& proxy_netns_path,
                        int workload_netns_fd,
                        SpliceStage stage) {
    if (stage >= SpliceStage::kInstalledReplacement) {
        if (auto workload_ns = ScopedNetns::Enter(workload_netns_path)) {
            DeleteLink(plan.ifname);
        }
    } else if (stage >= SpliceStage::kMovedPeerToWorkload) {
        if (auto workload_ns = ScopedNetns::Enter(workload_netns_path)) {
            DeleteLink(std::string(peer_name));
        }
    }

    if (stage >= SpliceStage::kCreatedReplacementPair) {
        if (auto proxy_ns = ScopedNetns::Enter(proxy_netns_path)) {
            DeleteLink(plan.lan_name);
        }
    }

    if (stage >= SpliceStage::kMovedWanToProxy) {
        if (auto proxy_ns = ScopedNetns::Enter(proxy_netns_path)) {
            MoveLinkToNetns(plan.wan_name, workload_netns_fd);
        }
        if (auto workload_ns = ScopedNetns::Enter(workload_netns_path)) {
            RenameLink(plan.wan_name, plan.ifname);
            SetLinkUp(plan.ifname);
        }
        return;
    }

    if (stage >= SpliceStage::kRenamedWorkload) {
        if (auto workload_ns = ScopedNetns::Enter(workload_netns_path)) {
            RenameLink(plan.wan_name, plan.ifname);
            SetLinkUp(plan.ifname);
        }
    }
}

StateFields BuildStateFields(const SplicePlan& plan,
                             const CniInvocation& invocation,
                             const PodInfo& workload_pod,
                             const PodInfo& proxy_pod,
                             const ResolvedNetnsPaths& netns_paths) {
    const auto network_config = ParseWorkloadNetworkConfig(invocation);
    std::string pod_ips_joined;
    if (network_config.has_value()) {
        bool first = true;
        for (const auto& pod_ip : network_config->pod_ips) {
            if (!first) {
                pod_ips_joined.push_back(',');
            }
            pod_ips_joined += pod_ip;
            first = false;
        }
    }
    return StateFields{
        {"container_id", plan.container_id},
        {"ifname", plan.ifname},
        {"lan_name", plan.lan_name},
        {"pod_name", workload_pod.name},
        {"pod_namespace", workload_pod.namespace_name},
        {"pod_ips", pod_ips_joined},
        {"prev_result", RenderPrevResultJson(invocation.request)},
        {"proxy_netns_path", netns_paths.proxy.string()},
        {"proxy_name", proxy_pod.name},
        {"proxy_namespace", proxy_pod.namespace_name},
        {"proxy_node_name", proxy_pod.node_name},
        {"route_table", std::to_string(RouteTableForPlan(plan))},
        {"wan_name", plan.wan_name},
        {"workload_netns_path", netns_paths.workload.string()},
    };
}

}  // namespace

SpliceExecutor::SpliceExecutor(CniExecutionOptions options) : options_(std::move(options)) {}

std::filesystem::path SpliceExecutor::StatePathForContainerId(std::string_view container_id) const {
    return BuildSplicePlan(container_id, "eth0", options_.state_root).state_path;
}

CniExecutionResult SpliceExecutor::HandleAdd(const CniInvocation& invocation,
                                             const PodInfo& workload_pod,
                                             const std::optional<PodInfo>& proxy_pod) const {
    CniExecutionResult result;
    result.stdout_json = RenderPrevResultJson(invocation.request);

    if (IsProxyPod(workload_pod)) {
        result.success = true;
        return result;
    }

    if (!IsAnnotationEnabled(workload_pod)) {
        result.success = true;
        return result;
    }

    if (!proxy_pod.has_value() ||
        !MatchesNodeLocalProxy(*proxy_pod, workload_pod.node_name)) {
        result.stderr_text = "no node-local proxy pod found for annotated workload";
        return result;
    }

    const auto plan = BuildSplicePlan(invocation.container_id, invocation.ifname, options_.state_root);
    const auto netns_paths = ResolveNetnsPaths(invocation, *proxy_pod);
    if (!netns_paths.has_value()) {
        result.stderr_text = "failed to resolve workload or proxy network namespace";
        return result;
    }

    if (!ExecuteSplice(plan, *netns_paths, invocation)) {
        result.stderr_text = "failed to execute inline proxy splice";
        return result;
    }

    StateStore store(plan.state_path);
    if (!store.Write(BuildStateFields(plan, invocation, workload_pod, *proxy_pod, *netns_paths))) {
        RollbackSplice(plan, *netns_paths);
        result.stderr_text = "failed to persist inline proxy splice state";
        return result;
    }

    result.success = true;
    result.plan = plan;
    return result;
}

CniExecutionResult SpliceExecutor::HandleDel(const CniInvocation& invocation) const {
    CniExecutionResult result;
    const StateStore store(StatePathForContainerId(invocation.container_id));
    const auto state = store.Read();
    if (state.has_value()) {
        const auto wan_it = state->find("wan_name");
        const auto lan_it = state->find("lan_name");
        const auto pod_ips_it = state->find("pod_ips");
        const auto proxy_ns_it = state->find("proxy_netns_path");
        const auto route_table_it = state->find("route_table");
        if (wan_it != state->end() && lan_it != state->end() && proxy_ns_it != state->end() &&
            !proxy_ns_it->second.empty() &&
            std::filesystem::exists(proxy_ns_it->second)) {
            if (auto proxy_ns = ScopedNetns::Enter(proxy_ns_it->second)) {
                if (route_table_it != state->end()) {
                    const int table = std::stoi(route_table_it->second);
                    if (pod_ips_it != state->end()) {
                        std::stringstream pod_ips_stream(pod_ips_it->second);
                        std::string pod_ip;
                        while (std::getline(pod_ips_stream, pod_ip, ',')) {
                            if (!pod_ip.empty()) {
                                DeleteSourceRule(pod_ip + "/32", table);
                            }
                        }
                    }
                    FlushRouteTable(table);
                }
                DeleteLink(lan_it->second);
                DeleteLink(wan_it->second);
            }
        }
    }

    if (!store.Remove()) {
        result.stderr_text = "failed to remove inline proxy splice state";
        return result;
    }
    result.success = true;
    return result;
}

std::optional<ResolvedNetnsPaths> SpliceExecutor::ResolveNetnsPaths(
    const CniInvocation& invocation,
    const PodInfo& proxy_pod) const {
    ResolvedNetnsPaths resolved;
    if (options_.workload_netns_path.has_value()) {
        resolved.workload = *options_.workload_netns_path;
    } else {
        const auto workload_path = ResolveWorkloadNetnsPath(invocation);
        if (!workload_path.has_value()) {
            return std::nullopt;
        }
        resolved.workload = *workload_path;
    }

    if (options_.proxy_netns_path.has_value()) {
        resolved.proxy = *options_.proxy_netns_path;
    } else {
        const auto proxy_path = ResolveProxyNetnsPath(proxy_pod, options_.proxy_netns_root);
        if (!proxy_path.has_value()) {
            return std::nullopt;
        }
        resolved.proxy = *proxy_path;
    }

    return resolved;
}

bool SpliceExecutor::ExecuteSplice(const SplicePlan& plan,
                                   const ResolvedNetnsPaths& netns_paths,
                                   const CniInvocation& invocation) const {
    if (options_.splice_runner) {
        return options_.splice_runner(plan, netns_paths.workload, netns_paths.proxy);
    }

    const auto network_config = ParseWorkloadNetworkConfig(invocation);
    if (!network_config.has_value()) {
        return false;
    }

    auto workload_netns_fd = OpenNetnsFd(netns_paths.workload);
    auto proxy_netns_fd = OpenNetnsFd(netns_paths.proxy);
    if (!workload_netns_fd || !proxy_netns_fd) {
        return false;
    }

    SpliceStage stage = SpliceStage::kInitial;
    const auto peer_name = PeerNameForPlan(plan);
    std::optional<unsigned int> workload_mtu;

    {
        auto workload_ns = ScopedNetns::Enter(netns_paths.workload);
        if (!workload_ns) {
            return false;
        }
        workload_mtu = ReadLinkMtu(plan.ifname);
        if (!RenameLink(plan.ifname, plan.wan_name)) {
            return false;
        }
        stage = SpliceStage::kRenamedWorkload;
        if (!MoveLinkToNetns(plan.wan_name, proxy_netns_fd.get())) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        stage = SpliceStage::kMovedWanToProxy;
    }

    {
        auto proxy_ns = ScopedNetns::Enter(netns_paths.proxy);
        if (!proxy_ns) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!SetLinkUp(plan.wan_name)) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!SetInterfaceProxyArp(plan.wan_name, true)) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!CreateVethPair(plan.lan_name, peer_name)) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        stage = SpliceStage::kCreatedReplacementPair;
        if (workload_mtu.has_value() &&
            (!SetLinkMtu(plan.lan_name, *workload_mtu) ||
             !SetLinkMtu(peer_name, *workload_mtu))) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!FlushInterfaceAddresses(plan.wan_name)) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!SetLinkUp(plan.lan_name)) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!MoveLinkToNetns(peer_name, workload_netns_fd.get())) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        stage = SpliceStage::kMovedPeerToWorkload;
    }

    {
        auto workload_ns = ScopedNetns::Enter(netns_paths.workload);
        if (!workload_ns) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!RenameLink(peer_name, plan.ifname)) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        stage = SpliceStage::kInstalledReplacement;
        if (workload_mtu.has_value() && !SetLinkMtu(plan.ifname, *workload_mtu)) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!SetLinkUp(plan.ifname)) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        const auto routed_link = RoutedLinkConfigForPlan(plan);
        if (!AddInterfaceAddress(plan.ifname, routed_link.workload_lan_cidr)) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        for (const auto& address : network_config->addresses) {
            if (!AddInterfaceAddress(plan.ifname, ForceHostMask(address))) {
                BestEffortRollback(plan,
                                   peer_name,
                                   netns_paths.workload,
                                   netns_paths.proxy,
                                   workload_netns_fd.get(),
                                   stage);
                return false;
            }
        }
        for (const auto& route : network_config->routes) {
            if (!AddRouteVia(route.dst, routed_link.proxy_lan_ip, plan.ifname)) {
                BestEffortRollback(plan,
                                   peer_name,
                                   netns_paths.workload,
                                   netns_paths.proxy,
                                   workload_netns_fd.get(),
                                   stage);
                return false;
            }
        }
        stage = SpliceStage::kConfiguredWorkloadRoutes;
    }

    {
        auto proxy_ns = ScopedNetns::Enter(netns_paths.proxy);
        if (!proxy_ns) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        const auto routed_link = RoutedLinkConfigForPlan(plan);
        const int route_table = RouteTableForPlan(plan);
        if (!AddInterfaceAddress(plan.lan_name, routed_link.proxy_lan_cidr) ||
            !EnableIpv4Forwarding()) {
            BestEffortRollback(plan,
                               peer_name,
                               netns_paths.workload,
                               netns_paths.proxy,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        stage = SpliceStage::kConfiguredProxyLan;
        for (const auto& pod_ip : network_config->pod_ips) {
            if (!AddRouteVia(pod_ip + "/32", routed_link.workload_lan_ip, plan.lan_name)) {
                BestEffortRollback(plan,
                                   peer_name,
                                   netns_paths.workload,
                                   netns_paths.proxy,
                                   workload_netns_fd.get(),
                                   stage);
                return false;
            }
        }
        for (const auto& route : network_config->routes) {
            if (route.gw.has_value()) {
                if (!AddDirectRouteInTable(*route.gw + "/32", plan.wan_name, route_table) ||
                    !AddRouteViaInTable(route.dst, *route.gw, plan.wan_name, route_table)) {
                    BestEffortRollback(plan,
                                       peer_name,
                                       netns_paths.workload,
                                       netns_paths.proxy,
                                       workload_netns_fd.get(),
                                       stage);
                    return false;
                }
            } else if (!AddDirectRouteInTable(route.dst, plan.wan_name, route_table)) {
                BestEffortRollback(plan,
                                   peer_name,
                                   netns_paths.workload,
                                   netns_paths.proxy,
                                   workload_netns_fd.get(),
                                   stage);
                return false;
            }
        }
        for (const auto& pod_ip : network_config->pod_ips) {
            if (!ReplaceSourceRule(pod_ip + "/32", route_table)) {
                BestEffortRollback(plan,
                                   peer_name,
                                   netns_paths.workload,
                                   netns_paths.proxy,
                                   workload_netns_fd.get(),
                                   stage);
                return false;
            }
        }
        stage = SpliceStage::kConfiguredProxyRoutes;
    }

    return true;
}

void SpliceExecutor::RollbackSplice(const SplicePlan& plan,
                                    const ResolvedNetnsPaths& netns_paths) const {
    if (options_.splice_runner) {
        return;
    }
    auto workload_netns_fd = OpenNetnsFd(netns_paths.workload);
    if (!workload_netns_fd) {
        return;
    }
    BestEffortRollback(plan,
                       PeerNameForPlan(plan),
                       netns_paths.workload,
                       netns_paths.proxy,
                       workload_netns_fd.get(),
                       SpliceStage::kInstalledReplacement);
}

}  // namespace inline_proxy
