#include "cni/splice_executor.hpp"

#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sstream>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "bpf/loader.hpp"
#include "cni/netns_resolver.hpp"
#include "cni/yajl_parser.hpp"
#include "shared/netlink.hpp"
#include "shared/netns.hpp"
#include "shared/scoped_fd.hpp"
#include "shared/state_store.hpp"

namespace inline_proxy {
namespace {

using Json = nlohmann::json;

ScopedFd OpenNetnsFd(const std::filesystem::path& path) {
    return ScopedFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
}

std::string PeerNameForPlan(const SplicePlan& plan) {
    return "peer_" + plan.wan_name.substr(4);
}

std::string RootWanNameForPlan(const SplicePlan& plan) {
    return "rwan_" + plan.wan_name.substr(4);
}

struct WorkloadRoute {
    std::string dst;
    std::optional<std::string> gw;
};

struct WorkloadNetworkConfig {
    std::vector<std::string> addresses;
    std::vector<WorkloadRoute> routes;
    std::vector<std::string> pod_ips;
};

std::optional<unsigned int> WorkloadInterfaceIndex(const PrevResult& prev_result,
                                                   std::string_view ifname) {
    const auto& interfaces = prev_result.interfaces;
    for (std::size_t index = 0; index < interfaces.size(); ++index) {
        if (interfaces[index].name == ifname) {
            return static_cast<unsigned int>(index);
        }
    }

    return std::nullopt;
}

std::optional<unsigned int> WorkloadInterfaceIndex(const CniInvocation& invocation) {
    if (!invocation.request.prev_result.has_value()) {
        return std::nullopt;
    }
    return WorkloadInterfaceIndex(*invocation.request.prev_result, invocation.ifname);
}

std::optional<WorkloadNetworkConfig> ParseWorkloadNetworkConfig(std::string_view prev_result_json,
                                                                std::optional<unsigned int> interface_index) {
    const auto parsed = Json::parse(prev_result_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        return std::nullopt;
    }

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
            WorkloadRoute route{.dst = dst_it->get<std::string>()};
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

std::optional<WorkloadNetworkConfig> ParseWorkloadNetworkConfig(
    const CniInvocation& invocation) {
    if (!invocation.request.prev_result_json.has_value()) {
        return std::nullopt;
    }
    return ParseWorkloadNetworkConfig(*invocation.request.prev_result_json,
                                      WorkloadInterfaceIndex(invocation));
}

bool ReplaceInterfaceRoute(const std::string& ifname, const WorkloadRoute& route) {
    ::inline_proxy::RouteConfig cfg;
    cfg.cidr = route.dst;
    cfg.oif = ifname;
    if (route.gw.has_value()) {
        cfg.via = *route.gw;
    }
    return AddRoute(cfg, /*replace=*/true);
}

bool ReplaceRouteVia(const std::string& destination,
                     const std::string& via,
                     const std::string& ifname) {
    ::inline_proxy::RouteConfig cfg;
    cfg.cidr = destination;
    cfg.oif = ifname;
    cfg.via = via;
    return AddRoute(cfg, /*replace=*/true);
}

bool DeleteRouteOnDev(const std::string& destination, const std::string& ifname) {
    ::inline_proxy::RouteConfig cfg;
    cfg.cidr = destination;
    cfg.oif = ifname;
    return DeleteRoute(cfg);
}

bool EnableIpv4Forwarding() {
    std::ofstream stream("/proc/sys/net/ipv4/ip_forward");
    if (!stream) {
        return false;
    }
    stream << "1\n";
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
    std::string root_wan_cidr;
    std::string root_wan_ip;
    std::string proxy_wan_cidr;
    std::string proxy_wan_ip;
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
    const unsigned int octet = 1U + (seed % 254U);
    RoutedLinkConfig cfg;
    cfg.root_wan_ip = "169.254." + std::to_string(octet) + ".1";
    cfg.proxy_wan_ip = "169.254." + std::to_string(octet) + ".2";
    cfg.root_wan_cidr = cfg.root_wan_ip + "/30";
    cfg.proxy_wan_cidr = cfg.proxy_wan_ip + "/30";
    cfg.proxy_lan_ip = "169.254." + std::to_string(octet) + ".5";
    cfg.workload_lan_ip = "169.254." + std::to_string(octet) + ".6";
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

std::optional<std::string> PrimaryPodIp(const WorkloadNetworkConfig& network_config) {
    if (network_config.pod_ips.empty()) {
        return std::nullopt;
    }
    return network_config.pod_ips.front();
}

bool AddRouteViaInTable(const std::string& destination,
                        const std::string& via,
                        const std::string& ifname,
                        int table) {
    ::inline_proxy::RouteConfig cfg;
    cfg.cidr = destination;
    cfg.oif = ifname;
    cfg.via = via;
    cfg.table = static_cast<std::uint32_t>(table);
    return AddRoute(cfg, /*replace=*/true);
}

bool ReplaceSourceRule(const std::string& source_cidr, int table) {
    RuleConfig rule;
    rule.src_cidr = source_cidr;
    rule.table = static_cast<std::uint32_t>(table);
    (void)DeleteRule(rule);
    return AddRule(rule);
}

bool DeleteSourceRule(const std::string& source_cidr, int table) {
    RuleConfig rule;
    rule.src_cidr = source_cidr;
    rule.table = static_cast<std::uint32_t>(table);
    return DeleteRule(rule);
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

StateFields BuildStateFields(const SplicePlan& plan,
                             const CniInvocation& invocation,
                             const PodInfo& workload_pod,
                             const PodInfo& proxy_pod,
                             const ResolvedNetnsPaths& netns_paths) {
    const auto network_config = ParseWorkloadNetworkConfig(invocation);
    const auto root_wan_name = RootWanNameForPlan(plan);
    const auto workload_peer_name = PeerNameForPlan(plan);
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
        {"root_wan_name", root_wan_name},
        {"wan_name", plan.wan_name},
        {"workload_peer_name", workload_peer_name},
        {"workload_netns_path", netns_paths.workload.string()},
    };
}

}  // namespace

SpliceExecutor::SpliceExecutor(CniExecutionOptions options)
    : options_(std::move(options)) {
    if (!options_.tc_attacher) {
        options_.tc_attacher = std::make_shared<TcAttacher>(options_.pin_dir);
    }
    if (!options_.proxy_pod_pinner) {
        options_.proxy_pod_pinner = [](std::string_view pin_dir) {
            BpfLoader loader;
            return loader.LoadAndPin(pin_dir);
        };
    }
}

std::filesystem::path SpliceExecutor::StatePathForContainerId(std::string_view container_id) const {
    return BuildSplicePlan(container_id, "eth0", options_.state_root).state_path;
}

CniExecutionResult SpliceExecutor::HandleAdd(const CniInvocation& invocation,
                                             const PodInfo& workload_pod,
                                             const std::optional<PodInfo>& proxy_pod) const {
    CniExecutionResult result;
    result.stdout_json = RenderPrevResultJson(invocation.request);

    if (IsProxyPod(workload_pod)) {
        if (!options_.proxy_pod_pinner(options_.pin_dir)) {
            result.stderr_text = "failed to LoadAndPin BPF program for proxy DS pod";
            return result;
        }
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
        const auto ifname_it = state->find("ifname");
        const auto lan_it = state->find("lan_name");
        const auto pod_ips_it = state->find("pod_ips");
        const auto proxy_ns_it = state->find("proxy_netns_path");
        const auto route_table_it = state->find("route_table");
        const auto root_wan_it = state->find("root_wan_name");
        const auto workload_ns_it = state->find("workload_netns_path");
        const auto prev_result_it = state->find("prev_result");
        const auto ifname = ifname_it != state->end() ? ifname_it->second : "eth0";
        std::optional<WorkloadNetworkConfig> network_config;

        if (prev_result_it != state->end()) {
            const auto request = ParseCniRequest(std::string(
                R"({"cniVersion":"1.0.0","name":"restore","prevResult":)" +
                prev_result_it->second + "}"));
            if (request.has_value() && request->prev_result.has_value()) {
                network_config = ParseWorkloadNetworkConfig(
                    prev_result_it->second,
                    WorkloadInterfaceIndex(*request->prev_result, ifname));
            }
        }

        if (workload_ns_it != state->end() && network_config.has_value() &&
            std::filesystem::exists(workload_ns_it->second)) {
            if (auto workload_ns = ScopedNetns::Enter(workload_ns_it->second)) {
                FlushInterfaceAddresses(ifname);
                for (const auto& address : network_config->addresses) {
                    (void)AddInterfaceAddress(ifname, address);
                }
                for (const auto& route : network_config->routes) {
                    (void)ReplaceInterfaceRoute(ifname, route);
                }
            }
        }

        if (root_wan_it != state->end() && pod_ips_it != state->end()) {
            std::stringstream pod_ips_stream(pod_ips_it->second);
            std::string pod_ip;
            while (std::getline(pod_ips_stream, pod_ip, ',')) {
                if (!pod_ip.empty()) {
                    (void)DeleteRouteOnDev(pod_ip + "/32", root_wan_it->second);
                }
            }
            (void)DeleteLink(root_wan_it->second);
        }

        if (lan_it != state->end() && proxy_ns_it != state->end() && !proxy_ns_it->second.empty() &&
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
                                DeleteRouteOnDev(pod_ip + "/32", lan_it->second);
                            }
                        }
                    }
                    FlushRouteTable(static_cast<std::uint32_t>(table));
                }
                DeleteLink(lan_it->second);
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

    const auto root_wan_name = RootWanNameForPlan(plan);
    const auto peer_name = PeerNameForPlan(plan);
    const auto routed_link = RoutedLinkConfigForPlan(plan);
    const int route_table = RouteTableForPlan(plan);
    const auto primary_pod_ip = PrimaryPodIp(*network_config);
    std::optional<unsigned int> workload_mtu;
    {
        auto workload_ns = ScopedNetns::Enter(netns_paths.workload);
        if (!workload_ns) {
            return false;
        }
        workload_mtu = ReadLinkMtu(plan.ifname);
    }

    auto cleanup = [&] {
        (void)DeleteLink(root_wan_name);
        if (auto proxy_ns = ScopedNetns::Enter(netns_paths.proxy)) {
            (void)DeleteLink(plan.lan_name);
            for (const auto& pod_ip : network_config->pod_ips) {
                (void)DeleteSourceRule(pod_ip + "/32", route_table);
                (void)DeleteRouteOnDev(pod_ip + "/32", plan.lan_name);
            }
            (void)FlushRouteTable(static_cast<std::uint32_t>(route_table));
        }
    };

    if (!CreateVethPair(root_wan_name, plan.wan_name)) {
        std::cerr << "routed-splice: CreateVethPair(" << root_wan_name << "," << plan.wan_name << ") failed\n";
        return false;
    }
    if (workload_mtu.has_value() &&
        (!SetLinkMtu(root_wan_name, *workload_mtu) ||
         !SetLinkMtu(plan.wan_name, *workload_mtu))) {
        std::cerr << "routed-splice: SetLinkMtu on root_wan/plan_wan failed\n";
        cleanup();
        return false;
    }
    if (!MoveLinkToNetns(plan.wan_name, proxy_netns_fd.get())) {
        std::cerr << "routed-splice: MoveLinkToNetns(" << plan.wan_name << ") to proxy failed\n";
        cleanup();
        return false;
    }
    if (!AddInterfaceAddress(root_wan_name, routed_link.root_wan_cidr) || !SetLinkUp(root_wan_name)) {
        std::cerr << "routed-splice: root_wan addr/up failed cidr=" << routed_link.root_wan_cidr << "\n";
        cleanup();
        return false;
    }

    {
        auto proxy_ns = ScopedNetns::Enter(netns_paths.proxy);
        if (!proxy_ns) {
            std::cerr << "routed-splice: enter proxy netns failed\n";
            cleanup();
            return false;
        }
        if (!AddInterfaceAddress(plan.wan_name, routed_link.proxy_wan_cidr) ||
            !SetLinkUp(plan.wan_name)) {
            std::cerr << "routed-splice: proxy_wan addr/up failed\n";
            cleanup();
            return false;
        }
        if (!options_.tc_attacher->AttachToInterface(plan.wan_name)) {
            std::cerr << "routed-splice: tc_attach to " << plan.wan_name << " failed\n";
            cleanup();
            return false;
        }
        if (!CreateVethPair(plan.lan_name, peer_name)) {
            std::cerr << "routed-splice: CreateVethPair(lan,peer) failed\n";
            cleanup();
            return false;
        }
        if (workload_mtu.has_value() &&
            (!SetLinkMtu(plan.lan_name, *workload_mtu) || !SetLinkMtu(peer_name, *workload_mtu))) {
            std::cerr << "routed-splice: lan/peer SetLinkMtu failed\n";
            cleanup();
            return false;
        }
        if (!MoveLinkToNetns(peer_name, workload_netns_fd.get()) ||
            !AddInterfaceAddress(plan.lan_name, routed_link.proxy_lan_cidr) ||
            !SetLinkUp(plan.lan_name) ||
            !EnableIpv4Forwarding()) {
            std::cerr << "routed-splice: peer move / lan addr-up / ip_forward failed\n";
            cleanup();
            return false;
        }
        if (primary_pod_ip.has_value() &&
            !ReplaceRouteVia(*primary_pod_ip + "/32", routed_link.workload_lan_ip, plan.lan_name)) {
            cleanup();
            return false;
        }
        for (const auto& route : network_config->routes) {
            if (!AddRouteViaInTable(route.dst, routed_link.root_wan_ip, plan.wan_name, route_table)) {
                cleanup();
                return false;
            }
        }
        for (const auto& pod_ip : network_config->pod_ips) {
            if (!ReplaceSourceRule(pod_ip + "/32", route_table)) {
                cleanup();
                return false;
            }
        }
    }

    {
        auto workload_ns = ScopedNetns::Enter(netns_paths.workload);
        if (!workload_ns) {
            std::cerr << "routed-splice: enter workload netns failed\n";
            cleanup();
            return false;
        }
        if (workload_mtu.has_value() && !SetLinkMtu(peer_name, *workload_mtu)) {
            std::cerr << "routed-splice: workload-side SetLinkMtu(peer) failed\n";
            cleanup();
            return false;
        }
        if (!AddInterfaceAddress(peer_name, routed_link.workload_lan_cidr)) {
            std::cerr << "routed-splice: AddInterfaceAddress(" << peer_name << "," << routed_link.workload_lan_cidr << ") failed\n";
            cleanup();
            return false;
        }
        if (!SetLinkUp(peer_name)) {
            std::cerr << "routed-splice: SetLinkUp(" << peer_name << ") failed\n";
            cleanup();
            return false;
        }
        if (!FlushInterfaceAddresses(plan.ifname)) {
            std::cerr << "routed-splice: FlushInterfaceAddresses(" << plan.ifname << ") failed\n";
            cleanup();
            return false;
        }
        for (const auto& address : network_config->addresses) {
            if (!AddInterfaceAddress(plan.ifname, ForceHostMask(address))) {
                std::cerr << "routed-splice: AddInterfaceAddress(" << plan.ifname << "," << address << ") failed\n";
                cleanup();
                return false;
            }
        }
        if (!SetLinkUp(plan.ifname)) {
            std::cerr << "routed-splice: SetLinkUp(" << plan.ifname << ") failed\n";
            cleanup();
            return false;
        }
        for (const auto& route : network_config->routes) {
            if (!ReplaceRouteVia(route.dst, routed_link.proxy_lan_ip, peer_name)) {
                std::cerr << "routed-splice: workload-side ReplaceRouteVia(" << route.dst << ") failed\n";
                cleanup();
                return false;
            }
        }
    }

    if (primary_pod_ip.has_value() &&
        !ReplaceRouteVia(*primary_pod_ip + "/32", routed_link.proxy_wan_ip, root_wan_name)) {
        cleanup();
        return false;
    }

    return true;
}

void SpliceExecutor::RollbackSplice(const SplicePlan& plan,
                                    const ResolvedNetnsPaths& netns_paths) const {
    if (options_.splice_runner) {
        return;
    }
    (void)DeleteLink(RootWanNameForPlan(plan));
    if (auto proxy_ns = ScopedNetns::Enter(netns_paths.proxy)) {
        (void)DeleteLink(plan.lan_name);
        (void)FlushRouteTable(static_cast<std::uint32_t>(RouteTableForPlan(plan)));
    }
}

}  // namespace inline_proxy
