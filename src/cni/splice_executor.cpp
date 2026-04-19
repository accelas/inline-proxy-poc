#include "cni/splice_executor.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <utility>

#include "shared/netlink.hpp"
#include "shared/netns.hpp"
#include "shared/scoped_fd.hpp"
#include "shared/state_store.hpp"

namespace inline_proxy {
namespace {

ScopedFd OpenNetnsFd(const std::filesystem::path& path) {
    return ScopedFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
}

std::string PeerNameForPlan(const SplicePlan& plan) {
    return "peer_" + plan.wan_name.substr(4);
}

StateFields BuildStateFields(const SplicePlan& plan,
                             const CniInvocation& invocation,
                             const PodInfo& workload_pod,
                             const PodInfo& proxy_pod) {
    return StateFields{
        {"container_id", plan.container_id},
        {"ifname", plan.ifname},
        {"lan_name", plan.lan_name},
        {"pod_name", workload_pod.name},
        {"pod_namespace", workload_pod.namespace_name},
        {"prev_result", RenderPrevResultJson(invocation.request)},
        {"proxy_name", proxy_pod.name},
        {"proxy_namespace", proxy_pod.namespace_name},
        {"proxy_node_name", proxy_pod.node_name},
        {"wan_name", plan.wan_name},
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
    StateStore store(plan.state_path);
    if (!store.Write(BuildStateFields(plan, invocation, workload_pod, *proxy_pod))) {
        result.stderr_text = "failed to persist inline proxy splice state";
        return result;
    }

    if ((options_.workload_netns_path.has_value() || options_.proxy_netns_path.has_value()) &&
        !ExecuteSplice(plan)) {
        result.stderr_text = "failed to execute inline proxy splice";
        return result;
    }

    result.success = true;
    result.plan = plan;
    return result;
}

CniExecutionResult SpliceExecutor::HandleDel(const CniInvocation& invocation) const {
    CniExecutionResult result;
    StateStore store(StatePathForContainerId(invocation.container_id));
    if (!store.Remove()) {
        result.stderr_text = "failed to remove inline proxy splice state";
        return result;
    }
    result.success = true;
    return result;
}

bool SpliceExecutor::ExecuteSplice(const SplicePlan& plan) const {
    if (!options_.workload_netns_path.has_value() || !options_.proxy_netns_path.has_value()) {
        return true;
    }

    auto workload_netns_fd = OpenNetnsFd(*options_.workload_netns_path);
    auto proxy_netns_fd = OpenNetnsFd(*options_.proxy_netns_path);
    if (!workload_netns_fd || !proxy_netns_fd) {
        return false;
    }

    {
        auto workload_ns = ScopedNetns::Enter(*options_.workload_netns_path);
        if (!workload_ns) {
            return false;
        }
        if (!RenameLink(plan.ifname, plan.wan_name)) {
            return false;
        }
        if (!MoveLinkToNetns(plan.wan_name, proxy_netns_fd.get())) {
            return false;
        }
    }

    const auto peer_name = PeerNameForPlan(plan);
    {
        auto proxy_ns = ScopedNetns::Enter(*options_.proxy_netns_path);
        if (!proxy_ns) {
            return false;
        }
        if (!SetLinkUp(plan.wan_name)) {
            return false;
        }
        if (!CreateVethPair(plan.lan_name, peer_name)) {
            return false;
        }
        if (!SetLinkUp(plan.lan_name)) {
            return false;
        }
        if (!MoveLinkToNetns(peer_name, workload_netns_fd.get())) {
            return false;
        }
    }

    {
        auto workload_ns = ScopedNetns::Enter(*options_.workload_netns_path);
        if (!workload_ns) {
            return false;
        }
        if (!RenameLink(peer_name, plan.ifname)) {
            return false;
        }
        if (!SetLinkUp(plan.ifname)) {
            return false;
        }
    }

    return true;
}

}  // namespace inline_proxy
