#include "cni/splice_executor.hpp"

#include <utility>

#include "shared/state_store.hpp"

namespace inline_proxy {
namespace {

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
        {"prev_result", RenderPrevResultJson(invocation.request.prev_result)},
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
    result.stdout_json = RenderPrevResultJson(invocation.request.prev_result);

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

}  // namespace inline_proxy
