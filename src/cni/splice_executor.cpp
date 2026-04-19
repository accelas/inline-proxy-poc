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

enum class SpliceStage {
    kInitial,
    kRenamedWorkload,
    kMovedWanToProxy,
    kCreatedReplacementPair,
    kMovedPeerToWorkload,
    kInstalledReplacement,
};

ScopedFd OpenNetnsFd(const std::filesystem::path& path) {
    return ScopedFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
}

std::string PeerNameForPlan(const SplicePlan& plan) {
    return "peer_" + plan.wan_name.substr(4);
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
    if ((options_.workload_netns_path.has_value() || options_.proxy_netns_path.has_value()) &&
        !ExecuteSplice(plan)) {
        result.stderr_text = "failed to execute inline proxy splice";
        return result;
    }

    StateStore store(plan.state_path);
    if (!store.Write(BuildStateFields(plan, invocation, workload_pod, *proxy_pod))) {
        RollbackSplice(plan);
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

bool SpliceExecutor::ExecuteSplice(const SplicePlan& plan) const {
    if (!options_.workload_netns_path.has_value() || !options_.proxy_netns_path.has_value()) {
        return true;
    }

    auto workload_netns_fd = OpenNetnsFd(*options_.workload_netns_path);
    auto proxy_netns_fd = OpenNetnsFd(*options_.proxy_netns_path);
    if (!workload_netns_fd || !proxy_netns_fd) {
        return false;
    }

    SpliceStage stage = SpliceStage::kInitial;
    const auto peer_name = PeerNameForPlan(plan);

    {
        auto workload_ns = ScopedNetns::Enter(*options_.workload_netns_path);
        if (!workload_ns) {
            return false;
        }
        if (!RenameLink(plan.ifname, plan.wan_name)) {
            return false;
        }
        stage = SpliceStage::kRenamedWorkload;
        if (!MoveLinkToNetns(plan.wan_name, proxy_netns_fd.get())) {
            BestEffortRollback(plan,
                               peer_name,
                               *options_.workload_netns_path,
                               *options_.proxy_netns_path,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        stage = SpliceStage::kMovedWanToProxy;
    }

    {
        auto proxy_ns = ScopedNetns::Enter(*options_.proxy_netns_path);
        if (!proxy_ns) {
            BestEffortRollback(plan,
                               peer_name,
                               *options_.workload_netns_path,
                               *options_.proxy_netns_path,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!SetLinkUp(plan.wan_name)) {
            BestEffortRollback(plan,
                               peer_name,
                               *options_.workload_netns_path,
                               *options_.proxy_netns_path,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!CreateVethPair(plan.lan_name, peer_name)) {
            BestEffortRollback(plan,
                               peer_name,
                               *options_.workload_netns_path,
                               *options_.proxy_netns_path,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        stage = SpliceStage::kCreatedReplacementPair;
        if (!SetLinkUp(plan.lan_name)) {
            BestEffortRollback(plan,
                               peer_name,
                               *options_.workload_netns_path,
                               *options_.proxy_netns_path,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!MoveLinkToNetns(peer_name, workload_netns_fd.get())) {
            BestEffortRollback(plan,
                               peer_name,
                               *options_.workload_netns_path,
                               *options_.proxy_netns_path,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        stage = SpliceStage::kMovedPeerToWorkload;
    }

    {
        auto workload_ns = ScopedNetns::Enter(*options_.workload_netns_path);
        if (!workload_ns) {
            BestEffortRollback(plan,
                               peer_name,
                               *options_.workload_netns_path,
                               *options_.proxy_netns_path,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        if (!RenameLink(peer_name, plan.ifname)) {
            BestEffortRollback(plan,
                               peer_name,
                               *options_.workload_netns_path,
                               *options_.proxy_netns_path,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
        stage = SpliceStage::kInstalledReplacement;
        if (!SetLinkUp(plan.ifname)) {
            BestEffortRollback(plan,
                               peer_name,
                               *options_.workload_netns_path,
                               *options_.proxy_netns_path,
                               workload_netns_fd.get(),
                               stage);
            return false;
        }
    }

    return true;
}

void SpliceExecutor::RollbackSplice(const SplicePlan& plan) const {
    if (!options_.workload_netns_path.has_value() || !options_.proxy_netns_path.has_value()) {
        return;
    }
    auto workload_netns_fd = OpenNetnsFd(*options_.workload_netns_path);
    if (!workload_netns_fd) {
        return;
    }
    BestEffortRollback(plan,
                       PeerNameForPlan(plan),
                       *options_.workload_netns_path,
                       *options_.proxy_netns_path,
                       workload_netns_fd.get(),
                       SpliceStage::kInstalledReplacement);
}

}  // namespace inline_proxy
