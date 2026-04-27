#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "bpf/tc_attach.hpp"
#include "cni/cni_types.hpp"
#include "cni/splice_plan.hpp"

namespace inline_proxy {

struct CniInvocation {
    CniRequest request;
    std::string container_id;
    std::string ifname;
};

struct CniExecutionOptions {
    std::filesystem::path state_root = "/var/run/inline-proxy-cni";
    std::filesystem::path proxy_netns_root = "/var/run/netns";
    std::optional<std::filesystem::path> workload_netns_path;
    std::optional<std::filesystem::path> proxy_netns_path;
    std::function<bool(const SplicePlan&,
                       const std::filesystem::path&,
                       const std::filesystem::path&)>
        splice_runner;
    // Injected so tests can substitute a stub. Default-constructed by
    // SpliceExecutor's constructor when the caller doesn't provide one,
    // pointing at /sys/fs/bpf/inline-proxy.
    std::shared_ptr<TcAttacher> tc_attacher;

    // Invoked when the workload being admitted IS the proxy DS pod
    // (IsProxyPod() matches). Default-initialised by SpliceExecutor's
    // ctor to a callable that drives BpfLoader::LoadAndPin against the
    // pin dir; tests can substitute a stub.
    std::function<bool(std::string_view pin_dir)> proxy_pod_pinner;

    // Pin dir used by the default proxy_pod_pinner. Tests typically
    // override this to a temp dir.
    std::string pin_dir = "/sys/fs/bpf/inline-proxy";
};

struct CniExecutionResult {
    bool success = false;
    std::string stdout_json;
    std::string stderr_text;
    std::optional<SplicePlan> plan;
};

struct ResolvedNetnsPaths {
    std::filesystem::path workload;
    std::filesystem::path proxy;
};

class SpliceExecutor {
public:
    explicit SpliceExecutor(CniExecutionOptions options = {});

    std::filesystem::path StatePathForContainerId(std::string_view container_id) const;

    CniExecutionResult HandleAdd(const CniInvocation& invocation,
                                 const PodInfo& workload_pod,
                                 const std::optional<PodInfo>& proxy_pod) const;

    CniExecutionResult HandleDel(const CniInvocation& invocation) const;

private:
    std::optional<ResolvedNetnsPaths> ResolveNetnsPaths(
        const CniInvocation& invocation,
        const PodInfo& proxy_pod) const;
    bool ExecuteSplice(const SplicePlan& plan,
                       const ResolvedNetnsPaths& netns_paths,
                       const CniInvocation& invocation) const;
    void RollbackSplice(const SplicePlan& plan, const ResolvedNetnsPaths& netns_paths) const;

    CniExecutionOptions options_;
};

}  // namespace inline_proxy
