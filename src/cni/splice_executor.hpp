#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

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
};

struct CniExecutionResult {
    bool success = false;
    std::string stdout_json;
    std::string stderr_text;
    std::optional<SplicePlan> plan;
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
    CniExecutionOptions options_;
};

}  // namespace inline_proxy
