#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>

#include "cni/splice_executor.hpp"

namespace inline_proxy {

struct SpliceRepairResult {
    std::size_t total_state_files = 0;
    std::size_t skipped_intact = 0;
    std::size_t skipped_workload_gone = 0;
    std::size_t skipped_deadline_exceeded = 0;
    std::size_t repaired = 0;
    std::size_t failed = 0;
};

// Walk every container-*.json in `executor.options().state_root`. For each,
// compare the recorded `proxy_netns_path` inode to `current_proxy_netns`'s
// inode; if they differ, fabricate a CniInvocation + PodInfo pair from the
// state file fields and call `executor.HandleAdd` to re-splice the workload
// into `current_proxy_netns`. Per-pod failures are logged to std::cerr and
// counted in `failed`; they do not abort the scan.
//
// At the top of each per-state-file iteration, the wall-clock deadline is
// re-evaluated. Once exceeded, remaining files bump
// `skipped_deadline_exceeded` and the function returns. Default budget is
// 30 seconds — well under kubelet's CNI ADD timeout.
SpliceRepairResult RepairOrphanedSplices(
    const SpliceExecutor& executor,
    std::filesystem::path current_proxy_netns,
    std::chrono::steady_clock::duration deadline = std::chrono::seconds(30));

}  // namespace inline_proxy
