#include "cni/splice_repair.hpp"

namespace inline_proxy {

SpliceRepairResult RepairOrphanedSplices(const SpliceExecutor& /*executor*/,
                                         std::filesystem::path /*current_proxy_netns*/,
                                         std::chrono::steady_clock::duration /*deadline*/) {
    return SpliceRepairResult{};
}

}  // namespace inline_proxy
