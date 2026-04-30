#include <chrono>
#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "cni/splice_executor.hpp"
#include "cni/splice_repair.hpp"
#include "shared/state_store.hpp"

namespace fs = std::filesystem;

namespace {

class SpliceRepairTest : public ::testing::Test {
protected:
    void SetUp() override {
        state_root_ = fs::temp_directory_path() /
            ("splice-repair-test-" + std::to_string(::getpid()) + "-" +
             std::to_string(reinterpret_cast<std::uintptr_t>(this)));
        fs::create_directories(state_root_);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(state_root_, ec);
    }

    fs::path state_root_;
};

}  // namespace

TEST_F(SpliceRepairTest, EmptyStateRootProducesZeroCounts) {
    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [](const auto&, const auto&, const auto&) { return true; };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, "/proc/self/ns/net");
    EXPECT_EQ(result.total_state_files, 0u);
    EXPECT_EQ(result.skipped_intact, 0u);
    EXPECT_EQ(result.skipped_workload_gone, 0u);
    EXPECT_EQ(result.skipped_deadline_exceeded, 0u);
    EXPECT_EQ(result.repaired, 0u);
    EXPECT_EQ(result.failed, 0u);
}

TEST_F(SpliceRepairTest, NonexistentStateRootProducesZeroCounts) {
    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_ / "does-not-exist";
    options.splice_runner = [](const auto&, const auto&, const auto&) { return true; };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, "/proc/self/ns/net");
    EXPECT_EQ(result.total_state_files, 0u);
    EXPECT_EQ(result.failed, 0u);
}
