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

inline std::string MakePrevResultJson(std::string_view sandbox) {
    std::string s;
    s.reserve(160 + sandbox.size());
    s += R"({"interfaces":[{"name":"eth0","sandbox":")";
    s += sandbox;
    s += R"("}],"ips":[{"address":"10.42.0.10/24","gateway":"10.42.0.1","interface":0}],"routes":[{"dst":"0.0.0.0/0","gw":"10.42.0.1"}]})";
    return s;
}

inline void WriteStateFile(const fs::path& dir,
                           std::string_view container_id,
                           std::string_view workload_netns_path,
                           std::string_view proxy_netns_path) {
    inline_proxy::StateStore store(dir / ("container-" + std::string(container_id) + ".json"));
    inline_proxy::StateFields fields = {
        {"container_id", std::string(container_id)},
        {"ifname", "eth0"},
        {"pod_name", "caddy-1"},
        {"pod_namespace", "default"},
        {"prev_result", MakePrevResultJson(workload_netns_path)},
        {"proxy_netns_path", std::string(proxy_netns_path)},
        {"proxy_name", "inline-proxy-daemon-x"},
        {"proxy_namespace", "inline-proxy-system"},
        {"proxy_node_name", "worker-1"},
        {"workload_netns_path", std::string(workload_netns_path)},
    };
    ASSERT_TRUE(store.Write(fields));
}

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

TEST_F(SpliceRepairTest, MatchingProxyInodeIsSkippedIntact) {
    const auto netns_path = state_root_ / "fake-netns";
    std::ofstream(netns_path).put('x');

    const auto workload_path = state_root_ / "fake-workload-netns";
    std::ofstream(workload_path).put('x');

    WriteStateFile(state_root_, "abc", workload_path.string(), netns_path.string());

    bool runner_called = false;
    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [&](const auto&, const auto&, const auto&) {
        runner_called = true;
        return true;
    };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, netns_path);
    EXPECT_EQ(result.total_state_files, 1u);
    EXPECT_EQ(result.skipped_intact, 1u);
    EXPECT_EQ(result.repaired, 0u);
    EXPECT_FALSE(runner_called);
}

TEST_F(SpliceRepairTest, MissingWorkloadNetnsIsSkippedAsGone) {
    const auto current_path = state_root_ / "current";
    std::ofstream(current_path).put('x');
    const auto stale_proxy = state_root_ / "stale-proxy";
    std::ofstream(stale_proxy).put('y');

    WriteStateFile(state_root_, "wlgone",
                   /*workload_netns_path=*/(state_root_ / "definitely-missing").string(),
                   stale_proxy.string());

    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [](const auto&, const auto&, const auto&) { return true; };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, current_path);
    EXPECT_EQ(result.total_state_files, 1u);
    EXPECT_EQ(result.skipped_workload_gone, 1u);
    EXPECT_EQ(result.skipped_intact, 0u);
    EXPECT_EQ(result.repaired, 0u);
    EXPECT_EQ(result.failed, 0u);
}
