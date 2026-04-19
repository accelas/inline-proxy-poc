#include <filesystem>

#include <gtest/gtest.h>

#include "cni/splice_plan.hpp"

TEST(SplicePlanTest, CreatesWanAndLanNamesFromContainerId) {
    auto plan = inline_proxy::BuildSplicePlan("1234567890abcdef", "eth0");
    EXPECT_EQ(plan.wan_name, "wan_12345678");
    EXPECT_EQ(plan.lan_name, "lan_12345678");
}

TEST(SplicePlanTest, KeepsStatePathWithinStateRootForPathLikeContainerIds) {
    const auto state_root = std::filesystem::temp_directory_path() / "inline_proxy_cni_state_test";
    const auto plan = inline_proxy::BuildSplicePlan("../../escape/../abc", "eth0", state_root);

    EXPECT_EQ(plan.state_path.parent_path(), state_root);
}
