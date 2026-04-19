#include <gtest/gtest.h>

#include "cni/splice_plan.hpp"

TEST(SplicePlanTest, CreatesWanAndLanNamesFromContainerId) {
    auto plan = inline_proxy::BuildSplicePlan("1234567890abcdef", "eth0");
    EXPECT_EQ(plan.wan_name, "wan_12345678");
    EXPECT_EQ(plan.lan_name, "lan_12345678");
}
