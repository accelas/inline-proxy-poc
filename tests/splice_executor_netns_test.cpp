#include <gtest/gtest.h>

#include "tests/netns_fixture.hpp"

TEST(SpliceExecutorNetnsTest, LeavesWorkloadWithWorkingReplacementEth0) {
    if (!inline_proxy::NetnsFixture::HasRequiredPrivileges()) {
        GTEST_SKIP() << "Requires CAP_NET_ADMIN/root and /usr/bin/ip";
    }

    auto env = inline_proxy::NetnsFixture::Create();
    ASSERT_TRUE(env.has_value());
    EXPECT_TRUE(env->RunSpliceExecutorScenario());
}
