#include <dirent.h>

#include <gtest/gtest.h>

#include "tests/fd_netns_harness.hpp"

namespace {

int CountOpenFileDescriptors() {
    int count = 0;
    if (DIR* dir = ::opendir("/proc/self/fd")) {
        while (auto* entry = ::readdir(dir)) {
            if (entry->d_name[0] != '.') {
                ++count;
            }
        }
        ::closedir(dir);
    }
    return count;
}

}  // namespace

TEST(FdNetnsHarnessTest, InterceptsPort80TrafficTransparentlyWithCleanTeardown) {
    if (!inline_proxy::FdNetnsHarness::HasRequiredPrivileges()) {
        GTEST_SKIP() << "Requires CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, and /sbin/ip";
    }

    const int baseline_fds = CountOpenFileDescriptors();
    std::string server_peer;
    std::string proxy_client;
    std::string proxy_original_dst;
    int accepted_connections = 0;

    {
        auto harness = inline_proxy::FdNetnsHarness::Create();
        ASSERT_TRUE(harness.has_value());
        ASSERT_TRUE(harness->RunInterceptEchoScenario());
        const auto& observation = harness->observation();
        accepted_connections = observation.accepted_connections.load(std::memory_order_relaxed);
        server_peer = observation.server_peer;
        proxy_client = observation.proxy_client;
        proxy_original_dst = observation.proxy_original_dst;
        EXPECT_GE(accepted_connections, 1);
    }

    EXPECT_FALSE(server_peer.empty());
    EXPECT_FALSE(proxy_client.empty());
    EXPECT_EQ(server_peer.rfind("10.10.1.2:", 0), 0U);
    EXPECT_EQ(proxy_client.rfind("10.10.1.2:", 0), 0U);
    EXPECT_EQ(proxy_original_dst, "10.10.2.2:80");
    EXPECT_EQ(CountOpenFileDescriptors(), baseline_fds);
}
