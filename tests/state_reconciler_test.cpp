#include <filesystem>

#include <gtest/gtest.h>

#include "proxy/interface_registry.hpp"
#include "proxy/state_reconciler.hpp"
#include "shared/state_store.hpp"

TEST(StateReconcilerTest, SyncsInterfacesFromStateFilesAndRemovesStaleOnes) {
    const auto state_root =
        std::filesystem::temp_directory_path() / "inline_proxy_state_reconciler_test";
    std::error_code ec;
    std::filesystem::remove_all(state_root, ec);
    std::filesystem::create_directories(state_root);

    inline_proxy::StateStore first(state_root / "first.json");
    inline_proxy::StateStore second(state_root / "second.json");
    ASSERT_TRUE(first.Write({{"wan_name", "wan_alpha"}, {"lan_name", "lan_alpha"}}));
    ASSERT_TRUE(second.Write({{"wan_name", "wan_beta"}, {"lan_name", "lan_beta"}}));

    inline_proxy::InterfaceRegistry registry;
    inline_proxy::StateReconciler reconciler(state_root);
    reconciler.Sync(registry);

    const auto synced = registry.SummaryText();
    EXPECT_NE(synced.find("wan_alpha"), std::string::npos);
    EXPECT_NE(synced.find("wan_beta"), std::string::npos);
    EXPECT_NE(synced.find("lan_alpha"), std::string::npos);
    EXPECT_NE(synced.find("lan_beta"), std::string::npos);

    ASSERT_TRUE(second.Remove());
    reconciler.Sync(registry);

    const auto pruned = registry.SummaryText();
    EXPECT_NE(pruned.find("wan_alpha"), std::string::npos);
    EXPECT_EQ(pruned.find("wan_beta"), std::string::npos);
    EXPECT_NE(pruned.find("lan_alpha"), std::string::npos);
    EXPECT_EQ(pruned.find("lan_beta"), std::string::npos);

    std::filesystem::remove_all(state_root, ec);
}
