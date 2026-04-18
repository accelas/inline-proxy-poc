#include <gtest/gtest.h>

#include <string>

#include "proxy/interface_registry.hpp"

TEST(InterfaceRegistryTest, TracksAndRemovesWanAndLanInterfaces) {
    inline_proxy::InterfaceRegistry registry;

    EXPECT_EQ(registry.SummaryText(), "wan_interfaces=none\nlan_interfaces=none\nactive_sessions=0\n");

    registry.RecordInterface("wan_eth0");
    registry.RecordInterface("lan_eth1");
    registry.IncrementSessions();

    const auto added = registry.SummaryText();
    EXPECT_NE(added.find("wan_eth0"), std::string::npos);
    EXPECT_NE(added.find("lan_eth1"), std::string::npos);
    EXPECT_NE(added.find("active_sessions=1"), std::string::npos);

    registry.RemoveInterface("wan_eth0");
    registry.RemoveInterface("lan_eth1");
    registry.DecrementSessions();

    EXPECT_EQ(registry.SummaryText(), "wan_interfaces=none\nlan_interfaces=none\nactive_sessions=0\n");
}
