#include <gtest/gtest.h>
#include <stdexcept>

#include "proxy/admin_http.hpp"
#include "proxy/interface_registry.hpp"

TEST(AdminHttpTest, HealthAndReadinessEndpointsReturn200) {
    inline_proxy::ProxyState state;
    inline_proxy::InterfaceRegistry registry;
    auto app = inline_proxy::BuildAdminHttp(state, registry);
    const auto health = app.Handle("GET", "/healthz");
    const auto ready = app.Handle("GET", "/readyz");

    EXPECT_EQ(health.status, 200);
    EXPECT_EQ(health.content_type, "text/plain; charset=utf-8");
    EXPECT_EQ(health.body, "ok\n");
    EXPECT_EQ(ready.status, 200);
    EXPECT_EQ(ready.content_type, "text/plain; charset=utf-8");
    EXPECT_EQ(ready.body, "ready\n");
}

TEST(AdminHttpTest, MetricsAndSessionsEndpointsReturnText) {
    inline_proxy::ProxyState state;
    inline_proxy::InterfaceRegistry registry;
    auto app = inline_proxy::BuildAdminHttp(state, registry);

    const auto metrics = app.Handle("GET", "/metrics");
    const auto sessions = app.Handle("GET", "/sessions");

    EXPECT_EQ(metrics.status, 200);
    EXPECT_EQ(metrics.content_type, "text/plain; version=0.0.4; charset=utf-8");
    EXPECT_NE(metrics.body.find("inline_proxy_ready"), std::string::npos);
    EXPECT_NE(metrics.body.find("inline_proxy_active_sessions"), std::string::npos);

    EXPECT_EQ(sessions.status, 200);
    EXPECT_EQ(sessions.content_type, "text/plain; charset=utf-8");
    EXPECT_NE(sessions.body.find("active_sessions="), std::string::npos);
}

TEST(AdminHttpTest, UnknownOrUnsupportedRequestsReturnExpectedStatus) {
    inline_proxy::ProxyState state;
    inline_proxy::InterfaceRegistry registry;
    auto app = inline_proxy::BuildAdminHttp(state, registry);

    EXPECT_EQ(app.Handle("GET", "/does-not-exist").status, 404);
    EXPECT_EQ(app.Handle("POST", "/healthz").status, 405);
}

TEST(AdminHttpTest, InterfacesEndpointReturnsRegistryStateAndIsGetOnly) {
    inline_proxy::ProxyState state;
    inline_proxy::InterfaceRegistry registry;
    EXPECT_TRUE(registry.RecordInterface("lan_eth1"));

    auto app = inline_proxy::BuildAdminHttp(state, registry);
    const auto interfaces = app.Handle("GET", "/interfaces");

    EXPECT_EQ(interfaces.status, 200);
    EXPECT_EQ(interfaces.content_type, "text/plain; charset=utf-8");
    EXPECT_NE(interfaces.body.find("lan_eth1"), std::string::npos);

    EXPECT_EQ(app.Handle("POST", "/interfaces").status, 405);
}


TEST(ProxyStateTest, DecrementSessionsUnderflowThrows) {
    inline_proxy::ProxyState state;
    EXPECT_THROW(state.decrement_sessions(), std::logic_error);
}
