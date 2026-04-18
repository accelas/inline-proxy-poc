#include <gtest/gtest.h>

#include "proxy/admin_http.hpp"

TEST(AdminHttpTest, HealthAndReadinessEndpointsReturn200) {
    inline_proxy::ProxyState state;
    auto app = inline_proxy::BuildAdminHttp(state);
    EXPECT_EQ(app.Handle("GET", "/healthz").status, 200);
    EXPECT_EQ(app.Handle("GET", "/readyz").status, 200);
}

TEST(AdminHttpTest, MetricsAndSessionsEndpointsReturn200) {
    inline_proxy::ProxyState state;
    auto app = inline_proxy::BuildAdminHttp(state);
    EXPECT_EQ(app.Handle("GET", "/metrics").status, 200);
    EXPECT_EQ(app.Handle("GET", "/sessions").status, 200);
}
