#include <gtest/gtest.h>

#include "cni/cni_args.hpp"

TEST(CniArgsTest, ParsesPodIdentityFromStandardCniArgs) {
    const auto identity = inline_proxy::ParseCniArgs(
        "IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=backend-1");

    ASSERT_TRUE(identity.has_value());
    EXPECT_EQ(identity->namespace_name, "default");
    EXPECT_EQ(identity->pod_name, "backend-1");
}
