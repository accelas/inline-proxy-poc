#include <gtest/gtest.h>

#include "cni/k8s_client.hpp"

TEST(K8sClientTest, ParsesPodLookupResponse) {
    std::string json = R"({
        "apiVersion":"v1",
        "kind":"Pod",
        "metadata":{
            "name":"proxy-1",
            "namespace":"inline-proxy-system",
            "labels":{"app":"inline-proxy"},
            "annotations":{"inline-proxy.example.com/enabled":"true"}
        },
        "spec":{"nodeName":"worker-1"},
        "status":{"phase":"Running"}
    })";

    auto pod = inline_proxy::ParsePodInfo(json);
    ASSERT_TRUE(pod.has_value());
    EXPECT_EQ(pod->name, "proxy-1");
    EXPECT_EQ(pod->namespace_name, "inline-proxy-system");
    EXPECT_EQ(pod->node_name, "worker-1");
    EXPECT_TRUE(pod->running);
    EXPECT_EQ(pod->labels.at("app"), "inline-proxy");
    EXPECT_EQ(pod->annotations.at("inline-proxy.example.com/enabled"), "true");
}

TEST(K8sClientTest, BuildsDefaultInClusterApiEndpoint) {
    const auto endpoint = inline_proxy::BuildK8sApiEndpoint("10.0.0.1", "443");
    EXPECT_EQ(endpoint, "https://10.0.0.1:443");
}

TEST(K8sClientTest, FetchPodInfoUsesInjectedFetcher) {
    const inline_proxy::K8sQuery query{.namespace_name = "inline-proxy-system", .pod_name = "proxy-1"};

    inline_proxy::SetK8sResponseFetcherForTesting(
        [](const inline_proxy::K8sClientOptions&, const inline_proxy::K8sQuery&) {
            return std::optional<std::string>(R"({
                "metadata":{"name":"proxy-1","namespace":"inline-proxy-system"},
                "spec":{"nodeName":"worker-1"},
                "status":{"phase":"Running"}
            })");
        });

    const auto pod = inline_proxy::FetchPodInfo(query);
    EXPECT_EQ(pod.name, "proxy-1");
    EXPECT_EQ(pod.node_name, "worker-1");
    EXPECT_TRUE(pod.running);

    inline_proxy::SetK8sResponseFetcherForTesting({});
}
