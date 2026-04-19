#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "cni/netns_resolver.hpp"
#include "cni/splice_executor.hpp"
#include "cni/k8s_client.hpp"
#include "cni/yajl_parser.hpp"

namespace {

inline_proxy::CniInvocation MakeInvocation(std::string_view json, std::string_view ifname = "eth0") {
    auto request = inline_proxy::ParseCniRequest(std::string(json));
    EXPECT_TRUE(request.has_value());
    return inline_proxy::CniInvocation{
        .request = *request,
        .container_id = "container-1",
        .ifname = std::string(ifname),
    };
}

}  // namespace

TEST(CniNetnsResolverTest, UsesMatchingInterfaceSandboxForWorkloadNamespace) {
    const auto invocation = MakeInvocation(
        R"({"cniVersion":"1.0.0","name":"k8s-pod-network","prevResult":{"interfaces":[{"name":"net1","sandbox":"/var/run/netns/ignored"},{"name":"eth0","sandbox":"/var/run/netns/workload"}]}})");

    const auto path = inline_proxy::ResolveWorkloadNetnsPath(invocation);
    ASSERT_TRUE(path.has_value());
    EXPECT_EQ(*path, "/var/run/netns/workload");
}

TEST(CniNetnsResolverTest, FallsBackToFirstSandboxWhenInterfaceNameIsMissing) {
    const auto invocation = MakeInvocation(
        R"({"cniVersion":"1.0.0","name":"k8s-pod-network","prevResult":{"interfaces":[{"name":"net1","sandbox":"/var/run/netns/fallback"},{"name":"net2","sandbox":"/var/run/netns/other"}]}})",
        "eth0");

    const auto path = inline_proxy::ResolveWorkloadNetnsPath(invocation);
    ASSERT_TRUE(path.has_value());
    EXPECT_EQ(*path, "/var/run/netns/fallback");
}

TEST(CniNetnsResolverTest, FindsProxyNamespaceByMatchingPodIp) {
    const auto netns_root =
        std::filesystem::temp_directory_path() / "inline_proxy_cni_netns_resolver_test";
    std::error_code ec;
    std::filesystem::remove_all(netns_root, ec);
    std::filesystem::create_directories(netns_root);
    const auto wrong = netns_root / "proxy-wrong";
    const auto right = netns_root / "proxy-right";
    {
        std::ofstream wrong_stream(wrong);
        std::ofstream right_stream(right);
    }

    inline_proxy::PodInfo proxy_pod;
    proxy_pod.name = "inline-proxy-daemon-worker-1";
    proxy_pod.namespace_name = "inline-proxy-system";
    proxy_pod.node_name = "worker-1";
    proxy_pod.pod_ip = "10.42.0.9";
    proxy_pod.phase = "Running";
    proxy_pod.running = true;

    inline_proxy::SetNamespaceIpv4MatcherForTesting(
        [&](const std::filesystem::path& path, std::string_view address) {
            return path == right && address == "10.42.0.9";
        });

    const auto path = inline_proxy::ResolveProxyNetnsPath(proxy_pod, netns_root);
    ASSERT_TRUE(path.has_value());
    EXPECT_EQ(*path, right);

    inline_proxy::SetNamespaceIpv4MatcherForTesting({});
    std::filesystem::remove_all(netns_root, ec);
}
