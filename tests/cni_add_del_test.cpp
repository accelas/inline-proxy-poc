#include <filesystem>
#include <optional>

#include <gtest/gtest.h>

#include "cni/splice_executor.hpp"
#include "cni/splice_plan.hpp"
#include "cni/yajl_parser.hpp"
#include "shared/state_store.hpp"

namespace {

inline_proxy::PodInfo MakeWorkloadPod() {
    inline_proxy::PodInfo pod;
    pod.name = "backend-1";
    pod.namespace_name = "default";
    pod.node_name = "worker-1";
    pod.phase = "Running";
    pod.running = true;
    pod.annotations["inline-proxy.example.com/enabled"] = "true";
    return pod;
}

inline_proxy::PodInfo MakeUnannotatedWorkloadPod() {
    inline_proxy::PodInfo pod = MakeWorkloadPod();
    pod.annotations.clear();
    return pod;
}

inline_proxy::PodInfo MakeProxyPod() {
    inline_proxy::PodInfo pod;
    pod.name = "inline-proxy-daemon-worker-1";
    pod.namespace_name = "inline-proxy-system";
    pod.node_name = "worker-1";
    pod.phase = "Running";
    pod.running = true;
    pod.labels["app"] = "inline-proxy";
    return pod;
}

inline_proxy::CniRequest MakeRequest() {
    auto prev_result = inline_proxy::ParsePrevResult(R"({"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}]})");
    EXPECT_TRUE(prev_result.has_value());

    inline_proxy::CniRequest request;
    request.cni_version = "1.0.0";
    request.name = "k8s-pod-network";
    request.prev_result = std::move(prev_result);
    return request;
}

}  // namespace

TEST(CniAddDelTest, AnnotatedAddWritesStateAndPassesThroughPrevResult) {
    const auto state_root = std::filesystem::temp_directory_path() / "inline_proxy_cni_add_test";
    std::error_code ec;
    std::filesystem::remove_all(state_root, ec);

    inline_proxy::SpliceExecutor executor({.state_root = state_root});
    const auto request = MakeRequest();
    const auto workload_pod = MakeWorkloadPod();
    const auto proxy_pod = MakeProxyPod();
    const inline_proxy::CniInvocation invocation{
        .request = request,
        .container_id = "1234567890abcdef",
        .ifname = "eth0",
    };

    const auto result = executor.HandleAdd(invocation, workload_pod, proxy_pod);
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.stdout_json, R"({"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}]})");

    inline_proxy::StateStore store(executor.StatePathForContainerId(invocation.container_id));
    auto saved = store.Read();
    ASSERT_TRUE(saved.has_value());
    EXPECT_EQ(saved->at("container_id"), invocation.container_id);
    EXPECT_EQ(saved->at("wan_name"), "wan_12345678");
    EXPECT_EQ(saved->at("lan_name"), "lan_12345678");
    EXPECT_EQ(saved->at("prev_result"), R"({"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}]})");
    EXPECT_EQ(saved->at("proxy_name"), proxy_pod.name);

    EXPECT_TRUE(store.Remove());
    std::filesystem::remove_all(state_root, ec);
}

TEST(CniAddDelTest, ProxyPodAddDoesNotWriteState) {
    const auto state_root = std::filesystem::temp_directory_path() / "inline_proxy_cni_proxy_test";
    std::error_code ec;
    std::filesystem::remove_all(state_root, ec);

    inline_proxy::SpliceExecutor executor({.state_root = state_root});
    const auto request = MakeRequest();
    const auto proxy_pod = MakeProxyPod();
    const inline_proxy::CniInvocation invocation{
        .request = request,
        .container_id = "1234567890abcdef",
        .ifname = "eth0",
    };

    const auto result = executor.HandleAdd(invocation, proxy_pod, std::nullopt);
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.stdout_json, R"({"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}]})");
    EXPECT_FALSE(std::filesystem::exists(executor.StatePathForContainerId(invocation.container_id)));

    std::filesystem::remove_all(state_root, ec);
}

TEST(CniAddDelTest, UnannotatedAddPassesThroughWithoutState) {
    const auto state_root = std::filesystem::temp_directory_path() / "inline_proxy_cni_passthrough_test";
    std::error_code ec;
    std::filesystem::remove_all(state_root, ec);

    inline_proxy::SpliceExecutor executor({.state_root = state_root});
    const auto request = MakeRequest();
    const auto workload_pod = MakeUnannotatedWorkloadPod();
    const auto proxy_pod = MakeProxyPod();
    const inline_proxy::CniInvocation invocation{
        .request = request,
        .container_id = "1234567890abcdef",
        .ifname = "eth0",
    };

    const auto result = executor.HandleAdd(invocation, workload_pod, proxy_pod);
    ASSERT_TRUE(result.success);
    EXPECT_EQ(result.stdout_json, R"({"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}]})");
    EXPECT_FALSE(std::filesystem::exists(executor.StatePathForContainerId(invocation.container_id)));

    std::filesystem::remove_all(state_root, ec);
}

TEST(CniAddDelTest, DelRemovesSavedState) {
    const auto state_root = std::filesystem::temp_directory_path() / "inline_proxy_cni_del_test";
    std::error_code ec;
    std::filesystem::remove_all(state_root, ec);

    inline_proxy::SpliceExecutor executor({.state_root = state_root});
    const auto request = MakeRequest();
    const auto workload_pod = MakeWorkloadPod();
    const auto proxy_pod = MakeProxyPod();
    const inline_proxy::CniInvocation invocation{
        .request = request,
        .container_id = "1234567890abcdef",
        .ifname = "eth0",
    };

    ASSERT_TRUE(executor.HandleAdd(invocation, workload_pod, proxy_pod).success);
    EXPECT_TRUE(std::filesystem::exists(executor.StatePathForContainerId(invocation.container_id)));

    const auto del_result = executor.HandleDel(invocation);
    EXPECT_TRUE(del_result.success);
    EXPECT_FALSE(std::filesystem::exists(executor.StatePathForContainerId(invocation.container_id)));

    std::filesystem::remove_all(state_root, ec);
}
