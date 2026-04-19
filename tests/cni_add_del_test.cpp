#include <filesystem>
#include <optional>
#include <string>

#include <gtest/gtest.h>

#include "cni/splice_executor.hpp"
#include "cni/splice_plan.hpp"
#include "cni/k8s_client.hpp"
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

inline_proxy::PodInfo MakePendingProxyPod() {
    auto pod = MakeProxyPod();
    pod.phase = "Pending";
    pod.running = false;
    return pod;
}

inline_proxy::CniRequest MakeRequest() {
    const std::string json = R"({"cniVersion":"1.0.0","name":"k8s-pod-network","prevResult":{"dns":{"nameservers":["1.1.1.1"],"search":["svc.cluster.local"]},"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}],"routes":[{"dst":"10.0.0.0/8","gw":"10.42.0.1"}]}})";
    auto request = inline_proxy::ParseCniRequest(json);
    EXPECT_TRUE(request.has_value());
    return *request;
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
    EXPECT_EQ(result.stdout_json,
              R"({"dns":{"nameservers":["1.1.1.1"],"search":["svc.cluster.local"]},"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}],"routes":[{"dst":"10.0.0.0/8","gw":"10.42.0.1"}]})");

    inline_proxy::StateStore store(executor.StatePathForContainerId(invocation.container_id));
    auto saved = store.Read();
    ASSERT_TRUE(saved.has_value());
    EXPECT_EQ(saved->at("container_id"), invocation.container_id);
    EXPECT_EQ(saved->at("wan_name"), "wan_12345678");
    EXPECT_EQ(saved->at("lan_name"), "lan_12345678");
    EXPECT_EQ(saved->at("prev_result"),
              R"({"dns":{"nameservers":["1.1.1.1"],"search":["svc.cluster.local"]},"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}],"routes":[{"dst":"10.0.0.0/8","gw":"10.42.0.1"}]})");
    EXPECT_EQ(saved->at("proxy_name"), proxy_pod.name);

    EXPECT_TRUE(store.Remove());
    std::filesystem::remove_all(state_root, ec);
}

TEST(CniAddDelTest, SelectsNodeLocalProxyByLabelAndNodeName) {
    inline_proxy::SetK8sPodListResponseFetcherForTesting(
        [](const inline_proxy::K8sClientOptions&, const inline_proxy::K8sPodListQuery& query) {
            EXPECT_EQ(query.namespace_name, "inline-proxy-system");
            EXPECT_EQ(query.label_selector, "app=inline-proxy");
            return std::optional<std::string>(R"({
                "apiVersion":"v1",
                "kind":"PodList",
                "items":[
                    {
                        "metadata":{"name":"proxy-a","namespace":"inline-proxy-system","labels":{"app":"inline-proxy"}},
                        "spec":{"nodeName":"worker-2"},
                        "status":{"phase":"Running"}
                    },
                    {
                        "metadata":{"name":"proxy-b","namespace":"inline-proxy-system","labels":{"app":"inline-proxy"}},
                        "spec":{"nodeName":"worker-1"},
                        "status":{"phase":"Running"}
                    }
                ]
            })");
        });

    const auto proxy = inline_proxy::FindNodeLocalProxyPod("worker-1");
    ASSERT_TRUE(proxy.has_value());
    EXPECT_EQ(proxy->name, "proxy-b");
    EXPECT_EQ(proxy->node_name, "worker-1");

    inline_proxy::SetK8sPodListResponseFetcherForTesting({});
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
    EXPECT_EQ(result.stdout_json,
              R"({"dns":{"nameservers":["1.1.1.1"],"search":["svc.cluster.local"]},"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}],"routes":[{"dst":"10.0.0.0/8","gw":"10.42.0.1"}]})");
    EXPECT_FALSE(std::filesystem::exists(executor.StatePathForContainerId(invocation.container_id)));

    std::filesystem::remove_all(state_root, ec);
}

TEST(CniAddDelTest, ProxyPodAddDoesNotRequireRunningPhase) {
    const auto state_root = std::filesystem::temp_directory_path() / "inline_proxy_cni_proxy_pending_test";
    std::error_code ec;
    std::filesystem::remove_all(state_root, ec);

    inline_proxy::SpliceExecutor executor({.state_root = state_root});
    const auto request = MakeRequest();
    const auto proxy_pod = MakePendingProxyPod();
    const inline_proxy::CniInvocation invocation{
        .request = request,
        .container_id = "1234567890abcdef",
        .ifname = "eth0",
    };

    const auto result = executor.HandleAdd(invocation, proxy_pod, std::nullopt);
    ASSERT_TRUE(result.success);
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
    EXPECT_EQ(result.stdout_json,
              R"({"dns":{"nameservers":["1.1.1.1"],"search":["svc.cluster.local"]},"interfaces":[{"name":"eth0","sandbox":"/var/run/netns/test"}],"routes":[{"dst":"10.0.0.0/8","gw":"10.42.0.1"}]})");
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
