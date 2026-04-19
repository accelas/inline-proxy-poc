# Inline Proxy PoC Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a k3s-installable inline transparent proxy PoC that splices annotated Caddy backend pods through a per-node DaemonSet proxy using a chained CNI plugin written in C++ with yajl.

**Architecture:** Start from the `mango-template` Bazel skeleton, add a C++ shared Linux/network layer, implement a single-threaded proxy daemon with a small admin HTTP server, add an eBPF ingress steering path on `wan_*` interfaces, then implement the yajl-based chained CNI plugin that performs node-local pod splicing and cleanup. Finish with k3s deployment artifacts for the installer, proxy DaemonSet, RBAC, Caddy demo manifests, and demo verification docs.

**Tech Stack:** C++20, Bazel/Bzlmod, GoogleTest, yajl, eBPF/libbpf, Linux netns/netlink APIs, k3s manifests, Caddy.

---

### Task 1: Replace template scaffolding with project layout and dependencies

**Files:**
- Modify: `README.md`
- Modify: `MODULE.bazel`
- Modify: `BUILD.bazel`
- Modify: `src/BUILD.bazel`
- Modify: `tests/BUILD.bazel`
- Create: `src/shared/BUILD.bazel`
- Create: `src/proxy/BUILD.bazel`
- Create: `src/cni/BUILD.bazel`
- Create: `src/bpf/BUILD.bazel`
- Create: `deploy/README.md`
- Create: `third_party/yajl/BUILD.bazel`
- Create: `third_party/libbpf/BUILD.bazel`
- Test: `tests/project_layout_test.cpp`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include <filesystem>

TEST(ProjectLayoutTest, ExpectedDirectoriesExist) {
    EXPECT_TRUE(std::filesystem::exists("src/shared/BUILD.bazel"));
    EXPECT_TRUE(std::filesystem::exists("src/proxy/BUILD.bazel"));
    EXPECT_TRUE(std::filesystem::exists("src/cni/BUILD.bazel"));
    EXPECT_TRUE(std::filesystem::exists("src/bpf/BUILD.bazel"));
    EXPECT_TRUE(std::filesystem::exists("deploy/README.md"));
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:project_layout_test --test_output=errors`
Expected: FAIL because the new layout files do not exist yet.

**Step 3: Write minimal implementation**

Create the new BUILD files and placeholder packages, update `MODULE.bazel` to declare yajl/libbpf support, and replace template README text with project-specific content.

```starlark
# src/proxy/BUILD.bazel
cc_binary(
    name = "proxy_daemon",
    srcs = ["main.cpp"],
    deps = ["//src/shared:core"],
)
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:project_layout_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add README.md MODULE.bazel BUILD.bazel src/BUILD.bazel tests/BUILD.bazel src/shared/BUILD.bazel src/proxy/BUILD.bazel src/cni/BUILD.bazel src/bpf/BUILD.bazel deploy/README.md third_party/yajl/BUILD.bazel third_party/libbpf/BUILD.bazel tests/project_layout_test.cpp
git commit -m "build: establish inline proxy project layout"
```

### Task 2: Build the shared Linux/network support layer

**Files:**
- Create: `src/shared/scoped_fd.hpp`
- Create: `src/shared/scoped_fd.cpp`
- Create: `src/shared/sockaddr.hpp`
- Create: `src/shared/sockaddr.cpp`
- Create: `src/shared/netns.hpp`
- Create: `src/shared/netns.cpp`
- Create: `src/shared/netlink.hpp`
- Create: `src/shared/netlink.cpp`
- Create: `src/shared/state_store.hpp`
- Create: `src/shared/state_store.cpp`
- Modify: `src/shared/BUILD.bazel`
- Test: `tests/shared_linux_test.cpp`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include "shared/sockaddr.hpp"

TEST(SockaddrTest, FormatsIpv4Endpoint) {
    auto addr = inline_proxy::MakeSockaddr4("10.42.0.15", 8080);
    EXPECT_EQ(inline_proxy::FormatSockaddr(addr), "10.42.0.15:8080");
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:shared_linux_test --test_output=errors`
Expected: FAIL because the shared headers and functions do not exist.

**Step 3: Write minimal implementation**

Implement RAII fd management, IPv4 socket helpers, minimal netns enter/restore guards, netlink wrappers for veth/link operations, and JSON-backed state file helpers.

```cpp
namespace inline_proxy {
std::string FormatSockaddr(const sockaddr_storage& addr) {
    // Use inet_ntop + ntohs, return "ip:port"
}
}
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:shared_linux_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/shared/scoped_fd.* src/shared/sockaddr.* src/shared/netns.* src/shared/netlink.* src/shared/state_store.* src/shared/BUILD.bazel tests/shared_linux_test.cpp
git commit -m "feat: add shared linux networking primitives"
```

### Task 3: Port a minimal single-threaded event loop and admin HTTP server from `../http-endpoint`

**Files:**
- Create: `src/shared/event_loop.hpp`
- Create: `src/shared/event_loop.cpp`
- Create: `src/proxy/admin_http.hpp`
- Create: `src/proxy/admin_http.cpp`
- Create: `src/proxy/proxy_state.hpp`
- Create: `src/proxy/proxy_state.cpp`
- Modify: `src/proxy/BUILD.bazel`
- Test: `tests/admin_http_test.cpp`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include "proxy/admin_http.hpp"

TEST(AdminHttpTest, HealthAndReadinessEndpointsReturn200) {
    inline_proxy::ProxyState state;
    auto app = inline_proxy::BuildAdminHttp(state);
    EXPECT_EQ(app.Handle("GET", "/healthz").status, 200);
    EXPECT_EQ(app.Handle("GET", "/readyz").status, 200);
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:admin_http_test --test_output=errors`
Expected: FAIL because the admin HTTP surface does not exist.

**Step 3: Write minimal implementation**

Reuse only the event loop / fd watcher and lightweight HTTP routing concepts from `../http-endpoint`; do not port worker pool code. Add endpoints for `/healthz`, `/readyz`, `/metrics`, and `/sessions`.

```cpp
struct AdminResponse {
    int status;
    std::string content_type;
    std::string body;
};
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:admin_http_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/shared/event_loop.* src/proxy/admin_http.* src/proxy/proxy_state.* src/proxy/BUILD.bazel tests/admin_http_test.cpp
git commit -m "feat: add single-threaded admin HTTP server"
```

### Task 4: Implement transparent socket helpers and relay sessions

**Files:**
- Create: `src/proxy/transparent_socket.hpp`
- Create: `src/proxy/transparent_socket.cpp`
- Create: `src/proxy/relay_session.hpp`
- Create: `src/proxy/relay_session.cpp`
- Create: `src/proxy/transparent_listener.hpp`
- Create: `src/proxy/transparent_listener.cpp`
- Modify: `src/proxy/BUILD.bazel`
- Test: `tests/transparent_socket_test.cpp`
- Test: `tests/relay_session_test.cpp`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include "proxy/transparent_socket.hpp"

TEST(TransparentSocketTest, ListenerConfigEnablesIpTransparent) {
    auto listener = inline_proxy::CreateTransparentListener(127001, 15001);
    EXPECT_TRUE(listener.ok());
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:transparent_socket_test //tests:relay_session_test --test_output=errors`
Expected: FAIL because the transparent socket and relay code is missing.

**Step 3: Write minimal implementation**

Implement:
- listener creation on loopback with `IP_TRANSPARENT`
- accepted-socket helpers using `getpeername()` / `getsockname()`
- upstream transparent socket creation with `bind(original_src)` then `connect(original_dst)`
- bidirectional nonblocking relay under one event loop

```cpp
SessionEndpoints eps{
    .client = GetPeer(fd),
    .original_dst = GetSockName(fd),
};
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:transparent_socket_test //tests:relay_session_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/proxy/transparent_socket.* src/proxy/relay_session.* src/proxy/transparent_listener.* src/proxy/BUILD.bazel tests/transparent_socket_test.cpp tests/relay_session_test.cpp
git commit -m "feat: add transparent relay sessions"
```

### Task 5: Add a proxy daemon binary that ties admin, relay, and per-interface lifecycle together

**Files:**
- Create: `src/proxy/config.hpp`
- Create: `src/proxy/config.cpp`
- Create: `src/proxy/interface_registry.hpp`
- Create: `src/proxy/interface_registry.cpp`
- Create: `src/proxy/main.cpp`
- Modify: `src/proxy/BUILD.bazel`
- Test: `tests/proxy_daemon_config_test.cpp`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include "proxy/config.hpp"

TEST(ProxyConfigTest, ParsesDefaultAdminAndTransparentPorts) {
    auto cfg = inline_proxy::ProxyConfig::FromEnv({});
    EXPECT_EQ(cfg.admin_port, 8080);
    EXPECT_EQ(cfg.transparent_port, 15001);
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:proxy_daemon_config_test --test_output=errors`
Expected: FAIL because the proxy daemon config and main binary are missing.

**Step 3: Write minimal implementation**

Wire the event loop, admin server, transparent listener, and session state into a single-threaded `proxy_daemon` process. The interface registry should track `wan_*` / `lan_*` names and session counters for admin output.

```cpp
int main(int argc, char** argv) {
    inline_proxy::ProxyConfig cfg = inline_proxy::ProxyConfig::FromEnv(argc, argv);
    return inline_proxy::RunProxyDaemon(cfg);
}
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:proxy_daemon_config_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/proxy/config.* src/proxy/interface_registry.* src/proxy/main.cpp src/proxy/BUILD.bazel tests/proxy_daemon_config_test.cpp
git commit -m "feat: assemble proxy daemon binary"
```

### Task 6: Add the eBPF ingress steering program and loader glue

**Files:**
- Create: `src/bpf/ingress_redirect.bpf.c`
- Create: `src/bpf/loader.hpp`
- Create: `src/bpf/loader.cpp`
- Modify: `src/bpf/BUILD.bazel`
- Modify: `src/proxy/interface_registry.cpp`
- Modify: `src/proxy/BUILD.bazel`
- Test: `tests/bpf_loader_test.cpp`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include "bpf/loader.hpp"

TEST(BpfLoaderTest, RejectsMissingInterfaceName) {
    inline_proxy::BpfLoader loader;
    EXPECT_FALSE(loader.AttachIngress(""));
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:bpf_loader_test --test_output=errors`
Expected: FAIL because the loader and BPF program do not exist.

**Step 3: Write minimal implementation**

Create a minimal ingress eBPF program and userspace loader. The first pass only needs:
- per-interface attach/detach
- listener socket handoff configuration
- enough structure to steer eligible TCP traffic on `wan_*`

```c
SEC("tc")
int redirect_ingress(struct __sk_buff* skb) {
    // lookup listener socket / config, then steer TCP traffic
}
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:bpf_loader_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/bpf/ingress_redirect.bpf.c src/bpf/loader.* src/bpf/BUILD.bazel src/proxy/interface_registry.cpp src/proxy/BUILD.bazel tests/bpf_loader_test.cpp
git commit -m "feat: add bpf ingress steering"
```

### Task 7: Implement yajl-based CNI request parsing and Kubernetes pod lookup

**Files:**
- Create: `src/cni/cni_types.hpp`
- Create: `src/cni/cni_types.cpp`
- Create: `src/cni/yajl_parser.hpp`
- Create: `src/cni/yajl_parser.cpp`
- Create: `src/cni/k8s_client.hpp`
- Create: `src/cni/k8s_client.cpp`
- Modify: `src/cni/BUILD.bazel`
- Test: `tests/cni_yajl_parser_test.cpp`
- Test: `tests/k8s_client_test.cpp`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include "cni/yajl_parser.hpp"

TEST(CniYajlParserTest, ParsesAnnotatedPodAddRequest) {
    std::string json = R"({"cniVersion":"1.0.0","name":"k8s-pod-network","prevResult":{"interfaces":[]}})";
    auto req = inline_proxy::ParseCniRequest(json);
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->cni_version, "1.0.0");
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:cni_yajl_parser_test //tests:k8s_client_test --test_output=errors`
Expected: FAIL because the yajl parser and Kubernetes client do not exist.

**Step 3: Write minimal implementation**

Use yajl only in the CNI plugin for:
- request parsing
- extracting `prevResult` data needed for splice state
- serializing/deserializing plugin state files if helpful

Add a simple Kubernetes REST client for pod lookup using the in-cluster token/CA files.

```cpp
std::optional<CniRequest> ParseCniRequest(std::string_view json);
PodInfo FetchPodInfo(const K8sQuery& query);
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:cni_yajl_parser_test //tests:k8s_client_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/cni/cni_types.* src/cni/yajl_parser.* src/cni/k8s_client.* src/cni/BUILD.bazel tests/cni_yajl_parser_test.cpp tests/k8s_client_test.cpp
git commit -m "feat: add yajl-based cni request parsing"
```

### Task 8: Implement splice orchestration and CNI ADD/DEL handling

**Files:**
- Create: `src/cni/splice_plan.hpp`
- Create: `src/cni/splice_plan.cpp`
- Create: `src/cni/splice_executor.hpp`
- Create: `src/cni/splice_executor.cpp`
- Create: `src/cni/main.cpp`
- Modify: `src/cni/BUILD.bazel`
- Modify: `src/shared/state_store.cpp`
- Test: `tests/splice_plan_test.cpp`
- Test: `tests/cni_add_del_test.cpp`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include "cni/splice_plan.hpp"

TEST(SplicePlanTest, CreatesWanAndLanNamesFromContainerId) {
    auto plan = inline_proxy::BuildSplicePlan("1234567890abcdef", "eth0");
    EXPECT_EQ(plan.wan_name, "wan_12345678");
    EXPECT_EQ(plan.lan_name, "lan_12345678");
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:splice_plan_test //tests:cni_add_del_test --test_output=errors`
Expected: FAIL because the splice planner/executor and CNI main entrypoint do not exist.

**Step 3: Write minimal implementation**

Implement:
- proxy-pod role handling
- annotated-pod splice planning
- node-local proxy lookup by label + `spec.nodeName`
- ADD/DEL execution with saved state in `/var/run/inline-proxy-cni/`
- CNI stdout passthrough using the original `prevResult`

```cpp
if (pod_info.is_proxy_pod) return HandleProxyPod(req, env);
if (!pod_info.annotation_enabled) return PassThrough(req);
return ExecuteSplice(req, pod_info, proxy_info);
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:splice_plan_test //tests:cni_add_del_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add src/cni/splice_plan.* src/cni/splice_executor.* src/cni/main.cpp src/cni/BUILD.bazel src/shared/state_store.cpp tests/splice_plan_test.cpp tests/cni_add_del_test.cpp
git commit -m "feat: add chained cni splice handling"
```

### Task 9: Add namespace-based integration tests for transparent relay and splice behavior

**Files:**
- Create: `tests/netns_fixture.hpp`
- Create: `tests/netns_fixture.cpp`
- Create: `tests/transparent_relay_netns_test.cpp`
- Create: `tests/splice_executor_netns_test.cpp`
- Modify: `tests/BUILD.bazel`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include "tests/netns_fixture.hpp"

TEST(TransparentRelayNetnsTest, PreservesOriginalEndpointsAcrossRelay) {
    auto env = inline_proxy::NetnsFixture::Create();
    ASSERT_TRUE(env.has_value());
    EXPECT_TRUE(env->RunTransparentRelayScenario());
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:transparent_relay_netns_test //tests:splice_executor_netns_test --test_output=errors`
Expected: FAIL because the netns fixture and integration helpers do not exist.

**Step 3: Write minimal implementation**

Create Linux-only integration fixtures that:
- create temporary netns/veth setups
- run the proxy listener in a controlled test loop
- verify original endpoint reconstruction and relay correctness
- verify splice execution leaves the app pod with working replacement `eth0`

```cpp
if (!CanCreateNetns()) GTEST_SKIP() << "Requires CAP_NET_ADMIN";
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:transparent_relay_netns_test //tests:splice_executor_netns_test --test_output=errors`
Expected: PASS on a host with `CAP_NET_ADMIN`; otherwise SKIP with a clear reason.

**Step 5: Commit**

```bash
git add tests/netns_fixture.* tests/transparent_relay_netns_test.cpp tests/splice_executor_netns_test.cpp tests/BUILD.bazel
git commit -m "test: add netns integration coverage"
```

### Task 10: Package k3s deployment artifacts, Caddy demo, and operator runbook

**Files:**
- Create: `deploy/base/namespace.yaml`
- Create: `deploy/base/rbac.yaml`
- Create: `deploy/base/proxy-daemonset.yaml`
- Create: `deploy/base/proxy-installer-daemonset.yaml`
- Create: `deploy/base/caddy-demo.yaml`
- Create: `deploy/base/client-demo.yaml`
- Create: `deploy/base/kustomization.yaml`
- Create: `deploy/scripts/install-cni.sh`
- Create: `deploy/scripts/reconcile-cni.sh`
- Modify: `deploy/README.md`
- Modify: `README.md`
- Test: `tests/deploy_manifest_test.cpp`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include <filesystem>

TEST(DeployManifestTest, KustomizationAndCoreManifestsExist) {
    EXPECT_TRUE(std::filesystem::exists("deploy/base/kustomization.yaml"));
    EXPECT_TRUE(std::filesystem::exists("deploy/base/proxy-daemonset.yaml"));
    EXPECT_TRUE(std::filesystem::exists("deploy/base/caddy-demo.yaml"));
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:deploy_manifest_test --test_output=errors`
Expected: FAIL because the deployment manifests do not exist yet.

**Step 3: Write minimal implementation**

Add k3s-ready manifests with clearly productizable names such as `inline-proxy-*`. The installer scripts should patch/reconcile the active CNI conflist and install the `inline-proxy-cni` binary on each node.

```yaml
metadata:
  name: inline-proxy-daemon
  namespace: inline-proxy-system
```

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:deploy_manifest_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add deploy/base/*.yaml deploy/scripts/*.sh deploy/README.md README.md tests/deploy_manifest_test.cpp
git commit -m "deploy: add k3s manifests and demo runbook"
```

### Task 11: Final verification pass before demoing

**Files:**
- Modify: `README.md`
- Modify: `deploy/README.md`
- Modify: `docs/plans/2026-04-18-inline-proxy-poc.md`

**Step 1: Write the failing verification checklist**

```md
- [ ] `bazel test //...` passes
- [ ] `bazel build //src/proxy:proxy_daemon //src/cni:inline_proxy_cni //src/bpf:loader` passes
- [ ] deployment docs describe same-node and cross-node validation
```

**Step 2: Run verification to expose any failures**

Run: `bazel test //... --test_output=errors`
Expected: Any remaining failures are fixed before claiming completion.

**Step 3: Write minimal fixes and doc updates**

Only fix what verification proves is broken. Update docs with exact demo commands, including annotated vs unannotated Caddy behavior and proxy admin endpoints.

```md
kubectl get pods -n inline-proxy-system -o wide
kubectl logs -n inline-proxy-system ds/inline-proxy-daemon
```

**Step 4: Run final verification**

Run:
- `bazel test //... --test_output=errors`
- `bazel build //src/proxy:proxy_daemon //src/cni:inline_proxy_cni //src/bpf:loader`
Expected: PASS.

**Step 5: Commit**

```bash
git add README.md deploy/README.md docs/plans/2026-04-18-inline-proxy-poc.md
git commit -m "docs: finalize demo verification guidance"
```

## Verification status

- [x] `bazel test //... --test_output=errors` passes
- [x] `bazel build //src/proxy:proxy_daemon //src/cni:inline_proxy_cni //src/bpf:loader` passes
- [x] deployment docs describe same-node and cross-node validation
