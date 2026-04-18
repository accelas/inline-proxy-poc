# Task 7: CNI yajl Parsing and Kubernetes Pod Lookup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add typed CNI request parsing with yajl and a small in-cluster Kubernetes pod lookup client for later splice planning.

**Architecture:** Parse the CNI request JSON into a minimal typed model that preserves the fields needed for future splice state, including `cniVersion` and `prevResult`. Keep the Kubernetes client narrowly scoped to in-cluster service-account-based HTTPS GET requests for pod lookup, returning only the pod fields needed for node-local proxy discovery.

**Tech Stack:** C++20, Bazel/Bzlmod, GoogleTest, yajl, OpenSSL, Kubernetes in-cluster service account auth.

---

### Task 1: Add the CNI typed request model and parser test

**Files:**
- Create: `tests/cni_yajl_parser_test.cpp`
- Modify: `tests/BUILD.bazel`

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

Run: `bazel test //tests:cni_yajl_parser_test --test_output=errors`
Expected: FAIL because the parser and CNI types do not exist.

**Step 3: Write minimal implementation**

Define a minimal `CniRequest` model and a yajl-based parser that extracts `cniVersion` and preserves `prevResult`.

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:cni_yajl_parser_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/cni_yajl_parser_test.cpp tests/BUILD.bazel src/cni/cni_types.* src/cni/yajl_parser.* src/cni/BUILD.bazel
git commit -m "feat: add yajl-based cni request parsing"
```

### Task 2: Add the Kubernetes pod lookup client test

**Files:**
- Create: `tests/k8s_client_test.cpp`
- Modify: `tests/BUILD.bazel`

**Step 1: Write the failing test**

```cpp
#include <gtest/gtest.h>
#include "cni/k8s_client.hpp"

TEST(K8sClientTest, ParsesPodLookupResponse) {
    // test response parsing / lookup behavior
}
```

**Step 2: Run test to verify it fails**

Run: `bazel test //tests:k8s_client_test --test_output=errors`
Expected: FAIL because the Kubernetes client does not exist.

**Step 3: Write minimal implementation**

Implement an in-cluster HTTPS client that reads the service-account token and CA bundle, performs a GET against the pod API, and returns a minimal `PodInfo`.

**Step 4: Run test to verify it passes**

Run: `bazel test //tests:k8s_client_test --test_output=errors`
Expected: PASS.

**Step 5: Commit**

```bash
git add tests/k8s_client_test.cpp src/cni/k8s_client.* src/cni/BUILD.bazel
git commit -m "feat: add in-cluster kubernetes pod lookup client"
```
