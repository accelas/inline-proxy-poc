# CNI-side splice reconciler — implementation plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When kubelet calls CNI ADD for a new proxy daemon DS pod after the previous one was replaced, walk the on-disk container state files and re-splice every workload pod that points at a now-dead proxy netns into the new one — bounded by a 30-second deadline.

**Architecture:** The repair fires from `SpliceExecutor::HandleAdd`'s existing `IsProxyPod` branch in the CNI plugin (which runs as a host process in root netns). After `proxy_pod_pinner` succeeds, a new `RepairOrphanedSplices` walks `${state_root}/container-*.json`, compares each recorded `proxy_netns_path` inode to the new daemon's netns, and re-invokes `executor.HandleAdd` on stale entries. Per-pod failures and budget exhaustion are logged and counted; the daemon's CNI ADD never fails on repair errors.

**Tech Stack:** C++23, GoogleTest, Bazel, libbpf, Linux netlink (via existing CNI helpers).

**Spec:** [docs/superpowers/specs/2026-04-30-cni-side-splice-reconciler-design.md](../specs/2026-04-30-cni-side-splice-reconciler-design.md)

---

## File map

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `src/cni/splice_executor.hpp` | Add public `options()` accessor |
| Create | `src/cni/splice_repair.hpp` | Public reconciler API (with deadline parameter) |
| Create | `src/cni/splice_repair.cpp` | Walk state files, fabricate inputs, call HandleAdd, count outcomes, enforce deadline |
| Modify | `src/cni/BUILD.bazel` | Add splice_repair files to `cni_splice` cc_library |
| Modify | `src/cni/splice_executor.cpp` | Insert `RepairOrphanedSplices` call inside the `IsProxyPod` branch |
| Create | `tests/splice_repair_test.cpp` | Unit tests using `splice_runner`-stubbed executor |
| Modify | `tests/BUILD.bazel` | Register `splice_repair_test` and `splice_repair_netns_test` |
| Modify | `tests/cni_add_del_test.cpp` | Add IsProxyPod-triggers-repair test |
| Modify | `tests/netns_fixture.{hpp,cpp}` | Add `RunSpliceRepairScenario()` |
| Create | `tests/splice_repair_netns_test.cpp` | Root-gated gtest wrapper |

---

## Reusable assets from the unmerged `feature/splice-reconciler` branch

The unmerged branch (worktree at `/home/kai/work/k8s/.worktrees/splice-reconciler`) contains tested-but-not-architecturally-correct code that ports directly to this work:

| Asset | Source on unmerged branch | Action |
|-------|---------------------------|--------|
| `RepairOrphanedSplices` body | `src/proxy/splice_repair.cpp` | Copy → `src/cni/splice_repair.cpp`; change `proxy/splice_repair.hpp` include to `cni/splice_repair.hpp`; add deadline param |
| `SpliceRepairResult` struct + decl | `src/proxy/splice_repair.hpp` | Copy → `src/cni/splice_repair.hpp`; add `skipped_deadline_exceeded` field; add deadline parameter to function decl |
| Six unit tests | `tests/splice_repair_test.cpp` | Copy verbatim; only `#include`s change |
| `NetnsFixture::RunSpliceRepairScenario` | `tests/netns_fixture.{hpp,cpp}` | Copy verbatim — the scenario is netns-context-agnostic |
| `tests/splice_repair_netns_test.cpp` | identical name on unmerged branch | Copy verbatim |

Use `git show splice-reconciler:<path>` from this worktree to read the unmerged source when needed (`splice-reconciler` is the branch name).

---

## Chunk 1: Foundation — accessor + library skeleton + hookup

### Task 1: Expose `SpliceExecutor::options()` accessor

**Files:**
- Modify: `src/cni/splice_executor.hpp` (in `class SpliceExecutor`'s public section)

`RepairOrphanedSplices` needs `executor.options().state_root` to know which directory to walk. The struct field is private today.

- [ ] **Step 1.1: Add the accessor**

In `src/cni/splice_executor.hpp`, inside `class SpliceExecutor`'s public section, immediately after the `HandleDel` declaration (currently around line 69), add:

```cpp
const CniExecutionOptions& options() const { return options_; }
```

- [ ] **Step 1.2: Verify compile**

```
bazel build //src/cni:cni_splice
```

Expected: `Build completed successfully`.

- [ ] **Step 1.3: Commit**

```
git add src/cni/splice_executor.hpp
git commit -m "SpliceExecutor: expose options() accessor for reconciler"
```

---

### Task 2: Create `splice_repair` library skeleton

**Files:**
- Create: `src/cni/splice_repair.hpp` (public API, including deadline parameter and `skipped_deadline_exceeded` counter)
- Create: `src/cni/splice_repair.cpp` (skeleton returning `SpliceRepairResult{}`)
- Modify: `src/cni/BUILD.bazel`

The implementation in `splice_repair.cpp` will be filled in via TDD in Chunk 2. This task only sets up the surface area and Bazel wiring.

- [ ] **Step 2.1: Create the header**

Write `src/cni/splice_repair.hpp`:

```cpp
#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>

#include "cni/splice_executor.hpp"

namespace inline_proxy {

struct SpliceRepairResult {
    std::size_t total_state_files = 0;
    std::size_t skipped_intact = 0;
    std::size_t skipped_workload_gone = 0;
    std::size_t skipped_deadline_exceeded = 0;
    std::size_t repaired = 0;
    std::size_t failed = 0;
};

// Walk every container-*.json in `executor.options().state_root`. For each,
// compare the recorded `proxy_netns_path` inode to `current_proxy_netns`'s
// inode; if they differ, fabricate a CniInvocation + PodInfo pair from the
// state file fields and call `executor.HandleAdd` to re-splice the workload
// into `current_proxy_netns`. Per-pod failures are logged to std::cerr and
// counted in `failed`; they do not abort the scan.
//
// At the top of each per-state-file iteration, the wall-clock deadline is
// re-evaluated. Once exceeded, remaining files bump
// `skipped_deadline_exceeded` and the function returns. Default budget is
// 30 seconds — well under kubelet's CNI ADD timeout.
SpliceRepairResult RepairOrphanedSplices(
    const SpliceExecutor& executor,
    std::filesystem::path current_proxy_netns,
    std::chrono::steady_clock::duration deadline = std::chrono::seconds(30));

}  // namespace inline_proxy
```

- [ ] **Step 2.2: Create the implementation skeleton**

Write `src/cni/splice_repair.cpp`:

```cpp
#include "cni/splice_repair.hpp"

namespace inline_proxy {

SpliceRepairResult RepairOrphanedSplices(const SpliceExecutor& /*executor*/,
                                         std::filesystem::path /*current_proxy_netns*/,
                                         std::chrono::steady_clock::duration /*deadline*/) {
    return SpliceRepairResult{};
}

}  // namespace inline_proxy
```

- [ ] **Step 2.3: Add to `src/cni/BUILD.bazel`**

In `src/cni/BUILD.bazel`, find the existing `cc_library(name = "cni_splice", ...)` block. Add `"splice_repair.cpp"` to its `srcs` list and `"splice_repair.hpp"` to its `hdrs` list. Do NOT add new `deps` — the existing deps already cover everything `splice_repair.cpp` will need (per the spec's BUILD-wiring section: `cni_parser`, `cni_types`, `k8s_client`, `//src/shared:shared`).

- [ ] **Step 2.4: Build**

```
bazel build //src/cni:cni_splice //src/cni:inline_proxy_cni
```

Expected: `Build completed successfully`.

- [ ] **Step 2.5: Commit**

```
git add src/cni/splice_repair.hpp src/cni/splice_repair.cpp src/cni/BUILD.bazel
git commit -m "CNI: add splice_repair library skeleton with deadline param"
```

---

## Chunk 2: Driver TDD

### Task 3: Register test target + empty-dir baseline

**Files:**
- Create: `tests/splice_repair_test.cpp`
- Modify: `tests/BUILD.bazel`

The unit tests use `splice_runner` injection — a callback set on `CniExecutionOptions::splice_runner` that bypasses the real netlink work. They only verify the reconciler's per-state-file decisions: which files trigger `HandleAdd`, with what arguments, and how the counters increment.

- [ ] **Step 3.1: Register the cc_test**

Append to `tests/BUILD.bazel`:

```python
cc_test(
    name = "splice_repair_test",
    srcs = ["splice_repair_test.cpp"],
    deps = [
        "@googletest//:gtest_main",
        "//src/cni:cni_parser",
        "//src/cni:cni_splice",
        "//src/shared:shared",
    ],
)
```

- [ ] **Step 3.2: Create the test file with two baseline tests (existing dir + nonexistent dir)**

Write `tests/splice_repair_test.cpp`:

```cpp
#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "cni/splice_executor.hpp"
#include "cni/splice_repair.hpp"
#include "shared/state_store.hpp"

namespace fs = std::filesystem;

namespace {

class SpliceRepairTest : public ::testing::Test {
protected:
    void SetUp() override {
        state_root_ = fs::temp_directory_path() /
            ("splice-repair-test-" + std::to_string(::getpid()) + "-" +
             std::to_string(reinterpret_cast<std::uintptr_t>(this)));
        fs::create_directories(state_root_);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(state_root_, ec);
    }

    fs::path state_root_;
};

}  // namespace

TEST_F(SpliceRepairTest, EmptyStateRootProducesZeroCounts) {
    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [](const auto&, const auto&, const auto&) { return true; };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, "/proc/self/ns/net");
    EXPECT_EQ(result.total_state_files, 0u);
    EXPECT_EQ(result.skipped_intact, 0u);
    EXPECT_EQ(result.skipped_workload_gone, 0u);
    EXPECT_EQ(result.skipped_deadline_exceeded, 0u);
    EXPECT_EQ(result.repaired, 0u);
    EXPECT_EQ(result.failed, 0u);
}

TEST_F(SpliceRepairTest, NonexistentStateRootProducesZeroCounts) {
    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_ / "does-not-exist";
    options.splice_runner = [](const auto&, const auto&, const auto&) { return true; };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, "/proc/self/ns/net");
    EXPECT_EQ(result.total_state_files, 0u);
    EXPECT_EQ(result.failed, 0u);
}
```

- [ ] **Step 3.3: Run — expect PASS**

```
bazel test //tests:splice_repair_test --test_output=errors
```

Expected: 2 PASS. (Skeleton returns `{}` so both pass trivially.)

- [ ] **Step 3.4: Commit**

```
git add tests/splice_repair_test.cpp tests/BUILD.bazel
git commit -m "Test: add splice_repair_test scaffolding with baseline tests"
```

---

### Task 4: Test "skipped_intact" + dir-walk + inode compare

**Files:**
- Modify: `tests/splice_repair_test.cpp` (helpers + one test)
- Modify: `src/cni/splice_repair.cpp` (replace skeleton with real walk)

- [ ] **Step 4.1: Add fixture helpers**

In the anonymous namespace of `tests/splice_repair_test.cpp` (after the `SpliceRepairTest` class), add:

```cpp
inline std::string MakePrevResultJson(std::string_view sandbox) {
    std::string s;
    s.reserve(160 + sandbox.size());
    s += R"({"interfaces":[{"name":"eth0","sandbox":")";
    s += sandbox;
    s += R"("}],"ips":[{"address":"10.42.0.10/24","gateway":"10.42.0.1","interface":0}],"routes":[{"dst":"0.0.0.0/0","gw":"10.42.0.1"}]})";
    return s;
}

inline void WriteStateFile(const fs::path& dir,
                           std::string_view container_id,
                           std::string_view workload_netns_path,
                           std::string_view proxy_netns_path) {
    inline_proxy::StateStore store(dir / ("container-" + std::string(container_id) + ".json"));
    inline_proxy::StateFields fields = {
        {"container_id", std::string(container_id)},
        {"ifname", "eth0"},
        {"pod_name", "caddy-1"},
        {"pod_namespace", "default"},
        {"prev_result", MakePrevResultJson(workload_netns_path)},
        {"proxy_netns_path", std::string(proxy_netns_path)},
        {"proxy_name", "inline-proxy-daemon-x"},
        {"proxy_namespace", "inline-proxy-system"},
        {"proxy_node_name", "worker-1"},
        {"workload_netns_path", std::string(workload_netns_path)},
    };
    ASSERT_TRUE(store.Write(fields));
}
```

- [ ] **Step 4.2: Append the test**

```cpp
TEST_F(SpliceRepairTest, MatchingProxyInodeIsSkippedIntact) {
    const auto netns_path = state_root_ / "fake-netns";
    std::ofstream(netns_path).put('x');

    const auto workload_path = state_root_ / "fake-workload-netns";
    std::ofstream(workload_path).put('x');

    WriteStateFile(state_root_, "abc", workload_path.string(), netns_path.string());

    bool runner_called = false;
    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [&](const auto&, const auto&, const auto&) {
        runner_called = true;
        return true;
    };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, netns_path);
    EXPECT_EQ(result.total_state_files, 1u);
    EXPECT_EQ(result.skipped_intact, 1u);
    EXPECT_EQ(result.repaired, 0u);
    EXPECT_FALSE(runner_called);
}
```

- [ ] **Step 4.3: Run — expect FAIL**

```
bazel test //tests:splice_repair_test --test_output=errors
```

Expected: failure on `total_state_files == 1` (skeleton returns zeroes).

- [ ] **Step 4.4: Replace skeleton body**

Replace `src/cni/splice_repair.cpp` entirely with:

```cpp
#include "cni/splice_repair.hpp"

#include <sys/stat.h>

#include <chrono>
#include <iostream>
#include <string>
#include <system_error>

#include "shared/state_store.hpp"

namespace inline_proxy {

namespace {

struct InodeId {
    dev_t dev;
    ino_t ino;
};

std::optional<InodeId> StatInode(const std::filesystem::path& p) {
    struct ::stat st {};
    if (::stat(p.c_str(), &st) != 0) {
        return std::nullopt;
    }
    return InodeId{st.st_dev, st.st_ino};
}

bool SameInode(const InodeId& a, const InodeId& b) {
    return a.dev == b.dev && a.ino == b.ino;
}

}  // namespace

SpliceRepairResult RepairOrphanedSplices(const SpliceExecutor& executor,
                                         std::filesystem::path current_proxy_netns,
                                         std::chrono::steady_clock::duration deadline) {
    SpliceRepairResult result;
    const auto& state_root = executor.options().state_root;

    std::error_code ec;
    if (!std::filesystem::exists(state_root, ec)) {
        return result;
    }

    const auto current_inode = StatInode(current_proxy_netns);
    if (!current_inode.has_value()) {
        std::cerr << "splice-repair: warning: cannot stat current proxy netns "
                  << current_proxy_netns
                  << "; intact-check disabled, all state files will be re-evaluated\n";
    }

    std::filesystem::directory_iterator dir_it(state_root, ec);
    if (ec) {
        std::cerr << "splice-repair: failed to open state dir " << state_root
                  << ": " << ec.message() << "\n";
        return result;
    }

    const auto deadline_at = std::chrono::steady_clock::now() + deadline;

    for (const auto& entry : dir_it) {
        const auto path = entry.path();
        if (path.filename().string().rfind("container-", 0) != 0) {
            continue;
        }
        if (path.extension() != ".json") {
            continue;
        }
        ++result.total_state_files;

        if (std::chrono::steady_clock::now() >= deadline_at) {
            ++result.skipped_deadline_exceeded;
            continue;
        }

        StateStore store(path);
        const auto fields_opt = store.Read();
        if (!fields_opt) {
            std::cerr << "splice-repair: parse failed for " << path << "\n";
            ++result.failed;
            continue;
        }
        const auto& fields = *fields_opt;
        const auto get = [&](const std::string& key) -> std::string {
            const auto it = fields.find(key);
            return it == fields.end() ? std::string{} : it->second;
        };

        const auto recorded_proxy = get("proxy_netns_path");
        if (current_inode.has_value()) {
            const auto recorded_inode = StatInode(recorded_proxy);
            if (recorded_inode.has_value() && SameInode(*recorded_inode, *current_inode)) {
                ++result.skipped_intact;
                continue;
            }
        }

        // Tasks 5-7 will add: workload-gone check, fabricate Pods + invocation, call HandleAdd.
        ++result.failed;
        std::cerr << "splice-repair: not yet implemented for " << path << "\n";
    }

    return result;
}

}  // namespace inline_proxy
```

- [ ] **Step 4.5: Run — expect PASS**

```
bazel test //tests:splice_repair_test --test_output=errors
```

Expected: 3 PASS.

- [ ] **Step 4.6: Commit**

```
git add src/cni/splice_repair.cpp tests/splice_repair_test.cpp
git commit -m "splice_repair: walk state dir + skip intact splices"
```

---

### Task 5: Test "skipped_workload_gone"

- [ ] **Step 5.1: Append the test**

In `tests/splice_repair_test.cpp`:

```cpp
TEST_F(SpliceRepairTest, MissingWorkloadNetnsIsSkippedAsGone) {
    const auto current_path = state_root_ / "current";
    std::ofstream(current_path).put('x');
    const auto stale_proxy = state_root_ / "stale-proxy";
    std::ofstream(stale_proxy).put('y');

    WriteStateFile(state_root_, "wlgone",
                   /*workload_netns_path=*/(state_root_ / "definitely-missing").string(),
                   stale_proxy.string());

    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [](const auto&, const auto&, const auto&) { return true; };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, current_path);
    EXPECT_EQ(result.total_state_files, 1u);
    EXPECT_EQ(result.skipped_workload_gone, 1u);
    EXPECT_EQ(result.skipped_intact, 0u);
    EXPECT_EQ(result.repaired, 0u);
    EXPECT_EQ(result.failed, 0u);
}
```

- [ ] **Step 5.2: Run — expect FAIL**

Current implementation increments `failed`.

- [ ] **Step 5.3: Implement workload-gone check**

In `src/cni/splice_repair.cpp`, just below the `skipped_intact` block (right before the placeholder `++result.failed;` line), add:

```cpp
        const auto workload_path = get("workload_netns_path");
        if (workload_path.empty() ||
            !std::filesystem::exists(workload_path, ec)) {
            ++result.skipped_workload_gone;
            continue;
        }
```

- [ ] **Step 5.4: Run — expect PASS**

- [ ] **Step 5.5: Commit**

```
git add src/cni/splice_repair.cpp tests/splice_repair_test.cpp
git commit -m "splice_repair: skip files whose workload netns is gone"
```

---

### Task 6: Test "repaired" — fully implement HandleAdd invocation

This is the largest task — adds the per-orphan repair loop body.

- [ ] **Step 6.1: Append the test**

In `tests/splice_repair_test.cpp`:

```cpp
TEST_F(SpliceRepairTest, OrphanedFileTriggersHandleAddWithCurrentNetns) {
    const auto current_path = state_root_ / "current-proxy";
    std::ofstream(current_path).put('c');
    const auto stale_proxy = state_root_ / "stale-proxy";
    std::ofstream(stale_proxy).put('s');
    const auto workload_path = state_root_ / "workload";
    std::ofstream(workload_path).put('w');

    WriteStateFile(state_root_, "orph", workload_path.string(), stale_proxy.string());

    bool called = false;
    std::filesystem::path observed_workload, observed_proxy;
    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [&](const inline_proxy::SplicePlan&,
                                const std::filesystem::path& wl,
                                const std::filesystem::path& px) {
        called = true;
        observed_workload = wl;
        observed_proxy = px;
        return true;
    };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, current_path);
    EXPECT_EQ(result.total_state_files, 1u);
    EXPECT_EQ(result.repaired, 1u);
    EXPECT_EQ(result.failed, 0u);
    EXPECT_EQ(result.skipped_intact, 0u);
    EXPECT_TRUE(called);
    EXPECT_EQ(observed_workload, workload_path);
    EXPECT_EQ(observed_proxy, current_path);
}
```

- [ ] **Step 6.2: Run — expect FAIL**

- [ ] **Step 6.3: Add includes + replace placeholder block**

In `src/cni/splice_repair.cpp`:

Add includes (after the existing ones):

```cpp
#include "cni/cni_types.hpp"
#include "cni/k8s_client.hpp"  // for PodInfo
#include "cni/yajl_parser.hpp"
```

Replace the placeholder block (the `++result.failed; std::cerr << "...not yet implemented..."`) with:

```cpp
        const auto pod_name = get("pod_name");
        const auto pod_namespace = get("pod_namespace");
        const auto proxy_name = get("proxy_name");
        const auto proxy_namespace = get("proxy_namespace");
        const auto proxy_node_name = get("proxy_node_name");
        const auto container_id = get("container_id");
        const auto ifname = get("ifname");
        const auto prev_result_raw = get("prev_result");
        if (container_id.empty() || ifname.empty() ||
            prev_result_raw.empty() || proxy_node_name.empty()) {
            std::cerr << "splice-repair: incomplete state file " << path << "\n";
            ++result.failed;
            continue;
        }

        // HandleDel uses the same wrap-and-parse recipe at splice_executor.cpp:404-406.
        const std::string envelope =
            R"({"cniVersion":"1.0.0","name":"restore","prevResult":)" +
            prev_result_raw + "}";
        auto request_opt = ParseCniRequest(envelope);
        if (!request_opt) {
            std::cerr << "splice-repair: malformed prev_result in " << path << "\n";
            ++result.failed;
            continue;
        }

        PodInfo workload_pod;
        workload_pod.name = pod_name;
        workload_pod.namespace_name = pod_namespace;
        workload_pod.node_name = proxy_node_name;
        workload_pod.running = true;
        workload_pod.annotations["inline-proxy.example.com/enabled"] = "true";

        PodInfo proxy_pod;
        proxy_pod.name = proxy_name;
        proxy_pod.namespace_name =
            proxy_namespace.empty() ? "inline-proxy-system" : proxy_namespace;
        proxy_pod.node_name = proxy_node_name;
        proxy_pod.running = true;
        proxy_pod.labels["app"] = "inline-proxy";

        // Per-call executor copy with proxy_netns_path overridden to the
        // current proxy netns. Cheap — SpliceExecutor holds only an options
        // struct. Do NOT set workload_netns_path: ResolveWorkloadNetnsPath
        // derives it from prev_result.interfaces[].sandbox, which is what
        // the state file already carries.
        auto per_call_options = executor.options();
        per_call_options.proxy_netns_path = current_proxy_netns;
        SpliceExecutor per_call_executor(std::move(per_call_options));

        CniInvocation invocation;
        invocation.request = std::move(*request_opt);
        invocation.container_id = container_id;
        invocation.ifname = ifname;

        // HandleAdd's third arg is `const std::optional<PodInfo>&`; PodInfo
        // converts implicitly.
        const auto handle_result =
            per_call_executor.HandleAdd(invocation, workload_pod, proxy_pod);
        if (handle_result.success) {
            ++result.repaired;
        } else {
            std::cerr << "splice-repair: HandleAdd failed for " << path
                      << ": " << handle_result.stderr_text << "\n";
            ++result.failed;
        }
    }  // end of for-loop body — closes the per-state-file iteration
```

(Note: the surrounding `for (const auto& entry : dir_it) { ... }` loop ends here. The previous placeholder `++result.failed;` was the loop body's last statement, so the closing brace was implicitly the loop's. Replacing the placeholder block in this step does not change that — the closing `}` for the for-loop still appears below the new block, where it was before. Make sure the loop's closing `}` is preserved when you make the edit.)

- [ ] **Step 6.4: Run — expect PASS**

```
bazel test //tests:splice_repair_test --test_output=errors
```

Expected: 5 PASS.

- [ ] **Step 6.5: Commit**

```
git add src/cni/splice_repair.cpp tests/splice_repair_test.cpp
git commit -m "splice_repair: re-splice orphans via HandleAdd with current netns"
```

---

### Task 7: Test "failed" branches (runner returns false + malformed JSON)

- [ ] **Step 7.1: Append both tests**

```cpp
TEST_F(SpliceRepairTest, RunnerFailureCountsAsFailed) {
    const auto current_path = state_root_ / "cur"; std::ofstream(current_path).put('c');
    const auto stale = state_root_ / "old"; std::ofstream(stale).put('o');
    const auto workload = state_root_ / "wl"; std::ofstream(workload).put('w');
    WriteStateFile(state_root_, "fail1", workload.string(), stale.string());

    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [](const auto&, const auto&, const auto&) { return false; };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, current_path);
    EXPECT_EQ(result.failed, 1u);
    EXPECT_EQ(result.repaired, 0u);
}

TEST_F(SpliceRepairTest, MalformedStateFileCountsAsFailed) {
    {
        std::ofstream f(state_root_ / "container-bad.json");
        f << "{not json";
    }

    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [](const auto&, const auto&, const auto&) { return true; };
    inline_proxy::SpliceExecutor executor(std::move(options));

    const auto result = inline_proxy::RepairOrphanedSplices(executor, "/proc/self/ns/net");
    EXPECT_EQ(result.total_state_files, 1u);
    EXPECT_EQ(result.failed, 1u);
}
```

- [ ] **Step 7.2: Run — expect PASS**

Both already work with the Task 6 implementation. Run to confirm.

```
bazel test //tests:splice_repair_test --test_output=errors
```

Expected: 7 PASS.

- [ ] **Step 7.3: Commit**

```
git add tests/splice_repair_test.cpp
git commit -m "Test: lock in failed counter on runner-false and malformed JSON"
```

---

### Task 8: Test deadline behaviour

- [ ] **Step 8.1: Append the test**

```cpp
TEST_F(SpliceRepairTest, DeadlineExceededShortCircuitsScan) {
    // Two orphan files; both should match the orphan path.
    const auto current_path = state_root_ / "cur"; std::ofstream(current_path).put('c');
    const auto stale = state_root_ / "old"; std::ofstream(stale).put('o');
    const auto wl1 = state_root_ / "wl1"; std::ofstream(wl1).put('1');
    const auto wl2 = state_root_ / "wl2"; std::ofstream(wl2).put('2');
    WriteStateFile(state_root_, "dl1", wl1.string(), stale.string());
    WriteStateFile(state_root_, "dl2", wl2.string(), stale.string());

    int runner_calls = 0;
    inline_proxy::CniExecutionOptions options;
    options.state_root = state_root_;
    options.splice_runner = [&](const auto&, const auto&, const auto&) {
        ++runner_calls;
        return true;
    };
    inline_proxy::SpliceExecutor executor(std::move(options));

    // Zero-duration deadline: the per-iteration check at the top of the loop
    // fires before any per-pod work runs.
    const auto result = inline_proxy::RepairOrphanedSplices(
        executor, current_path, std::chrono::seconds(0));

    EXPECT_EQ(result.total_state_files, 2u);
    EXPECT_EQ(result.skipped_deadline_exceeded, 2u);
    EXPECT_EQ(result.repaired, 0u);
    EXPECT_EQ(result.failed, 0u);
    EXPECT_EQ(runner_calls, 0);
}
```

- [ ] **Step 8.2: Run — expect PASS**

The Task 4 implementation already includes the per-iteration deadline check.

```
bazel test //tests:splice_repair_test --test_output=errors
```

Expected: 8 PASS.

- [ ] **Step 8.3: Commit**

```
git add tests/splice_repair_test.cpp
git commit -m "Test: lock in deadline behaviour for splice_repair"
```

---

## Chunk 3: CNI hookup

### Task 9: Wire `RepairOrphanedSplices` into the `IsProxyPod` branch

**Files:**
- Modify: `src/cni/splice_executor.cpp:343-350`
- Modify: `tests/cni_add_del_test.cpp` (add unit test for the new branch)

The repair must run AFTER `proxy_pod_pinner` succeeds (so the BPF prog is pinned and `tc_attach` against it works) and BEFORE the `result.success = true; return result;` so the daemon's CNI ADD response includes the repair side-effects.

The new daemon's netns path is obtained via `ResolveWorkloadNetnsPath(invocation)`, declared in `src/cni/netns_resolver.hpp`. This reads `request.prev_result->interfaces[].sandbox` — the daemon DS pod's own CNI sandbox path, populated by the upstream chain plugin (flannel/bridge/etc.).

- [ ] **Step 9.1: Add the include**

At the top of `src/cni/splice_executor.cpp`, near the other `cni/` includes, add:

```cpp
#include "cni/splice_repair.hpp"
```

`netns_resolver.hpp` is already included (it's in the same library and `ResolveWorkloadNetnsPath` is used elsewhere in the file).

- [ ] **Step 9.2: Modify the `IsProxyPod` branch**

Replace the existing block at `splice_executor.cpp:343-350`:

```cpp
    if (IsProxyPod(workload_pod)) {
        if (!options_.proxy_pod_pinner(options_.pin_dir)) {
            result.stderr_text = "failed to LoadAndPin BPF program for proxy DS pod";
            return result;
        }
        result.success = true;
        return result;
    }
```

with:

```cpp
    if (IsProxyPod(workload_pod)) {
        if (!options_.proxy_pod_pinner(options_.pin_dir)) {
            result.stderr_text = "failed to LoadAndPin BPF program for proxy DS pod";
            return result;
        }
        if (const auto self_netns = ResolveWorkloadNetnsPath(invocation);
            self_netns.has_value()) {
            const auto repair = RepairOrphanedSplices(*this, *self_netns);
            std::cerr << "splice-repair total=" << repair.total_state_files
                      << " repaired=" << repair.repaired
                      << " skipped_intact=" << repair.skipped_intact
                      << " skipped_workload_gone=" << repair.skipped_workload_gone
                      << " skipped_deadline_exceeded=" << repair.skipped_deadline_exceeded
                      << " failed=" << repair.failed << "\n";
        } else {
            std::cerr << "splice-repair skipped: cannot resolve daemon DS pod netns from prev_result\n";
        }
        result.success = true;
        return result;
    }
```

`RepairOrphanedSplices` takes `const SpliceExecutor&` so `*this` (a `const SpliceExecutor&` inside this `const` method) binds directly without `const_cast`. The reconciler does not mutate the executor; it builds a per-call copy internally via `executor.options()`.

- [ ] **Step 9.3: Add the unit test**

In `tests/cni_add_del_test.cpp`, find the existing tests that exercise the IsProxyPod branch (search for `MakeProxyPod` or `proxy_pod_pinner`). Add a new test alongside them. This test follows the existing `cni_add_del_test.cpp` style: manual `std::filesystem::temp_directory_path()` setup with `remove_all` cleanup, no external `ScopedTempDir` helper.

```cpp
TEST(CniAddDelTest, ProxyPodAddTriggersRepairWithSelfNetns) {
    namespace fs = std::filesystem;
    const fs::path fixture_dir = fs::temp_directory_path() /
        ("cni-add-del-repair-test-" + std::to_string(::getpid()));
    fs::remove_all(fixture_dir);
    fs::create_directories(fixture_dir / "netns");
    struct DirGuard {
        fs::path path;
        ~DirGuard() { std::error_code ec; fs::remove_all(path, ec); }
    } guard{fixture_dir};

    // Stand-in files act as netns paths for inode comparison.
    const auto self_netns_file = fixture_dir / "netns" / "self";
    const auto stale_netns_file = fixture_dir / "netns" / "stale";
    const auto workload_netns_file = fixture_dir / "netns" / "workload";
    std::ofstream(self_netns_file).put('s');
    std::ofstream(stale_netns_file).put('S');
    std::ofstream(workload_netns_file).put('w');

    // Write one state file pointing at the stale netns (orphaned splice).
    inline_proxy::StateStore store(fixture_dir / "container-orph.json");
    inline_proxy::StateFields fields = {
        {"container_id", "orph"},
        {"ifname", "eth0"},
        {"pod_name", "caddy-1"},
        {"pod_namespace", "default"},
        {"prev_result",
         std::string(R"({"interfaces":[{"name":"eth0","sandbox":")")
            + workload_netns_file.string()
            + R"("}],"ips":[{"address":"10.42.0.10/24","gateway":"10.42.0.1","interface":0}]})"},
        {"proxy_netns_path", stale_netns_file.string()},
        {"proxy_name", "inline-proxy-daemon-x"},
        {"proxy_namespace", "inline-proxy-system"},
        {"proxy_node_name", "worker-1"},
        {"workload_netns_path", workload_netns_file.string()},
    };
    ASSERT_TRUE(store.Write(fields));

    int repair_runner_calls = 0;
    std::filesystem::path observed_proxy;
    inline_proxy::CniExecutionOptions options;
    options.state_root = fixture_dir;
    options.proxy_pod_pinner = [](std::string_view) { return true; };
    options.splice_runner = [&](const inline_proxy::SplicePlan&,
                                const std::filesystem::path&,
                                const std::filesystem::path& proxy) {
        ++repair_runner_calls;
        observed_proxy = proxy;
        return true;
    };
    inline_proxy::SpliceExecutor executor(std::move(options));

    // The proxy DS pod is the workload from CNI's perspective.
    inline_proxy::PodInfo daemon_pod;
    daemon_pod.name = "inline-proxy-daemon-y";
    daemon_pod.namespace_name = "inline-proxy-system";
    daemon_pod.node_name = "worker-1";
    daemon_pod.running = true;
    daemon_pod.labels["app"] = "inline-proxy";

    // The invocation's prev_result.interfaces[].sandbox is the daemon's
    // own (new) netns — that's what ResolveWorkloadNetnsPath returns.
    const std::string daemon_request_json =
        std::string(R"({"cniVersion":"1.0.0","name":"k8s","prevResult":{"interfaces":[{"name":"eth0","sandbox":")")
        + self_netns_file.string() + R"("}]}})";
    auto request = inline_proxy::ParseCniRequest(daemon_request_json);
    ASSERT_TRUE(request.has_value());

    inline_proxy::CniInvocation invocation{
        .request = *request,
        .container_id = "daemon-cid",
        .ifname = "eth0",
    };
    const auto add_result = executor.HandleAdd(invocation, daemon_pod, std::nullopt);

    EXPECT_TRUE(add_result.success);
    EXPECT_EQ(repair_runner_calls, 1);
    EXPECT_EQ(observed_proxy, self_netns_file);
}
```

Make sure the file's existing includes cover `<filesystem>`, `<fstream>`, `shared/state_store.hpp`, and `cni/yajl_parser.hpp` (for `ParseCniRequest`). Add any missing ones at the top.

- [ ] **Step 9.4: Build and run**

```
bazel test //tests:cni_add_del_test //tests:splice_repair_test --test_output=errors
bazel test //tests/...
```

Expected: build succeeds; all tests pass except the two known pre-existing flakes (`event_loop_test`, `k8s_client_test` cert expiry — fixed in unmerged PR #10).

- [ ] **Step 9.5: Commit**

```
git add src/cni/splice_executor.cpp tests/cni_add_del_test.cpp
git commit -m "CNI: invoke splice repair from new daemon's IsProxyPod branch"
```

---

## Chunk 4: Integration test (root-gated)

### Task 10: Extend `NetnsFixture` with the splice-repair scenario

**Files:**
- Modify: `tests/netns_fixture.hpp`
- Modify: `tests/netns_fixture.cpp`
- Modify: `tests/BUILD.bazel`

Port the `RunSpliceRepairScenario` method from the unmerged `feature/splice-reconciler` branch. The logic is netns-context-agnostic: it creates an "old proxy" netns, runs `HandleAdd` against it, deletes it, then runs `RepairOrphanedSplices` against a "new proxy" netns and verifies the topology migrated.

The unmerged source can be retrieved with:

```
git show splice-reconciler:tests/netns_fixture.hpp > /tmp/unmerged-netns_fixture.hpp
git show splice-reconciler:tests/netns_fixture.cpp > /tmp/unmerged-netns_fixture.cpp
```

(or just read those files at `/home/kai/work/k8s/.worktrees/splice-reconciler/tests/netns_fixture.{hpp,cpp}`.)

- [ ] **Step 10.1: Declare `RunSpliceRepairScenario` in `tests/netns_fixture.hpp`**

In the public section after `RunSpliceExecutorScenario()`, add:

```cpp
    bool RunSpliceRepairScenario();
```

- [ ] **Step 10.2: Port the implementation**

Copy the body of `RunSpliceRepairScenario` from
`/home/kai/work/k8s/.worktrees/splice-reconciler/tests/netns_fixture.cpp`
into `tests/netns_fixture.cpp` (append after `RunSpliceExecutorScenario`'s closing brace).

The body uses `Quote`, `NamespacePath`, `LinkExistsInNamespace`, `RunCommand`, and `BuildBridgeBackedWorkloadTopology` — all already present in the current `netns_fixture.cpp`. The body also uses `IsLinkUpInNamespace` — port that file-local helper too (from the same source file).

Also port the tightening change to `ResetNamespaces` so the destructor doesn't print noise after the scenario clears `proxy_ns_`. In `tests/netns_fixture.cpp`, the existing body looks like:

```cpp
bool NetnsFixture::ResetNamespaces() {
    bool ok = true;
    ok &= RunCommand("/usr/bin/ip netns delete " + Quote(client_ns_));
    ok &= RunCommand("/usr/bin/ip netns delete " + Quote(proxy_ns_));
    ok &= RunCommand("/usr/bin/ip netns delete " + Quote(workload_ns_));
    namespaces_created_ = false;
    return ok;
}
```

Change it to skip empty names:

```cpp
bool NetnsFixture::ResetNamespaces() {
    bool ok = true;
    if (!client_ns_.empty()) {
        ok &= RunCommand("/usr/bin/ip netns delete " + Quote(client_ns_));
    }
    if (!proxy_ns_.empty()) {
        ok &= RunCommand("/usr/bin/ip netns delete " + Quote(proxy_ns_));
    }
    if (!workload_ns_.empty()) {
        ok &= RunCommand("/usr/bin/ip netns delete " + Quote(workload_ns_));
    }
    namespaces_created_ = false;
    return ok;
}
```

- [ ] **Step 10.3: Update the `netns_fixture` BUILD dep**

In `tests/BUILD.bazel`, the existing `cc_library(name = "netns_fixture", ...)` block already lists `//src/cni:cni_splice` in its deps (which now includes splice_repair). No additional dep needed.

If the unmerged port references any include that the current `netns_fixture.cpp` doesn't already pull in (e.g., `cni/splice_repair.hpp`), add the `#include` at the top.

- [ ] **Step 10.4: Build**

```
bazel build //tests:netns_fixture
```

Expected: `Build completed successfully`.

- [ ] **Step 10.5: Commit**

```
git add tests/netns_fixture.hpp tests/netns_fixture.cpp
git commit -m "Test: extend NetnsFixture with end-to-end splice repair scenario"
```

---

### Task 11: Add the gated gtest wrapper

**Files:**
- Create: `tests/splice_repair_netns_test.cpp`
- Modify: `tests/BUILD.bazel`

- [ ] **Step 11.1: Create the test wrapper**

Write `tests/splice_repair_netns_test.cpp` (verbatim from the unmerged branch):

```cpp
#include <gtest/gtest.h>

#include "tests/netns_fixture.hpp"

TEST(SpliceRepairNetnsTest, RebuildsOrphanedSpliceIntoNewProxyNetns) {
    if (!inline_proxy::NetnsFixture::HasRequiredPrivileges()) {
        GTEST_SKIP() << "Requires CAP_NET_ADMIN/root and /usr/bin/ip";
    }

    auto env = inline_proxy::NetnsFixture::Create();
    ASSERT_TRUE(env.has_value());
    EXPECT_TRUE(env->RunSpliceRepairScenario());
}
```

- [ ] **Step 11.2: Register the cc_test**

Append to `tests/BUILD.bazel`:

```python
cc_test(
    name = "splice_repair_netns_test",
    srcs = ["splice_repair_netns_test.cpp"],
    size = "large",
    local = True,
    deps = [
        ":netns_fixture",
        "@googletest//:gtest_main",
    ],
)
```

- [ ] **Step 11.3: Build and run**

```
bazel test //tests:splice_repair_netns_test --test_output=streamed
```

Expected:
- Without root: `SKIPPED` (or PASSED-with-skip message; Bazel counts skipped as PASS).
- With root: `PASSED`.

- [ ] **Step 11.4: Commit**

```
git add tests/splice_repair_netns_test.cpp tests/BUILD.bazel
git commit -m "Test: add splice_repair_netns_test integration test"
```

---

## Chunk 5: Live verification + PR

### Task 12: Build, ship, and verify on meta-dev k3s

**Files:**
- None (deployment + verification only)

The motivating bug was observed live on the `meta-dev` k3s cluster. After implementing, deploy the fix and reproduce the daemon-restart scenario; previously-orphaned workload pods should now self-heal during the new daemon's CNI ADD.

- [ ] **Step 12.1: Build the CNI binary**

```
bazel build //src/cni:inline_proxy_cni
```

Only the CNI binary changes; the daemon binary is unchanged from main. Verify by checking that no files under `src/proxy/` were modified by this branch (`git diff main -- src/proxy/` should be empty).

- [ ] **Step 12.2: Ship to meta-dev**

```
ssh meta-dev 'rm -f /tmp/inline-proxy-build/inline_proxy_cni'
scp bazel-bin/src/cni/inline_proxy_cni meta-dev:/tmp/inline-proxy-build/
TAG=cni-side-reconciler
ssh meta-dev "bash -s" <<BASH
cd /tmp/inline-proxy-build
podman build -f Containerfile.installer -t inline-proxy/installer:$TAG .
podman save -o "installer-${TAG}.tar" inline-proxy/installer:$TAG
sudo k3s ctr images import "installer-${TAG}.tar"
sudo kubectl -n inline-proxy-system set image ds/inline-proxy-installer installer=localhost/inline-proxy/installer:$TAG
sudo kubectl -n inline-proxy-system rollout status ds/inline-proxy-installer --timeout=120s
BASH
```

- [ ] **Step 12.3: Provoke orphan + verify recovery**

```
ssh meta-dev "bash -s" <<'BASH'
# Establish a baseline: client → caddy via service should work today.
sudo kubectl exec inline-proxy-client-demo -- curl -s --max-time 5 -o /dev/null -w 'before=%{http_code}\n' http://inline-proxy-caddy-demo.default.svc.cluster.local/

# Force a daemon restart while caddy pods are alive — this is the failure mode.
sudo kubectl -n inline-proxy-system delete pod -l app=inline-proxy --wait=false
sleep 30
sudo kubectl -n inline-proxy-system wait --for=condition=Ready pod -l app=inline-proxy --timeout=60s

# Without the fix, caddy pods would now be unreachable. With the CNI-side
# reconciler, the new daemon's CNI ADD should have re-spliced them.
sudo kubectl exec inline-proxy-client-demo -- curl -s --max-time 5 -o /dev/null -w 'after=%{http_code}\n' http://inline-proxy-caddy-demo.default.svc.cluster.local/

# Confirm via daemon log that splice-repair fired with non-zero `repaired`
# (visible in journald via the CNI plugin's stderr — appears in the new
# daemon pod's logs because the plugin runs synchronously during its CNI ADD).
sudo journalctl -u k3s --since '2 min ago' | grep '^splice-repair' | tail -3
BASH
```

Expected: `after=200`; `splice-repair total=N repaired=N skipped_intact=0 ... failed=0` for the caddy pods.

- [ ] **Step 12.4: Push the branch and open a PR**

```
git push -u origin feature/cni-side-reconciler
gh pr create --title "CNI: repair orphaned splices on new daemon's CNI ADD" \
    --body "..."
```

PR body should:
- Summarise the orphan-on-DS-restart bug (link issue #12).
- Describe the trigger (new daemon's IsProxyPod branch), inode-based detection, and 30s deadline.
- Reference PR #11 (Layer 1 cleanup) and PR #9 (CNI-owned BPF attach) for context.
- Document the live verification.
- Note that the failed daemon-side approach on `feature/splice-reconciler` is superseded; that branch can be deleted after merge.

---

## Definition of done

- 8 unit tests in `splice_repair_test` pass: `EmptyStateRoot…`, `NonexistentStateRoot…`, `MatchingProxyInodeIsSkippedIntact`, `MissingWorkloadNetnsIsSkippedAsGone`, `OrphanedFileTriggersHandleAddWithCurrentNetns`, `RunnerFailureCountsAsFailed`, `MalformedStateFileCountsAsFailed`, `DeadlineExceededShortCircuitsScan`.
- 1 new test in `cni_add_del_test` passes: `ProxyPodAddTriggersRepairWithSelfNetns`.
- `splice_repair_netns_test` passes when run as root, skips otherwise.
- `bazel test //tests/...` shows no regressions beyond the two known flaky tests.
- Live disruption test on meta-dev: caddy pods remain reachable after a forced daemon restart; daemon logs show `splice-repair repaired=N` matching the previously-spliced caddy pods.
- PR opened on `feature/cni-side-reconciler` and linked to PR #11 + issue #12.
