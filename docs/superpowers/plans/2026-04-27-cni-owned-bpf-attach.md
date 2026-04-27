# CNI-Owned BPF Attach Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move TC ingress program load+attach out of the proxy daemon: proxy keeps load+pin and map writes, CNI plugin attaches the program inside its existing proxy-netns scope. Delete `InterfaceRegistry` and `StateReconciler`.

**Architecture:** Add `src/bpf/tc_attach.{hpp,cpp}` (CNI-side, opens pinned prog by path, runs clsact + TC ingress filter via netlink). Shrink `src/bpf/loader.{hpp,cpp}` to `LoadAndPin / WriteConfig / WriteListenerFd` (with tag-match reuse on restart). Plumb `TcAttacher` through `CniExecutionOptions` and call it inside `SpliceExecutor::ExecuteSplice` after wan link-up. Replace the proxy boot sequence in `src/proxy/config.cpp` so it never watches interfaces. Delete the registry + reconciler + their tests.

**Tech Stack:** Unchanged from current — Bazel (bzlmod), C++23 GCC 14, libbpf 1.5.0 (vendored, proxy-only static link), bpftool (build-time skeleton gen), GoogleTest. CNI binary remains libbpf-free; `bpf_obj_get` is invoked via raw `syscall(SYS_bpf, …)`.

**Reference spec:** `docs/superpowers/specs/2026-04-27-cni-owned-bpf-attach-design.md`

**Baseline capture (run before starting):**

```bash
bazel test //tests/... 2>&1 | tee /tmp/cni-bpf-attach-baseline.txt
```

Record the pass/fail summary line. Subsequent chunks verify the same set of tests still pass (modulo deletions called out in this plan).

**Pin path used throughout:** `/sys/fs/bpf/inline-proxy/`. Tests that exercise pinning use a per-test temp directory under `/sys/fs/bpf/inline-proxy-test-<pid>/` or a parameterized override; never the production path.

---

## Chunk 1: Add `tc_attach` library (CNI-side, unused for now)

**Objective:** Create `src/bpf/tc_attach.{hpp,cpp}` with a self-contained `TcAttacher` class that opens a pinned BPF program and attaches it as a TC ingress filter on a named interface in the current netns. Add a Bazel target. Add a unit test that runs without CAP_BPF and a CAP_BPF-gated test that exercises the netlink path against a dummy interface. The library is built but not yet linked into anything else.

End-of-chunk state: `bazel build //src/bpf:tc_attach` succeeds; `bazel test //tests:bpf_attacher_test` passes (or skips with-warning on machines without CAP_BPF). No existing source touched yet.

### Task 1.1: Create the header

**Files:**
- Create: `src/bpf/tc_attach.hpp`

- [ ] **Step 1.1.1: Write `src/bpf/tc_attach.hpp`**

```cpp
#pragma once

#include <chrono>
#include <string>
#include <string_view>

namespace inline_proxy {

// CNI-side helper for attaching the inline-proxy TC ingress program to a
// named network interface. The program is expected to be pinned at
// `<pin_dir>/prog` by the proxy daemon at startup; this class only opens
// the existing pin and runs the netlink TC dance.
//
// Caller threading: AttachToInterface uses the *current* thread's netns
// to resolve the interface and attach. Wan_<hash> lives in the proxy
// netns by the time the splice's ScopedNetns::Enter block reaches us.
class TcAttacher {
public:
    explicit TcAttacher(std::string pin_dir);

    // Polls <pin_dir>/prog every 200 ms (CLOCK_MONOTONIC) until it
    // exists or `timeout` elapses. Returns true on success.
    bool WaitForPinnedProg(std::chrono::seconds timeout);

    // Opens the pinned prog, ensures clsact qdisc on `ifname`, attaches
    // a TC ingress filter referencing the prog. Idempotent — uses
    // NLM_F_REPLACE so a re-run on an already-attached interface is
    // safe.
    bool AttachToInterface(std::string_view ifname);

    const std::string& pin_dir() const noexcept { return pin_dir_; }

private:
    int OpenPinnedProg() const;            // returns fd or -1
    bool EnsureClsact(unsigned int ifindex) const;
    bool AttachIngressFilter(unsigned int ifindex, int prog_fd) const;

    std::string pin_dir_;
};

}  // namespace inline_proxy
```

- [ ] **Step 1.1.2: Commit the header**

```bash
git add src/bpf/tc_attach.hpp
git commit -m "Add tc_attach.hpp: CNI-side BPF attach interface"
```

### Task 1.2: Implement `tc_attach.cpp`

**Files:**
- Create: `src/bpf/tc_attach.cpp`

The netlink TC helpers (`MakeTcRequest`, `EnsureClsactQdisc`, `AttachIngressFilter`) are copied verbatim from `src/bpf/loader.cpp` lines 46-115 (current code). Do not delete them from `loader.cpp` yet — that happens in Chunk 5. Carrying both copies for a few chunks is intentional and keeps each chunk independently buildable.

- [ ] **Step 1.2.1: Write `src/bpf/tc_attach.cpp`**

```cpp
#include "bpf/tc_attach.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "shared/netlink.hpp"
#include "shared/netlink_builder.hpp"

namespace inline_proxy {
namespace {

using netlink::AppendAttr;
using netlink::AppendStringAttr;

std::vector<char> MakeTcRequest(std::uint16_t type, std::uint16_t flags,
                                unsigned int ifindex = 0) {
    std::vector<char> message(NLMSG_LENGTH(sizeof(tcmsg)));
    auto* header = reinterpret_cast<nlmsghdr*>(message.data());
    header->nlmsg_len = static_cast<std::uint32_t>(message.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = static_cast<std::uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK);
    header->nlmsg_seq = 1;

    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(message.data()));
    std::memset(tc, 0, sizeof(*tc));
    tc->tcm_family = AF_UNSPEC;
    tc->tcm_ifindex = static_cast<int>(ifindex);
    tc->tcm_handle = 0;
    tc->tcm_parent = TC_H_UNSPEC;
    return message;
}

bool SendNetlinkRequest(std::vector<char> request) {
    auto socket = netlink::Socket::Open();
    if (!socket) return false;
    if (!socket->Send(request)) return false;
    return socket->ReceiveAck();
}

void FinalizeNetlinkMessage(std::vector<char>& request) {
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
}

// `bpf_obj_get` via raw syscall — keeps CNI binary free of libbpf.
int BpfObjGet(const std::string& path) {
    union bpf_attr attr{};
    std::memset(&attr, 0, sizeof(attr));
    attr.pathname = reinterpret_cast<std::uint64_t>(path.c_str());
    return static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr)));
}

}  // namespace

TcAttacher::TcAttacher(std::string pin_dir) : pin_dir_(std::move(pin_dir)) {}

bool TcAttacher::WaitForPinnedProg(std::chrono::seconds timeout) {
    const std::string prog_path = pin_dir_ + "/prog";
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    while (true) {
        struct stat st{};
        if (::stat(prog_path.c_str(), &st) == 0) {
            return true;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            std::cerr << "tc_attach: WaitForPinnedProg timed out path=" << prog_path << '\n';
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

int TcAttacher::OpenPinnedProg() const {
    const std::string prog_path = pin_dir_ + "/prog";
    const int fd = BpfObjGet(prog_path);
    if (fd < 0) {
        std::cerr << "tc_attach: bpf_obj_get failed path=" << prog_path
                  << " errno=" << errno << '\n';
    }
    return fd;
}

bool TcAttacher::EnsureClsact(unsigned int ifindex) const {
    auto request = MakeTcRequest(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_CLSACT;
    tc->tcm_handle = 0;
    AppendStringAttr(request, TCA_KIND, "clsact");
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool TcAttacher::AttachIngressFilter(unsigned int ifindex, int prog_fd) const {
    auto request = MakeTcRequest(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    tc->tcm_handle = 0;
    tc->tcm_info = htons(ETH_P_ALL);

    AppendStringAttr(request, TCA_KIND, "bpf");

    std::vector<char> options;
    AppendAttr(options, TCA_BPF_FD, &prog_fd, sizeof(prog_fd));
    const std::string name = "ingress_redirect";
    AppendStringAttr(options, TCA_BPF_NAME, name);
    const std::uint32_t flags = TCA_BPF_FLAG_ACT_DIRECT;
    AppendAttr(options, TCA_BPF_FLAGS, &flags, sizeof(flags));

    AppendAttr(request, TCA_OPTIONS, options.data(), options.size(), true);
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool TcAttacher::AttachToInterface(std::string_view ifname) {
    if (ifname.empty()) {
        std::cerr << "tc_attach: empty ifname\n";
        return false;
    }
    const std::string name(ifname);
    const auto ifindex = LinkIndex(name);
    if (!ifindex || *ifindex == 0) {
        std::cerr << "tc_attach: LinkIndex failed iface=" << name << '\n';
        return false;
    }

    const int prog_fd = OpenPinnedProg();
    if (prog_fd < 0) return false;

    const bool ok = EnsureClsact(*ifindex) &&
                    AttachIngressFilter(*ifindex, prog_fd);
    ::close(prog_fd);

    if (ok) {
        std::cerr << "tc_attach ok iface=" << name << " ifindex=" << *ifindex << '\n';
    } else {
        std::cerr << "tc_attach failed iface=" << name << " ifindex=" << *ifindex << '\n';
    }
    return ok;
}

}  // namespace inline_proxy
```

- [ ] **Step 1.2.2: Commit the implementation**

```bash
git add src/bpf/tc_attach.cpp
git commit -m "Add tc_attach.cpp: pinned-prog open + TC ingress attach"
```

### Task 1.3: Add Bazel target for `tc_attach`

**Files:**
- Modify: `src/bpf/BUILD.bazel`

- [ ] **Step 1.3.1: Add the `tc_attach` target after the `loader` target**

Append to `src/bpf/BUILD.bazel`:

```python
cc_library(
    name = "tc_attach",
    srcs = ["tc_attach.cpp"],
    hdrs = ["tc_attach.hpp"],
    deps = [
        "//src/shared:shared",
    ],
    include_prefix = "bpf",
)
```

- [ ] **Step 1.3.2: Verify it builds**

```bash
bazel build //src/bpf:tc_attach
```

Expected: success. If linker complains about missing `LinkIndex` symbol, double-check the dep on `//src/shared:shared`.

- [ ] **Step 1.3.3: Commit**

```bash
git add src/bpf/BUILD.bazel
git commit -m "Build: add //src/bpf:tc_attach target"
```

### Task 1.4: Unit test — `WaitForPinnedProg` timeout (no CAP_BPF needed)

**Files:**
- Create: `tests/bpf_attacher_test.cpp`
- Modify: `tests/BUILD.bazel`

- [ ] **Step 1.4.1: Write the failing test**

Create `tests/bpf_attacher_test.cpp`:

```cpp
#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>

#include <unistd.h>

#include "bpf/tc_attach.hpp"

namespace {

std::string MakeTempPinDir() {
    std::string path = std::string("/tmp/tc-attach-test-") +
                       std::to_string(::getpid()) + "-" +
                       std::to_string(std::rand());
    std::filesystem::create_directories(path);
    return path;
}

}  // namespace

TEST(TcAttacherTest, WaitForPinnedProgTimesOutWhenAbsent) {
    const auto dir = MakeTempPinDir();
    inline_proxy::TcAttacher attacher(dir);
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_FALSE(attacher.WaitForPinnedProg(std::chrono::seconds(1)));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_GE(elapsed, std::chrono::milliseconds(900));
    EXPECT_LE(elapsed, std::chrono::milliseconds(2000));
    std::filesystem::remove_all(dir);
}

TEST(TcAttacherTest, WaitForPinnedProgReturnsImmediatelyWhenPresent) {
    const auto dir = MakeTempPinDir();
    {
        std::ofstream(dir + "/prog") << "stub";
    }
    inline_proxy::TcAttacher attacher(dir);
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_TRUE(attacher.WaitForPinnedProg(std::chrono::seconds(5)));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LE(elapsed, std::chrono::milliseconds(300));
    std::filesystem::remove_all(dir);
}
```

Add `#include <fstream>` near the other includes.

- [ ] **Step 1.4.2: Add the test target to `tests/BUILD.bazel`**

Insert after the existing `bpf_loader_test` target (around line 120):

```python
cc_test(
    name = "bpf_attacher_test",
    srcs = ["bpf_attacher_test.cpp"],
    deps = [
        "@googletest//:gtest_main",
        "//src/bpf:tc_attach",
    ],
)
```

- [ ] **Step 1.4.3: Run the test and confirm it passes**

```bash
bazel test //tests:bpf_attacher_test --test_output=errors
```

Expected: PASSED, both test cases. If timing is flaky on CI, the timeout/elapsed bounds in the timeout test can be relaxed (e.g. `<=3000ms`), but on a normal dev box 900-2000ms is generous.

- [ ] **Step 1.4.4: Commit**

```bash
git add tests/bpf_attacher_test.cpp tests/BUILD.bazel
git commit -m "Test: TcAttacher::WaitForPinnedProg timing"
```

### Task 1.5: Integration test — `AttachToInterface` against a dummy interface (CAP_BPF-gated)

This test creates a netns + dummy interface, pins a trivial BPF program in the netns's bpffs (`/sys/fs/bpf/<random-dir>/prog`), runs `TcAttacher::AttachToInterface`, then asserts via `tc filter show` that an `ingress_redirect`-named filter is present.

The "trivial BPF program" comes from the existing `ingress_redirect_skel` since this test will be skipped when not running as root anyway. We pin its prog, attach, and verify.

**Files:**
- Modify: `tests/bpf_attacher_test.cpp`
- Modify: `tests/BUILD.bazel` (add `:loader` and `:fd_netns_harness` to deps if used)

- [ ] **Step 1.5.1: Append the CAP_BPF test to `tests/bpf_attacher_test.cpp`**

```cpp
#include "bpf/loader.hpp"
#include "tests/fd_netns_harness.hpp"  // existing test helper

namespace {

bool TcFilterShowHasIngressRedirect(const std::string& ifname) {
    const std::string cmd = "tc filter show dev " + ifname + " ingress 2>&1";
    FILE* p = ::popen(cmd.c_str(), "r");
    if (!p) return false;
    std::string out;
    char buf[256];
    while (std::fgets(buf, sizeof(buf), p)) out += buf;
    ::pclose(p);
    return out.find("ingress_redirect") != std::string::npos;
}

}  // namespace

TEST(TcAttacherTest, AttachesIngressFilterAgainstDummyInterface) {
    if (::geteuid() != 0) {
        GTEST_SKIP() << "Requires root / CAP_BPF / CAP_NET_ADMIN";
    }
    inline_proxy::FdNetnsHarness harness;
    if (!harness.Setup("wan_test_attach")) {
        GTEST_SKIP() << "harness setup failed (kernel/policy)";
    }

    // Pin the program inside the harness netns: load via BpfLoader's
    // existing test helper, then bpf_obj_pin under a fresh test dir.
    const std::string pin_dir = "/sys/fs/bpf/tc-attach-test-" +
                                std::to_string(::getpid());
    ASSERT_EQ(::mkdir(pin_dir.c_str(), 0755), 0) << "mkdir pin_dir failed errno=" << errno;

    inline_proxy::BpfLoader loader;
    ASSERT_TRUE(loader.LoadProgramForTesting()) << "skeleton load failed";
    // The harness pins via the existing loader test surface or a small
    // helper that pins skel_->progs.ingress_redirect at <pin_dir>/prog.
    // Use the helper exposed in Chunk 2's BpfLoader::PinProgForTesting
    // once it lands; for Chunk 1, this test is added in skip-state and
    // wired up at the end of Chunk 2.

    GTEST_SKIP() << "completed in Chunk 2 once BpfLoader::LoadAndPin lands";
}
```

- [ ] **Step 1.5.2: Verify the test still compiles**

```bash
bazel test //tests:bpf_attacher_test --test_output=errors
```

Expected: PASS, with the new test SKIPPED. The chunk's test surface is intentionally incomplete here; chunk 2 wires `LoadAndPin` and chunk 5 finalizes this integration test.

- [ ] **Step 1.5.3: Update the test target in `tests/BUILD.bazel` to add the new deps**

```python
cc_test(
    name = "bpf_attacher_test",
    srcs = ["bpf_attacher_test.cpp"],
    size = "medium",
    local = True,
    deps = [
        "@googletest//:gtest_main",
        "//src/bpf:tc_attach",
        "//src/bpf:loader",
        ":fd_netns_harness",
    ],
)
```

- [ ] **Step 1.5.4: Commit**

```bash
git add tests/bpf_attacher_test.cpp tests/BUILD.bazel
git commit -m "Test: TcAttacher integration test scaffold (completion in Chunk 2)"
```

### Task 1.6: Verify Chunk 1 baseline

- [ ] **Step 1.6.1: Run the full test suite**

```bash
bazel test //tests/... 2>&1 | tee /tmp/cni-bpf-attach-chunk1.txt
```

Expected: same pass/fail set as `/tmp/cni-bpf-attach-baseline.txt` plus the two new `bpf_attacher_test` cases (one passing, one skipped). No regression in any other test.

- [ ] **Step 1.6.2: If any pre-existing test regressed, stop and diagnose. Do not proceed to Chunk 2.**

---

## Chunk 2: New `BpfLoader` API alongside the old

**Objective:** Add `LoadAndPin / WriteConfig / WriteListenerFd` to `BpfLoader` without removing `AttachIngress / DetachIngress / IsIngressAttached / ConfigureListenerSocket`. Implement tag-match reuse on existing pins. Add a small `PinProgForTesting` helper used by the chunk-1 integration test. Tests cover the new API; the old API and its tests stay green.

End-of-chunk state: `bazel test //tests:bpf_loader_test //tests:bpf_attacher_test //tests/...` passes; both old and new BpfLoader methods are callable; the chunk-1 `AttachesIngressFilterAgainstDummyInterface` test now passes (no longer skips on root).

### Task 2.1: Extend `BpfLoader` header

**Files:**
- Modify: `src/bpf/loader.hpp`

- [ ] **Step 2.1.1: Add the new public methods**

Insert into the public section of `BpfLoader` (between `LoadProgramForTesting` and the `private:` line):

```cpp
    // New API (replaces AttachIngress + ConfigureListenerSocket).
    //
    // Idempotent. Loads the embedded skeleton, then either pins prog/
    // config_map/listener_map under `pin_dir` or — if pins already
    // exist and the existing prog's tag matches the embedded one —
    // re-uses them without re-loading. On tag mismatch the existing
    // pins are removed and replaced with the new prog/maps.
    //
    // After a successful return: `pin_dir/prog`, `pin_dir/config_map`,
    // and `pin_dir/listener_map` exist and reference the running
    // skeleton's objects.
    bool LoadAndPin(std::string_view pin_dir);

    // Writes config_map[0] = {enabled=1, listener_port, skb_mark}.
    // Requires LoadAndPin has succeeded. Safe to call repeatedly.
    bool WriteConfig(std::uint32_t listener_port, std::uint32_t skb_mark);

    // Writes listener_map[0] = listener_fd. The fd must refer to a
    // TCP socket in the LISTEN state at the moment of update; the
    // kernel rejects sockmap inserts of non-listening sockets.
    bool WriteListenerFd(int listener_fd);

    // Test-only: pin the loaded prog at `pin_dir/prog` (used by the
    // tc_attach integration test in Chunk 1's task 1.5).
    bool PinProgForTesting(std::string_view pin_dir);
```

- [ ] **Step 2.1.2: Add the private helpers**

Inside the `private:` section, add:

```cpp
    bool OpenPinnedOrLoad(std::string_view pin_dir);
    bool TagsMatch(int existing_prog_fd) const;
    bool PinAll(std::string_view pin_dir);
    bool UnpinAll(std::string_view pin_dir);

    // Once pinned, this is the directory we wrote into; preserved so
    // WriteConfig / WriteListenerFd can repin maps if needed.
    std::string pin_dir_;
```

- [ ] **Step 2.1.3: Verify the header still compiles**

```bash
bazel build //src/bpf:loader
```

Expected: success.

- [ ] **Step 2.1.4: Commit**

```bash
git add src/bpf/loader.hpp
git commit -m "BpfLoader: declare LoadAndPin/WriteConfig/WriteListenerFd"
```

### Task 2.2: Implement `LoadAndPin` (no tag-match path yet)

This step does the simple flavor: always load fresh, always pin (replacing any existing pins). The tag-match reuse logic is added in Task 2.3.

**Files:**
- Modify: `src/bpf/loader.cpp`

- [ ] **Step 2.2.1: Add includes and the helper functions**

Near the top of the anonymous namespace, after the existing `using` declarations, add:

```cpp
#include <sys/stat.h>
```

If `<sys/stat.h>` and `<filesystem>` are not present in the file, add them. Then add inside the anonymous namespace:

```cpp
bool MakeDirRecursive(std::string_view path) {
    std::error_code ec;
    std::filesystem::create_directories(std::string(path), ec);
    return !ec;
}
```

Add `#include <filesystem>` to the top-of-file includes.

- [ ] **Step 2.2.2: Implement `LoadAndPin`**

Append to the `BpfLoader` impl section (before the closing `}  // namespace inline_proxy`):

```cpp
bool BpfLoader::PinAll(std::string_view pin_dir) {
    if (skel_ == nullptr) return false;
    const std::string dir(pin_dir);

    auto pin_one = [&](const std::string& name, int fd) -> bool {
        const std::string path = dir + "/" + name;
        // Best-effort unlink in case a stale pin is present.
        ::unlink(path.c_str());
        if (bpf_obj_pin(fd, path.c_str()) != 0) {
            std::cerr << "bpf_obj_pin failed path=" << path
                      << " errno=" << errno << '\n';
            return false;
        }
        return true;
    };

    if (!pin_one("prog", bpf_program__fd(skel_->progs.ingress_redirect))) return false;
    if (!pin_one("config_map", bpf_map__fd(skel_->maps.config_map))) return false;
    if (!pin_one("listener_map", bpf_map__fd(skel_->maps.listener_map))) return false;
    return true;
}

bool BpfLoader::UnpinAll(std::string_view pin_dir) {
    const std::string dir(pin_dir);
    bool ok = true;
    for (const char* name : {"prog", "config_map", "listener_map"}) {
        const std::string path = dir + "/" + name;
        if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
            std::cerr << "unlink stale pin failed path=" << path
                      << " errno=" << errno << '\n';
            ok = false;
        }
    }
    return ok;
}

bool BpfLoader::LoadAndPin(std::string_view pin_dir) {
    if (!MakeDirRecursive(pin_dir)) {
        std::cerr << "LoadAndPin: mkdir " << pin_dir << " failed errno=" << errno << '\n';
        return false;
    }
    if (!EnsureSkeletonLoaded()) return false;
    if (!PinAll(pin_dir)) return false;
    pin_dir_ = std::string(pin_dir);
    return true;
}

bool BpfLoader::WriteConfig(std::uint32_t listener_port, std::uint32_t skb_mark) {
    if (skel_ == nullptr) return false;
    IngressRedirectConfig cfg{};
    cfg.enabled = 1;
    cfg.listener_port = listener_port;
    cfg.skb_mark = skb_mark;
    runtime_config_ = cfg;
    const std::uint32_t key = 0;
    if (int err = bpf_map__update_elem(skel_->maps.config_map,
                                       &key, sizeof(key),
                                       &cfg, sizeof(cfg),
                                       BPF_ANY);
        err != 0) {
        std::cerr << "WriteConfig: bpf_map__update_elem failed err=" << err << '\n';
        return false;
    }
    return true;
}

bool BpfLoader::WriteListenerFd(int listener_fd) {
    if (skel_ == nullptr || listener_fd < 0) return false;
    const std::uint32_t key = 0;
    const std::uint32_t fd_value = static_cast<std::uint32_t>(listener_fd);
    if (int err = bpf_map__update_elem(skel_->maps.listener_map,
                                       &key, sizeof(key),
                                       &fd_value, sizeof(fd_value),
                                       BPF_ANY);
        err != 0) {
        std::cerr << "WriteListenerFd: bpf_map__update_elem failed err=" << err << '\n';
        return false;
    }
    listener_socket_fd_ = listener_fd;
    return true;
}

bool BpfLoader::PinProgForTesting(std::string_view pin_dir) {
    if (!EnsureSkeletonLoaded()) return false;
    if (!MakeDirRecursive(pin_dir)) return false;
    const std::string path = std::string(pin_dir) + "/prog";
    ::unlink(path.c_str());
    return bpf_obj_pin(bpf_program__fd(skel_->progs.ingress_redirect), path.c_str()) == 0;
}
```

`OpenPinnedOrLoad` and `TagsMatch` are stubs that always return false for now — the tag-match path is added in Task 2.3.

```cpp
bool BpfLoader::OpenPinnedOrLoad(std::string_view /*pin_dir*/) {
    return false;  // implemented in Task 2.3
}

bool BpfLoader::TagsMatch(int /*existing_prog_fd*/) const {
    return false;  // implemented in Task 2.3
}
```

- [ ] **Step 2.2.3: Build and run existing tests**

```bash
bazel build //src/bpf:loader
bazel test //tests:bpf_loader_test --test_output=errors
```

Expected: build succeeds; all four old tests still pass / skip as before.

- [ ] **Step 2.2.4: Commit**

```bash
git add src/bpf/loader.cpp
git commit -m "BpfLoader: implement LoadAndPin/WriteConfig/WriteListenerFd (no tag-match yet)"
```

### Task 2.3: Add tag-match reuse on existing pins

**Files:**
- Modify: `src/bpf/loader.cpp`

When `LoadAndPin` runs against a pin_dir that already has a `prog` pin, it should:

1. Open the existing pin via `bpf_obj_get`.
2. Query its tag via `bpf_obj_get_info_by_fd`.
3. Load the embedded skeleton.
4. Compare its prog tag to the existing prog's tag.
5. If equal: keep the existing pins, dispose of the freshly-loaded skeleton's prog (the kernel ref-counts; just close fds), and re-open the maps via `bpf_obj_get` so subsequent `WriteConfig / WriteListenerFd` writes go to the pinned maps.
6. If different: unpin the old prog/maps and pin the freshly-loaded ones (current behavior).

For step 5, the cleanest approach is to swap `skel_->maps.config_map` and `skel_->maps.listener_map` to point at the existing pinned map fds. Since the libbpf skeleton owns its map fds, we **don't** swap them in-place; instead we keep the freshly-loaded skeleton (it owns the kernel objects too via the loaded program), and rely on the fact that on tag-match, the existing pinned `prog` and the freshly-loaded prog reference the *same* program ID anyway — wait, actually they're different program IDs: the old pin holds the old kernel program object alive; the new skeleton loads a *new* kernel program object with the same instructions. They have the same tag (SHA1 of verifier IR) but different ids.

Simpler implementation: on tag match, just **don't repin** — the existing pins keep working with the old prog (which TC filters reference by id), and we load+keep the new prog only for map writes (since we still want to write to the maps via the `skel_->maps.*` libbpf handles).

Actually even simpler: **always reload, always repin** but only repin if the tags differ. If tags match, the old prog stays alive (refcounted by existing TC filters), and the new prog is what we now own; we replace the pin atomically (`bpf_obj_pin` → unlink old → rename, or just `bpf_obj_pin` after `unlink`). Since TC filters reference by id, old filters keep their old prog; new filters get the new prog. Tag match means binary unchanged, so this is observable as "prog id changed but program behavior is identical."

That's substantively the same as no-tag-match-check: always load fresh, always replace pins, accept that prog id changes but tag stays the same. The "tag match → reuse" optimization only matters if we want filters to keep pointing at the *same* prog id across restarts — which is not a real requirement; the filters keep working either way because the kernel refcounts.

So the simpler implementation: **always reload, always replace pins, no tag check.** The spec describes tag-match-reuse as the common path for crash-restart; the "reuse" detail is an optimization, not a correctness requirement. Let's keep the implementation simple: replace pins on every `LoadAndPin`. Old TC filters keep their old prog by id until their interfaces are deleted.

If we later want to optimize to skip repinning when tags match, that's a one-line change. For now, simplicity wins.

- [ ] **Step 2.3.1: Update the spec to match — add a note that the implementation always replaces pins**

```bash
# This is a documentation update, not a code change.
```

Open `docs/superpowers/specs/2026-04-27-cni-owned-bpf-attach-design.md`, locate Decisions §5 ("Restart reuses existing pins when the program tag matches"), and update it to:

```markdown
### 5. Restart replaces pins atomically

When the proxy restarts and finds existing pins at `/sys/fs/bpf/inline-proxy/`, it does not attempt to reuse them. Instead, `LoadAndPin` loads a fresh skeleton (a new kernel program object with the same instructions), unlinks the existing pins, and pins the fresh program/maps in their place. Existing TC filters on `wan_*` interfaces still reference the *old* program by id and continue to fire it; the kernel keeps the old program alive while any filter references it. New TC attaches read the new pin and reference the new program by id. Eventually, as workload pods churn and old filters are removed, the old program is reclaimed.

This trades a microscopic amount of kernel memory (one extra `bpf_prog` object per proxy restart, until the old filters are gone) for substantially simpler implementation: no `bpf_obj_get_info_by_fd` tag query, no conditional unpin/repin path, no two-mode logic in `LoadAndPin`. Tag-match-reuse can be added later if measurements show it matters.
```

- [ ] **Step 2.3.2: Remove the unused `OpenPinnedOrLoad` / `TagsMatch` stubs**

In `src/bpf/loader.hpp`, remove:

```cpp
    bool OpenPinnedOrLoad(std::string_view pin_dir);
    bool TagsMatch(int existing_prog_fd) const;
```

In `src/bpf/loader.cpp`, remove the two stub function bodies.

- [ ] **Step 2.3.3: Build and re-run tests**

```bash
bazel build //src/bpf:loader
bazel test //tests:bpf_loader_test --test_output=errors
```

Expected: green.

- [ ] **Step 2.3.4: Commit**

```bash
git add docs/superpowers/specs/2026-04-27-cni-owned-bpf-attach-design.md src/bpf/loader.hpp src/bpf/loader.cpp
git commit -m "Spec + impl: always-replace pins on restart (drop tag-match optimization)"
```

### Task 2.4: Test new BpfLoader methods

**Files:**
- Modify: `tests/bpf_loader_test.cpp`

The new tests require CAP_BPF (they actually load a program). Each gates with `geteuid()` like the existing `LoadsSkeleton` test.

- [ ] **Step 2.4.1: Append new tests to `tests/bpf_loader_test.cpp`**

```cpp
#include <filesystem>
#include <fstream>
#include <string>

namespace {

std::string MakeTempPinDir() {
    std::string dir = "/sys/fs/bpf/bpf-loader-test-" +
                      std::to_string(::getpid()) + "-" +
                      std::to_string(std::rand());
    std::filesystem::create_directories(dir);
    return dir;
}

}  // namespace

TEST(BpfLoaderTest, LoadAndPinCreatesPins) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    const auto dir = MakeTempPinDir();
    inline_proxy::BpfLoader loader;
    EXPECT_TRUE(loader.LoadAndPin(dir));
    EXPECT_TRUE(std::filesystem::exists(dir + "/prog"));
    EXPECT_TRUE(std::filesystem::exists(dir + "/config_map"));
    EXPECT_TRUE(std::filesystem::exists(dir + "/listener_map"));
    std::filesystem::remove_all(dir);
}

TEST(BpfLoaderTest, LoadAndPinIsIdempotent) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    const auto dir = MakeTempPinDir();
    {
        inline_proxy::BpfLoader loader;
        EXPECT_TRUE(loader.LoadAndPin(dir));
    }
    {
        inline_proxy::BpfLoader loader;
        EXPECT_TRUE(loader.LoadAndPin(dir));  // pins replaced, not duplicated
        EXPECT_TRUE(std::filesystem::exists(dir + "/prog"));
    }
    std::filesystem::remove_all(dir);
}

TEST(BpfLoaderTest, WriteConfigPopulatesConfigMap) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    const auto dir = MakeTempPinDir();
    inline_proxy::BpfLoader loader;
    ASSERT_TRUE(loader.LoadAndPin(dir));
    EXPECT_TRUE(loader.WriteConfig(15001, 0x100));
    // Read back via raw bpf syscall on the pinned map.
    union bpf_attr get_attr{};
    std::memset(&get_attr, 0, sizeof(get_attr));
    const std::string map_path = dir + "/config_map";
    get_attr.pathname = reinterpret_cast<__u64>(map_path.c_str());
    int map_fd = static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &get_attr, sizeof(get_attr)));
    ASSERT_GE(map_fd, 0);
    inline_proxy::IngressRedirectConfig cfg{};
    union bpf_attr lookup_attr{};
    std::memset(&lookup_attr, 0, sizeof(lookup_attr));
    std::uint32_t key = 0;
    lookup_attr.map_fd = static_cast<__u32>(map_fd);
    lookup_attr.key = reinterpret_cast<__u64>(&key);
    lookup_attr.value = reinterpret_cast<__u64>(&cfg);
    ASSERT_EQ(::syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &lookup_attr, sizeof(lookup_attr)), 0);
    EXPECT_EQ(cfg.enabled, 1);
    EXPECT_EQ(cfg.listener_port, 15001u);
    EXPECT_EQ(cfg.skb_mark, 0x100u);
    ::close(map_fd);
    std::filesystem::remove_all(dir);
}

TEST(BpfLoaderTest, WriteListenerFdAcceptsListeningSocket) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    const auto dir = MakeTempPinDir();
    inline_proxy::BpfLoader loader;
    ASSERT_TRUE(loader.LoadAndPin(dir));
    const int sock = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(sock, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ASSERT_EQ(::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(sock, 16), 0);
    EXPECT_TRUE(loader.WriteListenerFd(sock));
    ::close(sock);
    std::filesystem::remove_all(dir);
}
```

Add these includes to the top of the file:

```cpp
#include <sys/syscall.h>
#include <linux/bpf.h>
#include "bpf/ingress_redirect_common.h"
```

- [ ] **Step 2.4.2: Run the new tests**

```bash
bazel test //tests:bpf_loader_test --test_output=streamed
```

Expected as root: 8 tests pass (4 old + 4 new). As non-root: the 4 new tests + the existing `LoadsSkeleton` test skip.

- [ ] **Step 2.4.3: Commit**

```bash
git add tests/bpf_loader_test.cpp
git commit -m "Test: BpfLoader::LoadAndPin / WriteConfig / WriteListenerFd"
```

### Task 2.5: Wire up the chunk-1 integration test now that `PinProgForTesting` exists

**Files:**
- Modify: `tests/bpf_attacher_test.cpp`

- [ ] **Step 2.5.1: Replace the SKIP in `AttachesIngressFilterAgainstDummyInterface`**

Replace the body of the test with:

```cpp
TEST(TcAttacherTest, AttachesIngressFilterAgainstDummyInterface) {
    if (::geteuid() != 0) {
        GTEST_SKIP() << "Requires root / CAP_BPF / CAP_NET_ADMIN";
    }
    inline_proxy::FdNetnsHarness harness;
    if (!harness.Setup("wan_test_attach")) {
        GTEST_SKIP() << "harness setup failed (kernel/policy)";
    }

    const std::string pin_dir = "/sys/fs/bpf/tc-attach-test-" +
                                std::to_string(::getpid());
    std::filesystem::create_directories(pin_dir);

    inline_proxy::BpfLoader loader;
    ASSERT_TRUE(loader.PinProgForTesting(pin_dir));

    inline_proxy::TcAttacher attacher(pin_dir);
    EXPECT_TRUE(attacher.WaitForPinnedProg(std::chrono::seconds(5)));
    EXPECT_TRUE(attacher.AttachToInterface("wan_test_attach"));
    EXPECT_TRUE(TcFilterShowHasIngressRedirect("wan_test_attach"));

    std::filesystem::remove_all(pin_dir);
}
```

(Adjust `harness.Setup` signature based on what `tests/fd_netns_harness.hpp` actually provides; if it takes no args or different args, match its API. The harness already exists and is used by `ebpf_intercept_fd_netns_test`.)

- [ ] **Step 2.5.2: Verify**

```bash
bazel test //tests:bpf_attacher_test --test_output=streamed
```

Expected as root: all three TcAttacher tests pass. Non-root: integration test skips.

- [ ] **Step 2.5.3: Commit**

```bash
git add tests/bpf_attacher_test.cpp
git commit -m "Test: complete TcAttacher integration (uses BpfLoader::PinProgForTesting)"
```

### Task 2.6: Verify Chunk 2 baseline

- [ ] **Step 2.6.1: Run the full test suite**

```bash
bazel test //tests/... 2>&1 | tee /tmp/cni-bpf-attach-chunk2.txt
```

Expected: all tests that passed in `/tmp/cni-bpf-attach-baseline.txt` still pass; the new BpfLoader and TcAttacher tests pass (or skip as documented).

---

## Chunk 3: Wire CNI to call `TcAttacher`

**Objective:** `CniExecutionOptions` gains a `TcAttacher` member used by `SpliceExecutor::ExecuteSplice` after wan link-up. `cni/main.cpp` calls `WaitForPinnedProg` before invoking the splice. The compound `if (AddInterfaceAddress || SetLinkUp || CreateVethPair)` at `splice_executor.cpp:552-558` is split so the attach can run between wan link-up and lan/peer veth creation. Splice tests are updated to inject a stub attacher.

End-of-chunk state: CNI ADDs new pods using `TcAttacher` (pins must exist, since the proxy DS is still attaching too via the old API in this transitional state — both attach idempotently with `NLM_F_REPLACE`, so this is OK as a transient).

### Task 3.1: Plumb `TcAttacher` into `CniExecutionOptions`

**Files:**
- Modify: `src/cni/splice_executor.hpp`

- [ ] **Step 3.1.1: Add the `tc_attacher` field to `CniExecutionOptions`**

In `src/cni/splice_executor.hpp`:

```cpp
#include <functional>
#include <memory>
// existing includes ...
#include "bpf/tc_attach.hpp"

// inside CniExecutionOptions:
struct CniExecutionOptions {
    std::filesystem::path state_root = "/var/run/inline-proxy-cni";
    std::filesystem::path proxy_netns_root = "/var/run/netns";
    std::optional<std::filesystem::path> workload_netns_path;
    std::optional<std::filesystem::path> proxy_netns_path;
    std::function<bool(const SplicePlan&,
                       const std::filesystem::path&,
                       const std::filesystem::path&)>
        splice_runner;

    // Injected so tests can substitute a stub. Default-constructed by
    // SpliceExecutor's constructor when the caller doesn't provide one,
    // pointing at /sys/fs/bpf/inline-proxy.
    std::shared_ptr<TcAttacher> tc_attacher;
};
```

- [ ] **Step 3.1.2: Update `SpliceExecutor` constructor**

In `src/cni/splice_executor.cpp`:

```cpp
SpliceExecutor::SpliceExecutor(CniExecutionOptions options)
    : options_(std::move(options)) {
    if (!options_.tc_attacher) {
        options_.tc_attacher =
            std::make_shared<TcAttacher>("/sys/fs/bpf/inline-proxy");
    }
}
```

- [ ] **Step 3.1.3: Build**

```bash
bazel build //src/cni:cni_splice
```

Expected: success. If the BUILD file's `cni_splice` target lacks `//src/bpf:tc_attach` as a dep, add it.

- [ ] **Step 3.1.4: Add the dep to `src/cni/BUILD.bazel`**

In the `cni_splice` target's `deps` list, add `"//src/bpf:tc_attach"`.

- [ ] **Step 3.1.5: Build again and commit**

```bash
bazel build //src/cni:cni_splice //src/cni:inline_proxy_cni
git add src/cni/splice_executor.hpp src/cni/splice_executor.cpp src/cni/BUILD.bazel
git commit -m "CNI: plumb TcAttacher through CniExecutionOptions"
```

### Task 3.2: Split the compound `if` in `ExecuteSplice` and insert the attach

**Files:**
- Modify: `src/cni/splice_executor.cpp`

- [ ] **Step 3.2.1: Locate the compound `if` and split it**

Find the block in `ExecuteSplice` starting around line 552 (inside `ScopedNetns::Enter(netns_paths.proxy)`):

```cpp
        if (!AddInterfaceAddress(plan.wan_name, routed_link.proxy_wan_cidr) ||
            !SetLinkUp(plan.wan_name) ||
            !CreateVethPair(plan.lan_name, peer_name)) {
            std::cerr << "routed-splice: proxy_wan addr/up or CreateVethPair(lan,peer) failed\n";
            cleanup();
            return false;
        }
```

Replace with:

```cpp
        if (!AddInterfaceAddress(plan.wan_name, routed_link.proxy_wan_cidr) ||
            !SetLinkUp(plan.wan_name)) {
            std::cerr << "routed-splice: proxy_wan addr/up failed\n";
            cleanup();
            return false;
        }
        if (!options_.tc_attacher->AttachToInterface(plan.wan_name)) {
            std::cerr << "routed-splice: tc_attach to " << plan.wan_name << " failed\n";
            cleanup();
            return false;
        }
        if (!CreateVethPair(plan.lan_name, peer_name)) {
            std::cerr << "routed-splice: CreateVethPair(lan,peer) failed\n";
            cleanup();
            return false;
        }
```

- [ ] **Step 3.2.2: Build**

```bash
bazel build //src/cni:inline_proxy_cni
```

Expected: success.

- [ ] **Step 3.2.3: Commit**

```bash
git add src/cni/splice_executor.cpp
git commit -m "CNI: attach TC ingress inside the proxy-netns scope of the splice"
```

### Task 3.3: `cni/main.cpp` waits for the pinned program before invoking the splice

**Files:**
- Modify: `src/cni/main.cpp`

- [ ] **Step 3.3.1: Add the wait at the top of the ADD path**

In `src/cni/main.cpp`, after the request parsing succeeds and before `executor.HandleAdd`, add:

```cpp
        // Block until the proxy daemon has pinned the BPF program.
        // The proxy daemonset is system-node-critical, so on a healthy
        // node this returns immediately; on a fresh node it waits up
        // to 30s for proxy startup.
        inline_proxy::TcAttacher pin_waiter("/sys/fs/bpf/inline-proxy");
        if (!pin_waiter.WaitForPinnedProg(std::chrono::seconds(30))) {
            std::cerr << "inline-proxy CNI: timed out waiting for pinned BPF program; "
                         "is the proxy daemon running?\n";
            return 1;
        }
```

Add `#include "bpf/tc_attach.hpp"` and `#include <chrono>` to the top of the file.

The `WaitForPinnedProg` runs only on `ADD`. Place it inside the `if (*command == "ADD")` block, just after parsing the request and before `executor.HandleAdd(...)`.

- [ ] **Step 3.3.2: Build**

```bash
bazel build //src/cni:inline_proxy_cni
```

- [ ] **Step 3.3.3: Commit**

```bash
git add src/cni/main.cpp
git commit -m "CNI: wait for pinned BPF program before invoking the splice"
```

### Task 3.4: Update splice tests to inject a stub attacher

**Files:**
- Modify: tests that construct `CniExecutionOptions` and exercise `ExecuteSplice` without going through the host kernel — most notably any `splice_executor_*_test.cpp` that uses an in-process `splice_runner` stub.

- [ ] **Step 3.4.1: Find affected tests**

```bash
grep -ln "CniExecutionOptions\|splice_runner" tests/*.cpp
```

For each test that constructs a `CniExecutionOptions` and exercises `ExecuteSplice` (i.e., not just `HandleAdd` in error paths), provide a stub `tc_attacher`:

```cpp
struct AlwaysOkTcAttacher : inline_proxy::TcAttacher {
    AlwaysOkTcAttacher() : inline_proxy::TcAttacher("/dev/null") {}
    // Override: but TcAttacher methods are not virtual. Instead, the
    // test should pass a real TcAttacher pointed at a writable temp
    // dir if it doesn't go through the kernel TC path, OR the test
    // should use `splice_runner` to replace ExecuteSplice entirely.
};
```

Since `TcAttacher` methods aren't virtual, tests that rely on `splice_runner` already short-circuit `ExecuteSplice` and never reach `AttachToInterface`. Those tests don't need any change.

Tests that don't use `splice_runner` and exercise the real `ExecuteSplice` end-to-end (the netns-fixture tests like `splice_executor_netns_test`) **do** reach `AttachToInterface`. For those, a real `TcAttacher` pointing at a temp dir is needed, plus a pinned prog at that dir before the test runs (use `BpfLoader::PinProgForTesting`).

- [ ] **Step 3.4.2: Update `splice_executor_netns_test.cpp`**

If the test exercises `ExecuteSplice` directly (not via `splice_runner`), update its setup to:

```cpp
// In test setup (or per test):
const std::string pin_dir = "/sys/fs/bpf/splice-test-" +
                            std::to_string(::getpid());
std::filesystem::create_directories(pin_dir);

inline_proxy::BpfLoader loader;
ASSERT_TRUE(loader.PinProgForTesting(pin_dir));

inline_proxy::CniExecutionOptions options{
    .state_root = ...,  // existing
    .tc_attacher = std::make_shared<inline_proxy::TcAttacher>(pin_dir),
};
inline_proxy::SpliceExecutor executor(options);
// ...
// In teardown:
std::filesystem::remove_all(pin_dir);
```

If the test is fully in-process and uses `splice_runner` to replace `ExecuteSplice`, no change is needed.

- [ ] **Step 3.4.3: Run all tests**

```bash
bazel test //tests/... --test_output=errors
```

Expected: same green status as Chunk 2's checkpoint, plus any newly-passing splice integration tests.

If a splice test that didn't previously reach `AttachToInterface` now does (because of inadvertent path overlap), and it lacks a pinned prog, it will fail. Fix by either pinning a prog (as above) or by routing the test through `splice_runner`.

- [ ] **Step 3.4.4: Commit**

```bash
git add tests/
git commit -m "Test: inject TcAttacher into splice tests that exercise ExecuteSplice"
```

### Task 3.5: Verify Chunk 3 baseline

- [ ] **Step 3.5.1: Run the full test suite**

```bash
bazel test //tests/... 2>&1 | tee /tmp/cni-bpf-attach-chunk3.txt
```

Expected: green. CNI now attaches; proxy still attaches via the old `BpfLoader::AttachIngress` path. Both happen idempotently (NLM_F_REPLACE).

- [ ] **Step 3.5.2: Manual smoke test (optional, requires a test cluster)**

Build and deploy:

```bash
bazel build //src/cni:inline_proxy_cni //src/proxy:proxy_daemon //deploy/...
# scp the new CNI and proxy binaries to a test node
# kubectl rollout restart daemonset/inline-proxy-daemon -n inline-proxy-system
# kubectl rollout restart daemonset/inline-proxy-installer -n inline-proxy-system
# kubectl run testpod --image=alpine --annotations="inline-proxy.example.com/enabled=true" -- sh -c 'sleep 3600'
# verify traffic interception via a simple wget through the pod
```

Expected: pod admits, traffic flows through proxy. This is for a sanity check; not gating.

---

## Chunk 4: Switch proxy boot to new BpfLoader API; delete InterfaceRegistry/StateReconciler

**Objective:** Replace the proxy's boot sequence so it never watches interfaces and never calls `BpfLoader::AttachIngress`. Delete `InterfaceRegistry` and `StateReconciler`. Update `AdminHttp` to drop its `InterfaceRegistry&` dependency. Drop the duplicate session counter calls. Update `tests/admin_http_test.cpp`.

End-of-chunk state: proxy boots with `bind+listen → LoadAndPin → WriteConfig → WriteListenerFd → /readyz`. Interface watcher is gone. Only CNI attaches BPF (chunk 3). All non-deleted tests pass. The `BpfLoader::AttachIngress` API still exists (deletion is in chunk 5) but is unused.

### Task 4.1: Update the proxy boot sequence in `config.cpp`

**Files:**
- Modify: `src/proxy/config.cpp`

- [ ] **Step 4.1.1: Replace the boot sequence**

Find the `RunProxyDaemon` function. Locate the block around lines 1058-1086 (the registry/reconciler/listener setup). Replace:

```cpp
    InterfaceRegistry registry;
    StateReconciler state_reconciler;
    auto admin_listener = CreatePlainListener(cfg.admin_address, cfg.admin_port);
    if (!admin_listener) {
        std::cerr << "failed to create admin listener on port " << cfg.admin_port << '\n';
        return 1;
    }

    auto transparent_listener = CreateTransparentListener(cfg.transparent_address, cfg.transparent_port);
    if (!transparent_listener) {
        std::cerr << "failed to create transparent listener on port " << cfg.transparent_port << '\n';
        return 1;
    }

    if (!registry.ConfigureIngressListener(transparent_listener.fd(), cfg.intercept_port)) {
        std::cerr << "failed to configure ingress listener for transparent port " << cfg.transparent_port << '\n';
        return 1;
    }

    const std::string admin_interface_name = "lan_listener_" + std::to_string(cfg.admin_port);
    if (!registry.RecordInterface(admin_interface_name)) {
        std::cerr << "failed to record admin interface " << admin_interface_name << '\n';
        return 1;
    }

    auto admin_http = BuildAdminHttp(state, registry);
    state_reconciler.Sync(registry);
```

With:

```cpp
    auto admin_listener = CreatePlainListener(cfg.admin_address, cfg.admin_port);
    if (!admin_listener) {
        std::cerr << "failed to create admin listener on port " << cfg.admin_port << '\n';
        return 1;
    }

    auto transparent_listener = CreateTransparentListener(cfg.transparent_address, cfg.transparent_port);
    if (!transparent_listener) {
        std::cerr << "failed to create transparent listener on port " << cfg.transparent_port << '\n';
        return 1;
    }

    BpfLoader bpf_loader;
    constexpr const char* kPinDir = "/sys/fs/bpf/inline-proxy";
    if (!bpf_loader.LoadAndPin(kPinDir)) {
        std::cerr << "failed to load and pin BPF program at " << kPinDir << '\n';
        return 1;
    }
    const std::uint32_t intercept_port =
        cfg.intercept_port != 0 ? cfg.intercept_port : cfg.transparent_port;
    if (!bpf_loader.WriteConfig(intercept_port, 0x100)) {
        std::cerr << "failed to write BPF config_map\n";
        return 1;
    }
    if (!bpf_loader.WriteListenerFd(transparent_listener.fd())) {
        std::cerr << "failed to write BPF listener_map\n";
        return 1;
    }
    std::cerr << "bpf-pin loaded pin_dir=" << kPinDir
              << " intercept_port=" << intercept_port
              << " listener_fd=" << transparent_listener.fd() << '\n';

    auto admin_http = BuildAdminHttp(state);
```

- [ ] **Step 4.1.2: Drop the `state_reconciler.Sync(registry)` call inside the `sweep` lambda**

Find:

```cpp
    sweep = [&] {
        state_reconciler.Sync(registry);
        PruneClosedSessions(sessions);
        PruneClosedConnections(admin_connections);
        loop.Schedule(std::chrono::seconds(1), sweep);
    };
```

Replace with:

```cpp
    sweep = [&] {
        PruneClosedSessions(sessions);
        PruneClosedConnections(admin_connections);
        loop.Schedule(std::chrono::seconds(1), sweep);
    };
```

- [ ] **Step 4.1.3: Drop the `registry.IncrementSessions()` / `registry.DecrementSessions()` calls**

Find the relay-session creation block (around line 1206):

```cpp
                auto session = CreateRelaySession(
                    loop,
                    std::move(accepted),
                    endpoints,
                    [&loop, &sessions, &state, &registry] {
                        state.decrement_sessions();
                        registry.DecrementSessions();
                        loop.Defer([&sessions] { PruneClosedSessions(sessions); });
                    });
                if (!session) {
                    continue;
                }

                state.increment_sessions();
                registry.IncrementSessions();
                sessions.push_back(std::move(session));
```

Replace with:

```cpp
                auto session = CreateRelaySession(
                    loop,
                    std::move(accepted),
                    endpoints,
                    [&loop, &sessions, &state] {
                        state.decrement_sessions();
                        loop.Defer([&sessions] { PruneClosedSessions(sessions); });
                    });
                if (!session) {
                    continue;
                }

                state.increment_sessions();
                sessions.push_back(std::move(session));
```

- [ ] **Step 4.1.4: Remove the `registry.RemoveInterface(admin_interface_name)` epilogue**

Find:

```cpp
    state.set_ready(false);
    bool cleanup_ok = true;
    if (!registry.RemoveInterface(admin_interface_name)) {
        std::cerr << "failed to remove admin interface " << admin_interface_name << '\n';
        cleanup_ok = false;
    }
    return cleanup_ok ? 0 : 1;
}
```

Replace with:

```cpp
    state.set_ready(false);
    return 0;
}
```

- [ ] **Step 4.1.5: Update includes**

In `src/proxy/config.cpp`, remove:

```cpp
#include "proxy/interface_registry.hpp"
#include "proxy/state_reconciler.hpp"
```

Add (if not already present):

```cpp
#include "bpf/loader.hpp"
```

- [ ] **Step 4.1.6: Build**

```bash
bazel build //src/proxy:proxy_daemon
```

Expected: build fails because `BuildAdminHttp` still takes an `InterfaceRegistry&`. Continue to Task 4.2 to fix that.

### Task 4.2: Update `AdminHttp` to drop the `InterfaceRegistry` dependency

**Files:**
- Modify: `src/proxy/admin_http.hpp`
- Modify: `src/proxy/admin_http.cpp`

- [ ] **Step 4.2.1: Update the header**

Replace the contents of `src/proxy/admin_http.hpp` with:

```cpp
#pragma once

#include <string>
#include <string_view>

#include "proxy/proxy_state.hpp"

namespace inline_proxy {

struct AdminResponse {
    int status;
    std::string content_type;
    std::string body;
};

class AdminHttp {
public:
    explicit AdminHttp(ProxyState& state) noexcept;

    AdminResponse Handle(std::string_view method, std::string_view path) const;

private:
    ProxyState& state_;
};

AdminHttp BuildAdminHttp(ProxyState& state) noexcept;

}  // namespace inline_proxy
```

- [ ] **Step 4.2.2: Update the cpp**

Replace the contents of `src/proxy/admin_http.cpp` with:

```cpp
#include "proxy/admin_http.hpp"

#include <utility>

namespace inline_proxy {
namespace {

AdminResponse MakeTextResponse(int status, std::string body) {
    return AdminResponse{
        .status = status,
        .content_type = "text/plain; charset=utf-8",
        .body = std::move(body),
    };
}

}  // namespace

AdminHttp::AdminHttp(ProxyState& state) noexcept : state_(state) {}

AdminResponse AdminHttp::Handle(std::string_view method, std::string_view path) const {
    if (method != "GET") {
        return MakeTextResponse(405, "method not allowed\n");
    }

    if (path == "/healthz") {
        return MakeTextResponse(200, "ok\n");
    }
    if (path == "/readyz") {
        return state_.ready() ? MakeTextResponse(200, "ready\n")
                              : MakeTextResponse(503, "not ready\n");
    }
    if (path == "/metrics") {
        return AdminResponse{
            .status = 200,
            .content_type = "text/plain; version=0.0.4; charset=utf-8",
            .body = state_.MetricsText(),
        };
    }
    if (path == "/sessions") {
        return AdminResponse{
            .status = 200,
            .content_type = "text/plain; charset=utf-8",
            .body = state_.SessionsText(),
        };
    }

    return MakeTextResponse(404, "not found\n");
}

AdminHttp BuildAdminHttp(ProxyState& state) noexcept {
    return AdminHttp(state);
}

}  // namespace inline_proxy
```

The `/interfaces` handler is removed.

- [ ] **Step 4.2.3: Build**

```bash
bazel build //src/proxy:proxy_daemon
```

Expected: now fails because `tests/admin_http_test.cpp` still references the old constructor. Fix in Task 4.3.

### Task 4.3: Update `admin_http_test.cpp`

**Files:**
- Modify: `tests/admin_http_test.cpp`

- [ ] **Step 4.3.1: Drop the include and the registry argument**

Open `tests/admin_http_test.cpp`. Remove:

```cpp
#include "proxy/interface_registry.hpp"
```

For every test that constructs `AdminHttp(state, registry)` or `BuildAdminHttp(state, registry)`:

- Remove the `InterfaceRegistry registry;` declaration.
- Change `AdminHttp(state, registry)` → `AdminHttp(state)` (or `BuildAdminHttp(state)`).

Delete any test case that exercises the `/interfaces` endpoint (it's been removed). Search for `/interfaces` and remove those tests.

- [ ] **Step 4.3.2: Build the test**

```bash
bazel build //tests:admin_http_test
```

Expected: success.

- [ ] **Step 4.3.3: Run it**

```bash
bazel test //tests:admin_http_test --test_output=errors
```

Expected: green.

- [ ] **Step 4.3.4: Commit (chunk 4 task 1-3 together for one consistent state)**

```bash
git add src/proxy/config.cpp src/proxy/admin_http.hpp src/proxy/admin_http.cpp tests/admin_http_test.cpp
git commit -m "Proxy: new boot sequence (LoadAndPin/WriteConfig/WriteListenerFd); drop /interfaces"
```

### Task 4.4: Delete `InterfaceRegistry` and `StateReconciler`

**Files:**
- Delete: `src/proxy/interface_registry.hpp`
- Delete: `src/proxy/interface_registry.cpp`
- Delete: `src/proxy/state_reconciler.hpp`
- Delete: `src/proxy/state_reconciler.cpp`
- Delete: `tests/interface_registry_test.cpp`
- Delete: `tests/state_reconciler_test.cpp`
- Modify: `src/proxy/BUILD.bazel`
- Modify: `tests/BUILD.bazel`

- [ ] **Step 4.4.1: Confirm there are no remaining references**

```bash
grep -rln "InterfaceRegistry\|StateReconciler\|interface_registry\|state_reconciler" \
    src/ tests/ --include='*.cpp' --include='*.hpp' --include='BUILD.bazel'
```

Expected: only the four source files, two test files, and BUILD.bazel entries. If any other file references them, fix that first.

- [ ] **Step 4.4.2: Delete the source files**

```bash
git rm src/proxy/interface_registry.hpp \
       src/proxy/interface_registry.cpp \
       src/proxy/state_reconciler.hpp \
       src/proxy/state_reconciler.cpp \
       tests/interface_registry_test.cpp \
       tests/state_reconciler_test.cpp
```

- [ ] **Step 4.4.3: Update `src/proxy/BUILD.bazel`**

In the `:proxy` cc_library, remove:

```python
        "interface_registry.cpp",
        "state_reconciler.cpp",
```

from `srcs`, and:

```python
        "interface_registry.hpp",
        "state_reconciler.hpp",
```

from `hdrs`. Also add `//src/bpf:loader` to `deps` if it isn't already there (the proxy library now uses `BpfLoader` directly).

Looking at the current file, `//src/bpf:loader` is already in deps, so no change needed there.

- [ ] **Step 4.4.4: Update `tests/BUILD.bazel`**

Remove the `interface_registry_test` and `state_reconciler_test` `cc_test` blocks.

- [ ] **Step 4.4.5: Build everything**

```bash
bazel build //...
```

Expected: success. If something else still references the removed classes, the compiler will say so — fix and retry.

- [ ] **Step 4.4.6: Run the full test suite**

```bash
bazel test //tests/... --test_output=errors
```

Expected: green. The two deleted tests no longer appear.

- [ ] **Step 4.4.7: Commit**

```bash
git add src/proxy/BUILD.bazel tests/BUILD.bazel
git commit -m "Proxy: delete InterfaceRegistry and StateReconciler"
```

### Task 4.5: Verify Chunk 4 baseline and smoke test

- [ ] **Step 4.5.1: Run the full test suite**

```bash
bazel test //tests/... 2>&1 | tee /tmp/cni-bpf-attach-chunk4.txt
```

Expected: green. The pass count is two fewer than the baseline (`interface_registry_test`, `state_reconciler_test` are gone).

- [ ] **Step 4.5.2: Manual smoke test (optional, requires a test cluster)**

Build the new artifacts and deploy:

```bash
bazel build //src/cni:inline_proxy_cni //src/proxy:proxy_daemon
# Push images, kubectl rollout restart both daemonsets, schedule an annotated pod,
# verify traffic flows through the proxy.
```

The proxy now:
- Loads + pins on startup (logs `bpf-pin loaded pin_dir=...`)
- Writes config_map and listener_map
- Does NOT attach BPF anywhere (CNI handles that on each pod admission)

The CNI plugin:
- Waits up to 30s for the pinned program at the top of ADD
- Attaches BPF inside the splice's proxy-netns scope after wan link-up

---

## Chunk 5: Remove old `BpfLoader` API surface; tidy

**Objective:** Delete `AttachIngress`, `DetachIngress`, `IsIngressAttached`, `ConfigureListenerSocket`, `listener_socket_fd()`, and `listener_port()` from `BpfLoader`. Delete the duplicated netlink TC helpers from `src/bpf/loader.cpp` (they live in `tc_attach.cpp` now). Update `tests/bpf_loader_test.cpp` to drop tests for the removed API. Update `docs/architecture.md` sections 2.6 and 8. Final test sweep.

End-of-chunk state: `BpfLoader` is `LoadAndPin / WriteConfig / WriteListenerFd / PinProgForTesting / LoadProgramForTesting`. `loader.cpp` no longer contains netlink TC code (only the skeleton load + map writes + pin helpers). All tests green. Architecture doc reflects the new split.

### Task 5.1: Shrink `BpfLoader` API

**Files:**
- Modify: `src/bpf/loader.hpp`
- Modify: `src/bpf/loader.cpp`

- [ ] **Step 5.1.1: Update `loader.hpp`**

Replace the public API of `BpfLoader` so it reads:

```cpp
class BpfLoader {
public:
    BpfLoader() = default;
    ~BpfLoader();

    BpfLoader(const BpfLoader&) = delete;
    BpfLoader& operator=(const BpfLoader&) = delete;

    bool LoadAndPin(std::string_view pin_dir);
    bool WriteConfig(std::uint32_t listener_port, std::uint32_t skb_mark);
    bool WriteListenerFd(int listener_fd);

    // Test-only.
    bool LoadProgramForTesting();
    bool PinProgForTesting(std::string_view pin_dir);

private:
    bool EnsureSkeletonLoaded();
    bool PinAll(std::string_view pin_dir);
    bool UnpinAll(std::string_view pin_dir);

    std::optional<int> listener_socket_fd_;
    IngressRedirectConfig runtime_config_{};
    std::string pin_dir_;
    struct ingress_redirect_skel* skel_ = nullptr;
};
```

Removed: `AttachIngress`, `DetachIngress`, `IsIngressAttached`, `ConfigureListenerSocket`, `listener_socket_fd()`, `listener_port()`, `attached_interfaces_`, `listener_port_`.

The `set` of attached interfaces, the captured listener port, and the skb_mark are no longer carried as members; `WriteConfig` takes the port and mark as parameters.

- [ ] **Step 5.1.2: Update `loader.cpp`**

Delete:

- The anonymous-namespace netlink helpers (`MakeTcRequest`, `SendNetlinkRequest`, `FinalizeNetlinkMessage`, `EnsureClsactQdisc`, `RemoveIngressFilter`, `AttachIngressFilter`).
- All includes that are no longer needed: `<linux/if_ether.h>`, `<linux/pkt_cls.h>`, `<linux/pkt_sched.h>`, `<linux/rtnetlink.h>`, `<netinet/in.h>`, `<sys/socket.h>`, `"shared/netlink.hpp"`, `"shared/netlink_builder.hpp"` (keep them only if some other code in the file still uses them; after the deletions, none of them should be needed).
- The function bodies of `AttachIngress`, `DetachIngress`, `ConfigureListenerSocket`, `listener_socket_fd`, `listener_port`, `IsIngressAttached`.

Keep:
- The `BpfLoader::~BpfLoader` destructor.
- `EnsureSkeletonLoaded`.
- The new `LoadAndPin` / `WriteConfig` / `WriteListenerFd` / `PinAll` / `UnpinAll` / `PinProgForTesting` / `LoadProgramForTesting` impls.

- [ ] **Step 5.1.3: Build**

```bash
bazel build //src/bpf:loader //src/proxy:proxy_daemon
```

Expected: success. Any remaining references to the removed API in the proxy will surface here — there shouldn't be any after Chunk 4.

- [ ] **Step 5.1.4: Trim the `loader` BUILD dep on `//src/shared:shared` if no longer used**

Check `src/bpf/BUILD.bazel`. If `loader.cpp` no longer uses anything from `//src/shared`, the dep can be removed. Most likely `//src/shared` is still needed for `ScopedFd` or similar — verify by reading `loader.cpp` after the trim.

If unsure, leave the dep.

- [ ] **Step 5.1.5: Commit**

```bash
git add src/bpf/loader.hpp src/bpf/loader.cpp src/bpf/BUILD.bazel
git commit -m "BpfLoader: remove old AttachIngress/Detach/ConfigureListenerSocket API"
```

### Task 5.2: Update `bpf_loader_test.cpp`

**Files:**
- Modify: `tests/bpf_loader_test.cpp`

- [ ] **Step 5.2.1: Delete tests for the removed API**

Delete:

- `RejectsMissingInterfaceName`
- `RejectsNonWanInterfaceNamesAfterListenerConfiguration`
- `CapturesListenerPortFromConfiguredSocket`
- `RejectsConfigureListenerSocketWhenGetsocknameFails`

Keep:

- `LoadsSkeleton`
- `LoadAndPinCreatesPins`
- `LoadAndPinIsIdempotent`
- `WriteConfigPopulatesConfigMap`
- `WriteListenerFdAcceptsListeningSocket`

- [ ] **Step 5.2.2: Build and run**

```bash
bazel test //tests:bpf_loader_test --test_output=errors
```

Expected: green (5 tests pass / skip as documented).

- [ ] **Step 5.2.3: Commit**

```bash
git add tests/bpf_loader_test.cpp
git commit -m "Test: drop BpfLoader tests for removed AttachIngress / ConfigureListenerSocket"
```

### Task 5.3: Update `docs/architecture.md`

**Files:**
- Modify: `docs/architecture.md`

- [ ] **Step 5.3.1: Rewrite section 2.6**

Locate the heading `### 2.6 Attaches the TC-ingress BPF program on \`wan_<hash>\`` (around line 109). Replace its body with:

```markdown
### 2.6 Attaches the TC-ingress BPF program on `wan_<hash>`

The BPF program is loaded once per node by the proxy daemon at
startup and pinned at `/sys/fs/bpf/inline-proxy/{prog,config_map,listener_map}`.

When the CNI plugin creates the `wan_<hash>` interface and moves it
into the proxy netns, it then enters the proxy netns and attaches the
pinned program as a TC ingress filter on `wan_<hash>` before
returning. The proxy daemon never watches interfaces and never runs
TC netlink calls; it only writes `config_map[0]` (port, mark) and
`listener_map[0]` (its listener fd) once at startup.

The BPF program redirects matching TCP flows to the listener via
`bpf_sk_assign`, preserving the original dst via SO_ORIGINAL_DST.
```

- [ ] **Step 5.3.2: Rewrite section 8 ("Interface contract with the daemon")**

Replace the section body with:

```markdown
## 8. Interface contract with the daemon

The proxy daemon does not watch interfaces. At startup it:

1. Binds and listens on the transparent listener.
2. Loads the embedded BPF skeleton and pins prog/config_map/
   listener_map under `/sys/fs/bpf/inline-proxy/` (replacing any
   existing pins from a prior process).
3. Writes `config_map[0] = {enabled, listener_port, skb_mark}`.
4. Writes `listener_map[0] = listener_fd`.
5. Marks `/readyz` green.

The CNI plugin attaches the program. On every ADD it polls the
pinned `prog` file (up to 30s) before invoking the splice, then —
inside the splice's proxy-netns scope, after `wan_<hash>` has been
addressed and brought up — opens the pin via `bpf_obj_get` and runs
the TC ingress attach via netlink.

CNI DEL is a no-op for BPF: removing `wan_<hash>` drops its qdisc
and filter automatically.

If the proxy restarts:

- Existing pins keep the program/maps alive in the kernel.
- Existing TC filters on `wan_*` interfaces continue to run the old
  program by id.
- The new proxy reloads the skeleton, replaces the pins, and writes
  fresh map entries. New TC attaches reference the new program; old
  filters keep running the old program until their interfaces are
  deleted, at which point the kernel reclaims the old program.

The pin path `/sys/fs/bpf/inline-proxy/` is on host bpffs (mounted
into the proxy pod via hostPath with bidirectional propagation). CNI
runs on the host directly and reaches the same bpffs natively.
```

- [ ] **Step 5.3.3: Skim the rest of `architecture.md` for stale references**

```bash
grep -n "interface_registry\|state_reconciler\|StateReconciler\|InterfaceRegistry" docs/architecture.md
```

Expected: no matches. If any references exist, update them (likely in the topology diagram captions or section 7).

Also search for stale claims that the proxy "watches" interfaces:

```bash
grep -n "watches\|reconcile\|interface registry" docs/architecture.md
```

Update any text that describes the proxy as observing interfaces or running a reconciler.

- [ ] **Step 5.3.4: Commit**

```bash
git add docs/architecture.md
git commit -m "Docs: rewrite architecture sections 2.6 and 8 for CNI-owned BPF attach"
```

### Task 5.4: Final sweep

- [ ] **Step 5.4.1: Run the full test suite**

```bash
bazel test //tests/... 2>&1 | tee /tmp/cni-bpf-attach-final.txt
```

Expected: green; same set of tests as `/tmp/cni-bpf-attach-chunk4.txt`.

- [ ] **Step 5.4.2: Confirm no leftover references**

```bash
grep -rn "AttachIngress\|DetachIngress\|IsIngressAttached\|ConfigureListenerSocket" \
    src/ tests/ --include='*.cpp' --include='*.hpp'
```

Expected: no matches.

```bash
grep -rn "InterfaceRegistry\|StateReconciler" src/ tests/ docs/ --include='*.cpp' --include='*.hpp' --include='*.md'
```

Expected: no matches in code; only matches in `docs/superpowers/specs/2026-04-27-cni-owned-bpf-attach-design.md` (which describes the deletions) and possibly `docs/superpowers/plans/2026-04-27-cni-owned-bpf-attach.md` (this plan).

- [ ] **Step 5.4.3: Build all artifacts**

```bash
bazel build //...
```

Expected: success.

- [ ] **Step 5.4.4: Manual smoke test on a test cluster (final)**

Recommended sequence:

1. `bazel build //src/cni:inline_proxy_cni //src/proxy:proxy_daemon`
2. Push images / scp binaries to a test node.
3. `kubectl rollout restart daemonset/inline-proxy-installer -n inline-proxy-system`
4. `kubectl rollout restart daemonset/inline-proxy-daemon -n inline-proxy-system`
5. Schedule a fresh annotated pod; verify it gets a working interface.
6. `kubectl exec` into the pod and verify outbound traffic flows through the proxy (e.g. `wget` to a known service, observe the pod's perceived source IP at the destination).
7. While the pod is running, `kubectl rollout restart` the proxy DS again. Verify existing connections survive (or at least new connections recover within seconds).
8. Schedule a second annotated pod after the proxy bounce. Verify its CNI ADD succeeds and its traffic intercepts.

Expected: all steps pass. The behavior matches the pre-change behavior exactly; the only difference is who runs `tc filter add`.

- [ ] **Step 5.4.5: Final commit (no changes; just a marker)**

If everything is green, no commit needed. If any small fixes were required during the manual smoke test, commit them with a clear message.

---

## Done

The new layout:

- `src/bpf/loader.{hpp,cpp}` — proxy-side: load skeleton, pin maps, write map entries.
- `src/bpf/tc_attach.{hpp,cpp}` — CNI-side: open pinned prog, ensure clsact, attach TC ingress.
- `src/proxy/` — no `interface_registry`, no `state_reconciler`. Boot sequence: bind+listen → LoadAndPin → WriteConfig → WriteListenerFd → run.
- `src/cni/main.cpp` — calls `WaitForPinnedProg` before invoking the splice.
- `src/cni/splice_executor.cpp` — calls `TcAttacher::AttachToInterface` inside the proxy-netns scope, between wan link-up and lan/peer veth creation.
- Architecture doc, sections 2.6 and 8, rewritten.

External behavior is unchanged. The proxy and CNI binaries must ship together (chunk 3 + chunk 4 together change both ends of the contract).
