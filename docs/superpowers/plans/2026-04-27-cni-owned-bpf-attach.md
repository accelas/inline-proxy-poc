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

### Task 1.5: Verify Chunk 1 baseline

- [ ] **Step 1.5.1: Run the full test suite**

```bash
bazel test //tests/... 2>&1 | tee /tmp/cni-bpf-attach-chunk1.txt
```

Expected: same pass/fail set as `/tmp/cni-bpf-attach-baseline.txt` plus the two new `bpf_attacher_test` cases (both passing). No regression in any other test.

End-to-end TC-attach coverage is deferred to the existing `ebpf_intercept_fd_netns_test`, which gets exercised in Chunks 4-5 once the `fd_netns_harness` is rewritten to drive the new `BpfLoader` API.

- [ ] **Step 1.5.2: If any pre-existing test regressed, stop and diagnose. Do not proceed to Chunk 2.**

---

## Chunk 2: New `BpfLoader` API alongside the old

**Objective:** Add `LoadAndPin / WriteConfig / WriteListenerFd` to `BpfLoader` without removing `AttachIngress / DetachIngress / IsIngressAttached / ConfigureListenerSocket`. Implement tag-match reuse on existing pins (required for correctness — see Decisions §5 in the spec). Add a small `PinProgForTesting` helper used by the chunk-1 integration test. Tests cover the new API; the old API and its tests stay green.

**Why tag-match reuse is correctness-critical, not optimization:** On a proxy restart, already-attached TC filters on `wan_*` interfaces still reference the *old* program by kernel id. The old program reads the *old* config_map and listener_map (kernel-side references baked in at load time). If we replace pins with new maps, the new proxy writes its new listener fd into the *new* listener_map — but the old TC filters read the *old* listener_map, which holds the dead-fd entry. Sockmap auto-removes closed fds, so the old listener_map[0] is empty; lookups return NULL; existing pods stop being intercepted, indefinitely. Reusing the existing pinned maps when tags match means the new proxy writes into the same map the old filters read, restoring interception.

End-of-chunk state: `bazel test //tests:bpf_loader_test //tests:bpf_attacher_test //tests/...` passes; both old and new BpfLoader methods are callable; the chunk-1 `AttachesIngressFilterAgainstDummyInterface` test now passes (no longer skips on root).

### Task 2.1: Extend `BpfLoader` header

**Files:**
- Modify: `src/bpf/loader.hpp`

The post-Chunk-2 internal model:

- `LoadAndPin` ends with `config_map_fd_` and `listener_map_fd_` populated as raw fds (whether opened from existing pins on tag-match, or freshly loaded+pinned on first-time / tag-mismatch).
- The libbpf skeleton (`skel_`) is destroyed at the end of `LoadAndPin` regardless of path, because the pins keep the prog/maps alive in the kernel and the raw map fds are independent refs.
- `WriteConfig` and `WriteListenerFd` use raw `bpf(BPF_MAP_UPDATE_ELEM, ...)` syscalls (or libbpf's thin `bpf_map_update_elem` wrapper) on the stored map fds — never go through `skel_->maps.*`.

This shape is uniform across all three paths (no-existing-pin, tag-match, tag-mismatch) and lets us keep `BpfLoader`'s lifetime simple.

- [ ] **Step 2.1.1: Add the new public methods**

Insert into the public section of `BpfLoader` (between `LoadProgramForTesting` and the `private:` line):

```cpp
    // New API (replaces AttachIngress + ConfigureListenerSocket).
    //
    // Idempotent. If pins already exist at <pin_dir> and the pinned
    // program's tag matches the embedded program's tag, reuses the
    // existing pinned objects without relinking (so already-attached
    // TC filters keep firing the same program and reading the same
    // maps we now write to). Otherwise loads the embedded skeleton,
    // unlinks any stale pins, and pins the fresh program/maps.
    //
    // After a successful return: <pin_dir>/prog, <pin_dir>/config_map,
    // and <pin_dir>/listener_map exist; this->config_map_fd_ and
    // this->listener_map_fd_ hold raw fds usable for map writes.
    bool LoadAndPin(std::string_view pin_dir);

    // Writes config_map[0] = {enabled=1, listener_port, skb_mark}
    // via raw bpf_map_update_elem on config_map_fd_. Safe to call
    // repeatedly. Requires LoadAndPin to have succeeded.
    bool WriteConfig(std::uint32_t listener_port, std::uint32_t skb_mark);

    // Writes listener_map[0] = listener_fd via raw bpf_map_update_elem
    // on listener_map_fd_. The fd must refer to a TCP socket in the
    // LISTEN state at the moment of update; the kernel rejects
    // sockmap inserts of non-listening sockets.
    bool WriteListenerFd(int listener_fd);

    // Test-only: pin the loaded prog at <pin_dir>/prog. Used by the
    // tc_attach integration test (no maps pinned, no tag check).
    bool PinProgForTesting(std::string_view pin_dir);
```

- [ ] **Step 2.1.2: Add the private helpers and members**

Replace the existing `private:` section of `BpfLoader` with:

```cpp
private:
    bool EnsureSkeletonLoaded();

    // Returns the prog tag for an open prog fd, or nullopt on syscall
    // failure. The tag is bpf_prog_info::tag, an 8-byte SHA1 prefix
    // over the program's verifier IR.
    static std::optional<std::array<std::uint8_t, 8>> ProgTag(int prog_fd);

    // Tag-match path: open existing pinned prog/maps, store map fds,
    // close prog fd (the pin keeps prog alive). Returns true on
    // tag-match success; false on any failure (caller falls back to
    // load+pin).
    bool TryReuseExistingPin(std::string_view pin_dir,
                             const std::array<std::uint8_t, 8>& fresh_tag);

    // Load+pin path: unlink any stale pins, pin the freshly-loaded
    // skel.prog/skel.maps under pin_dir, store map fds.
    bool PinFresh(std::string_view pin_dir);

    // Best-effort unlink of <pin_dir>/{prog,config_map,listener_map}.
    static void UnlinkAllPins(std::string_view pin_dir);

    ScopedFd config_map_fd_;
    ScopedFd listener_map_fd_;
    std::string pin_dir_;
    struct ingress_redirect_skel* skel_ = nullptr;

    // Legacy fields kept until Chunk 5 to preserve the old API:
    std::set<std::string> attached_interfaces_;
    std::optional<int> listener_socket_fd_;
    std::uint32_t listener_port_ = 0;
    IngressRedirectConfig runtime_config_{};
};
```

Add `#include <array>` and `#include <optional>` to the top of `loader.hpp` if not already present.

- [ ] **Step 2.1.3: Verify the header still compiles**

```bash
bazel build //src/bpf:loader
```

Expected: success — the bodies don't exist yet, but the declarations are syntactically valid (`ScopedFd` is in `<shared/scoped_fd.hpp>` which is already included).

- [ ] **Step 2.1.4: Commit**

```bash
git add src/bpf/loader.hpp
git commit -m "BpfLoader: declare LoadAndPin/WriteConfig/WriteListenerFd + tag-match helpers"
```

### Task 2.2: Implement the helpers — pin/unpin/tag

**Files:**
- Modify: `src/bpf/loader.cpp`

- [ ] **Step 2.2.1: Add includes**

Near the top of `loader.cpp`, ensure these are present:

```cpp
#include <array>
#include <filesystem>
#include <sys/stat.h>
```

- [ ] **Step 2.2.2: Add the pin/unpin/tag helpers inside the impl section**

Append to `loader.cpp` (before the closing `}  // namespace inline_proxy`):

```cpp
namespace {

bool MakeDirRecursive(std::string_view path) {
    std::error_code ec;
    std::filesystem::create_directories(std::string(path), ec);
    return !ec;
}

}  // namespace

void BpfLoader::UnlinkAllPins(std::string_view pin_dir) {
    const std::string dir(pin_dir);
    for (const char* name : {"prog", "config_map", "listener_map"}) {
        const std::string path = dir + "/" + name;
        if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
            std::cerr << "BpfLoader::UnlinkAllPins unlink failed path=" << path
                      << " errno=" << errno << '\n';
        }
    }
}

std::optional<std::array<std::uint8_t, 8>> BpfLoader::ProgTag(int prog_fd) {
    struct bpf_prog_info info{};
    std::memset(&info, 0, sizeof(info));
    std::uint32_t info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0) {
        std::cerr << "bpf_obj_get_info_by_fd failed errno=" << errno << '\n';
        return std::nullopt;
    }
    std::array<std::uint8_t, 8> tag{};
    static_assert(sizeof(info.tag) == tag.size(),
                  "bpf_prog_info::tag size mismatch");
    std::memcpy(tag.data(), info.tag, tag.size());
    return tag;
}

bool BpfLoader::PinFresh(std::string_view pin_dir) {
    if (skel_ == nullptr) return false;
    const std::string dir(pin_dir);

    UnlinkAllPins(pin_dir);

    auto pin_one = [&](const std::string& name, int fd) -> bool {
        const std::string path = dir + "/" + name;
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

    // Open the just-pinned maps as raw fds so future writes don't
    // depend on skel staying alive.
    auto bpf_obj_get_path = [](const std::string& path) -> int {
        union bpf_attr a{};
        std::memset(&a, 0, sizeof(a));
        a.pathname = reinterpret_cast<std::uint64_t>(path.c_str());
        return static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &a, sizeof(a)));
    };

    int new_cfg_fd = bpf_obj_get_path(dir + "/config_map");
    if (new_cfg_fd < 0) {
        std::cerr << "bpf_obj_get(config_map) failed errno=" << errno << '\n';
        return false;
    }
    int new_listener_fd = bpf_obj_get_path(dir + "/listener_map");
    if (new_listener_fd < 0) {
        std::cerr << "bpf_obj_get(listener_map) failed errno=" << errno << '\n';
        ::close(new_cfg_fd);
        return false;
    }

    config_map_fd_ = ScopedFd(new_cfg_fd);
    listener_map_fd_ = ScopedFd(new_listener_fd);
    return true;
}

bool BpfLoader::TryReuseExistingPin(
    std::string_view pin_dir,
    const std::array<std::uint8_t, 8>& fresh_tag) {
    const std::string dir(pin_dir);
    const std::string prog_path = dir + "/prog";
    const std::string config_path = dir + "/config_map";
    const std::string listener_path = dir + "/listener_map";

    auto bpf_obj_get_path = [](const std::string& path) -> int {
        union bpf_attr a{};
        std::memset(&a, 0, sizeof(a));
        a.pathname = reinterpret_cast<std::uint64_t>(path.c_str());
        return static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &a, sizeof(a)));
    };

    const int existing_prog_fd = bpf_obj_get_path(prog_path);
    if (existing_prog_fd < 0) {
        // No existing pin (ENOENT) is the common first-boot case.
        return false;
    }
    auto existing_tag = ProgTag(existing_prog_fd);
    ::close(existing_prog_fd);
    if (!existing_tag) return false;
    if (*existing_tag != fresh_tag) {
        std::cerr << "BpfLoader: tag mismatch on existing pin; will replace\n";
        return false;
    }

    int cfg_fd = bpf_obj_get_path(config_path);
    if (cfg_fd < 0) return false;
    int listener_fd = bpf_obj_get_path(listener_path);
    if (listener_fd < 0) {
        ::close(cfg_fd);
        return false;
    }

    config_map_fd_ = ScopedFd(cfg_fd);
    listener_map_fd_ = ScopedFd(listener_fd);
    std::cerr << "BpfLoader: tag match; reusing existing pin at " << dir << '\n';
    return true;
}
```

- [ ] **Step 2.2.3: Build**

```bash
bazel build //src/bpf:loader
```

Expected: build succeeds. (The new helpers are unused in this step — `LoadAndPin` is implemented in the next task and exercises them.)

- [ ] **Step 2.2.4: Commit**

```bash
git add src/bpf/loader.cpp
git commit -m "BpfLoader: add pin/unpin/tag helpers (private)"
```

### Task 2.3: Implement `LoadAndPin` / `WriteConfig` / `WriteListenerFd` / `PinProgForTesting`

**Files:**
- Modify: `src/bpf/loader.cpp`

- [ ] **Step 2.3.1: Implement the public API**

Append to `loader.cpp`:

```cpp
bool BpfLoader::LoadAndPin(std::string_view pin_dir) {
    if (!MakeDirRecursive(pin_dir)) {
        std::cerr << "LoadAndPin: mkdir " << pin_dir << " failed errno=" << errno << '\n';
        return false;
    }
    pin_dir_ = std::string(pin_dir);

    // Always load the skeleton so we know the embedded program's tag.
    // Loading is what assigns the tag (computed by the verifier).
    if (!EnsureSkeletonLoaded()) return false;

    const int fresh_prog_fd = bpf_program__fd(skel_->progs.ingress_redirect);
    auto fresh_tag = ProgTag(fresh_prog_fd);
    if (!fresh_tag) {
        std::cerr << "LoadAndPin: failed to query freshly-loaded prog tag\n";
        return false;
    }

    if (TryReuseExistingPin(pin_dir, *fresh_tag)) {
        // Reuse path: pinned prog/maps stay alive thanks to pins +
        // their kernel-side reference from already-attached TC filters.
        // Discard the just-loaded fresh prog/maps by tearing down the
        // skeleton; the kernel reclaims them since nothing else holds
        // refs.
        ingress_redirect_skel__destroy(skel_);
        skel_ = nullptr;
        return true;
    }

    // Either no existing pin, or tag mismatch: pin fresh.
    if (!PinFresh(pin_dir)) {
        ingress_redirect_skel__destroy(skel_);
        skel_ = nullptr;
        return false;
    }
    // Map fds are now held in config_map_fd_/listener_map_fd_; the
    // pinned prog and the pinned maps keep the kernel objects alive.
    // We can drop the skeleton.
    ingress_redirect_skel__destroy(skel_);
    skel_ = nullptr;
    return true;
}

bool BpfLoader::WriteConfig(std::uint32_t listener_port, std::uint32_t skb_mark) {
    if (config_map_fd_.get() < 0) {
        std::cerr << "WriteConfig: config_map_fd_ not initialised\n";
        return false;
    }
    IngressRedirectConfig cfg{};
    cfg.enabled = 1;
    cfg.listener_port = listener_port;
    cfg.skb_mark = skb_mark;
    runtime_config_ = cfg;

    const std::uint32_t key = 0;
    union bpf_attr a{};
    std::memset(&a, 0, sizeof(a));
    a.map_fd = static_cast<__u32>(config_map_fd_.get());
    a.key = reinterpret_cast<std::uint64_t>(&key);
    a.value = reinterpret_cast<std::uint64_t>(&cfg);
    a.flags = BPF_ANY;
    if (::syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &a, sizeof(a)) != 0) {
        std::cerr << "WriteConfig: BPF_MAP_UPDATE_ELEM failed errno=" << errno << '\n';
        return false;
    }
    return true;
}

bool BpfLoader::WriteListenerFd(int listener_fd) {
    if (listener_map_fd_.get() < 0 || listener_fd < 0) {
        std::cerr << "WriteListenerFd: invalid map fd or listener fd\n";
        return false;
    }
    const std::uint32_t key = 0;
    const std::uint32_t fd_value = static_cast<std::uint32_t>(listener_fd);
    union bpf_attr a{};
    std::memset(&a, 0, sizeof(a));
    a.map_fd = static_cast<__u32>(listener_map_fd_.get());
    a.key = reinterpret_cast<std::uint64_t>(&key);
    a.value = reinterpret_cast<std::uint64_t>(&fd_value);
    a.flags = BPF_ANY;
    if (::syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &a, sizeof(a)) != 0) {
        std::cerr << "WriteListenerFd: BPF_MAP_UPDATE_ELEM failed errno=" << errno << '\n';
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
    return bpf_obj_pin(bpf_program__fd(skel_->progs.ingress_redirect),
                       path.c_str()) == 0;
}
```

Add `#include <sys/syscall.h>` and `#include <linux/bpf.h>` to the top of `loader.cpp` if not already present.

- [ ] **Step 2.3.2: Build and run existing tests**

```bash
bazel build //src/bpf:loader
bazel test //tests:bpf_loader_test --test_output=errors
```

Expected: build succeeds; the four pre-existing tests still pass / skip as before. (The old tests don't exercise the new API.)

- [ ] **Step 2.3.3: Commit**

```bash
git add src/bpf/loader.cpp src/bpf/loader.hpp
git commit -m "BpfLoader: implement LoadAndPin (with tag-match reuse) + map writes"
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
        EXPECT_TRUE(loader.LoadAndPin(dir));
        EXPECT_TRUE(std::filesystem::exists(dir + "/prog"));
    }
    std::filesystem::remove_all(dir);
}

// Tag-match reuse: the second LoadAndPin should reuse the existing
// pinned prog (same prog id) because the embedded program tag is
// identical. Verified by reading bpf_prog_info::id before and after.
TEST(BpfLoaderTest, LoadAndPinReusesPinOnTagMatch) {
    if (::geteuid() != 0) GTEST_SKIP() << "Requires root / CAP_BPF";
    const auto dir = MakeTempPinDir();
    auto read_prog_id = [&](const std::string& prog_path) -> std::uint32_t {
        union bpf_attr a{};
        std::memset(&a, 0, sizeof(a));
        a.pathname = reinterpret_cast<__u64>(prog_path.c_str());
        int fd = static_cast<int>(::syscall(SYS_bpf, BPF_OBJ_GET, &a, sizeof(a)));
        if (fd < 0) return 0;
        struct bpf_prog_info info{};
        std::memset(&info, 0, sizeof(info));
        std::uint32_t info_len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
            ::close(fd);
            return 0;
        }
        ::close(fd);
        return info.id;
    };

    inline_proxy::BpfLoader first;
    ASSERT_TRUE(first.LoadAndPin(dir));
    const std::uint32_t first_id = read_prog_id(dir + "/prog");
    ASSERT_NE(first_id, 0u);

    inline_proxy::BpfLoader second;
    ASSERT_TRUE(second.LoadAndPin(dir));
    const std::uint32_t second_id = read_prog_id(dir + "/prog");
    EXPECT_EQ(first_id, second_id) << "tag-match reuse should keep prog id stable";
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
    IngressRedirectConfig cfg{};
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

Expected as root: 9 tests pass (4 old + 5 new). As non-root: the 5 new tests + the existing `LoadsSkeleton` test skip.

- [ ] **Step 2.4.3: Commit**

```bash
git add tests/bpf_loader_test.cpp
git commit -m "Test: BpfLoader::LoadAndPin / WriteConfig / WriteListenerFd"
```

### Task 2.5: Verify Chunk 2 baseline

- [ ] **Step 2.5.1: Run the full test suite**

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

- [ ] **Step 3.4.1: Enumerate affected tests**

Run:

```bash
grep -L "splice_runner" tests/splice_executor_*test.cpp tests/*splice*test.cpp 2>/dev/null
grep -l "splice_runner" tests/splice_executor_*test.cpp tests/*splice*test.cpp 2>/dev/null
```

The first command lists splice tests that **do not** use `splice_runner` — those exercise the real `ExecuteSplice` and will hit `TcAttacher::AttachToInterface`. The second lists tests that **do** use `splice_runner` and therefore short-circuit `ExecuteSplice` entirely; they don't need any change.

In the current tree the splice tests are: `splice_executor_test.cpp` (uses `splice_runner` — no change needed), `splice_executor_netns_test.cpp` (does not use `splice_runner` — needs the update in Step 3.4.2), `splice_plan_test.cpp` (no `CniExecutionOptions` — no change needed). Verify with the greps above; if the inventory has changed, treat the greps as authoritative.

`TcAttacher`'s methods are non-virtual, so tests can't substitute a stub by inheritance. Tests that need a no-op attacher must either: (a) use `splice_runner` to replace `ExecuteSplice` entirely, or (b) feed a real `TcAttacher` pointed at a temp dir with a pre-pinned prog (via `BpfLoader::PinProgForTesting`).

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

### Task 4.4: Rewrite `tests/fd_netns_harness.cpp` to use the new `BpfLoader` API

The harness builds an in-process proxy (single thread, single transparent listener) for end-to-end tests like `ebpf_intercept_fd_netns_test`. Its proxy thread currently uses `InterfaceRegistry::ConfigureIngressListener` + `RecordInterface(wan_ifname_)` to (a) attach BPF to the harness's wan interface and (b) push the listener fd into `listener_map`. With BPF attach moved out of the proxy, the harness needs to do its own attach + map writes.

**Files:**
- Modify: `tests/fd_netns_harness.cpp`
- Modify: `tests/fd_netns_harness.hpp` (drop the `interface_registry.hpp` include)
- Modify: `tests/BUILD.bazel` (the `fd_netns_harness` cc_library may need `//src/bpf:loader` and `//src/bpf:tc_attach` deps)

- [ ] **Step 4.4.1: Drop the `InterfaceRegistry` include from `fd_netns_harness.hpp`**

Open `tests/fd_netns_harness.hpp`, remove `#include "proxy/interface_registry.hpp"`. The header doesn't expose any registry-typed APIs — the include was an implementation detail leaked through the header.

- [ ] **Step 4.4.2: Replace the proxy-thread setup in `fd_netns_harness.cpp`**

Find the block in the proxy thread (around `fd_netns_harness.cpp:331-338`):

```cpp
        InterfaceRegistry registry;
        auto listener = CreateTransparentListener("0.0.0.0", kListenerPort);
        if (!listener || !registry.ConfigureIngressListener(listener.fd(), kDemoPort) ||
            !registry.RecordInterface(wan_ifname_)) {
            proxy_ready.set_value(false);
            proxy_done.set_value(false);
            return;
        }
```

Replace with:

```cpp
        // Pin BPF in this proxy netns; CNI side (TcAttacher) drives the
        // TC attach, which we do inline here since the harness has no
        // separate CNI process.
        const std::string pin_dir = "/sys/fs/bpf/fd-netns-harness-" +
                                    std::to_string(::getpid());
        std::filesystem::create_directories(pin_dir);

        BpfLoader bpf_loader;
        auto listener = CreateTransparentListener("0.0.0.0", kListenerPort);
        if (!listener ||
            ::listen(listener.fd(), 16) != 0 ||
            !bpf_loader.LoadAndPin(pin_dir) ||
            !bpf_loader.WriteConfig(kDemoPort, 0x100) ||
            !bpf_loader.WriteListenerFd(listener.fd())) {
            proxy_ready.set_value(false);
            proxy_done.set_value(false);
            return;
        }

        TcAttacher attacher(pin_dir);
        if (!attacher.WaitForPinnedProg(std::chrono::seconds(5)) ||
            !attacher.AttachToInterface(wan_ifname_)) {
            proxy_ready.set_value(false);
            proxy_done.set_value(false);
            return;
        }
```

Note: `CreateTransparentListener` may already call `listen()` on the fd it returns; check the existing definition. If it does, drop the explicit `::listen(listener.fd(), 16)` from the chain. If it doesn't, keep it — the sockmap insert in `WriteListenerFd` requires LISTEN state.

Add includes near the top of `fd_netns_harness.cpp`:

```cpp
#include <chrono>
#include <filesystem>
#include "bpf/loader.hpp"
#include "bpf/tc_attach.hpp"
```

Remove:

```cpp
#include "proxy/interface_registry.hpp"
```

- [ ] **Step 4.4.3: Update the `fd_netns_harness` BUILD entry**

In `tests/BUILD.bazel`, find the `fd_netns_harness` cc_library and add to its `deps`:

```python
        "//src/bpf:loader",
        "//src/bpf:tc_attach",
```

The dep on `//src/proxy:proxy` is unchanged (the harness still uses `CreateTransparentListener`, `CreateRelaySession`, `EventLoop` from there).

- [ ] **Step 4.4.4: Build the harness and its consumers**

```bash
bazel build //tests:fd_netns_harness //tests:ebpf_intercept_fd_netns_test
```

Expected: success. The harness is a fixture, not a test, so building it is enough; the test will run in Step 4.4.7.

- [ ] **Step 4.4.5: Commit**

```bash
git add tests/fd_netns_harness.hpp tests/fd_netns_harness.cpp tests/BUILD.bazel
git commit -m "Test harness: drop InterfaceRegistry; use BpfLoader+TcAttacher directly"
```

### Task 4.5: Delete `InterfaceRegistry` and `StateReconciler`

**Files:**
- Delete: `src/proxy/interface_registry.hpp`
- Delete: `src/proxy/interface_registry.cpp`
- Delete: `src/proxy/state_reconciler.hpp`
- Delete: `src/proxy/state_reconciler.cpp`
- Delete: `tests/interface_registry_test.cpp`
- Delete: `tests/state_reconciler_test.cpp`
- Modify: `src/proxy/BUILD.bazel`
- Modify: `tests/BUILD.bazel`

- [ ] **Step 4.5.1: Confirm there are no remaining references**

```bash
grep -rln "InterfaceRegistry\|StateReconciler\|interface_registry\|state_reconciler" \
    src/ tests/ --include='*.cpp' --include='*.hpp' --include='BUILD.bazel'
```

Expected: only the four source files, two test files, and BUILD.bazel entries. If any other file references them, fix that first.

- [ ] **Step 4.5.2: Delete the source files**

```bash
git rm src/proxy/interface_registry.hpp \
       src/proxy/interface_registry.cpp \
       src/proxy/state_reconciler.hpp \
       src/proxy/state_reconciler.cpp \
       tests/interface_registry_test.cpp \
       tests/state_reconciler_test.cpp
```

- [ ] **Step 4.5.3: Update `src/proxy/BUILD.bazel`**

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

- [ ] **Step 4.5.4: Update `tests/BUILD.bazel`**

Remove the `interface_registry_test` and `state_reconciler_test` `cc_test` blocks.

- [ ] **Step 4.5.5: Build everything**

```bash
bazel build //...
```

Expected: success. If something else still references the removed classes, the compiler will say so — fix and retry.

- [ ] **Step 4.5.6: Run the full test suite**

```bash
bazel test //tests/... --test_output=errors
```

Expected: green. The two deleted tests no longer appear.

- [ ] **Step 4.5.7: Commit**

```bash
git add src/proxy/BUILD.bazel tests/BUILD.bazel
git commit -m "Proxy: delete InterfaceRegistry and StateReconciler"
```

### Task 4.6: Verify Chunk 4 baseline and smoke test

- [ ] **Step 4.6.1: Run the full test suite**

```bash
bazel test //tests/... 2>&1 | tee /tmp/cni-bpf-attach-chunk4.txt
```

Expected: green. The pass count is two fewer than the baseline (`interface_registry_test`, `state_reconciler_test` are gone).

- [ ] **Step 4.6.2: Manual smoke test (optional, requires a test cluster)**

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

Replace the public API and private section of `BpfLoader` so it reads:

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
    static std::optional<std::array<std::uint8_t, 8>> ProgTag(int prog_fd);
    bool TryReuseExistingPin(std::string_view pin_dir,
                             const std::array<std::uint8_t, 8>& fresh_tag);
    bool PinFresh(std::string_view pin_dir);
    static void UnlinkAllPins(std::string_view pin_dir);

    ScopedFd config_map_fd_;
    ScopedFd listener_map_fd_;
    std::string pin_dir_;
    IngressRedirectConfig runtime_config_{};
    struct ingress_redirect_skel* skel_ = nullptr;
};
```

Removed (relative to Chunk 2's transitional state):
- Public: `AttachIngress`, `DetachIngress`, `IsIngressAttached`, `ConfigureListenerSocket`, `listener_socket_fd()`, `listener_port()`.
- Private members: `attached_interfaces_`, `listener_socket_fd_`, `listener_port_`.

The `runtime_config_` member is retained because `WriteConfig` records the last-written config there for the destructor's benefit (no observable behavior change). If the destructor doesn't use it, it can also be removed — verify by reading the destructor body.

- [ ] **Step 5.1.2: Update `loader.cpp`**

Delete:

- The anonymous-namespace netlink helpers (`MakeTcRequest`, `SendNetlinkRequest`, `FinalizeNetlinkMessage`, `EnsureClsactQdisc`, `RemoveIngressFilter`, `AttachIngressFilter`) — these were only ever used by the removed `AttachIngress` / `DetachIngress` methods, and `tc_attach.cpp` carries its own copy for CNI use.
- All includes that are no longer needed: `<linux/if_ether.h>`, `<linux/pkt_cls.h>`, `<linux/pkt_sched.h>`, `<linux/rtnetlink.h>`, `<netinet/in.h>`, `<sys/socket.h>`, `"shared/netlink.hpp"`, `"shared/netlink_builder.hpp"`. Keep `<sys/syscall.h>`, `<linux/bpf.h>`, `<bpf/bpf.h>` (for `bpf_obj_pin`, `bpf_obj_get_info_by_fd`, `bpf_program__fd`, `bpf_map__fd`), `<bpf/libbpf.h>` (for skeleton API), `<filesystem>`, `<sys/stat.h>` — all used by the new pin/map-write paths.
- The function bodies of `AttachIngress`, `DetachIngress`, `ConfigureListenerSocket`, `listener_socket_fd`, `listener_port`, `IsIngressAttached`.

Keep:
- The `BpfLoader::~BpfLoader` destructor (verify it doesn't reference removed members; if it does, simplify to a `default` body since `ScopedFd` and `unique_ptr`-style state already self-clean).
- `EnsureSkeletonLoaded` (still used by `LoadAndPin` and `PinProgForTesting`).
- All Chunk 2 helpers: `ProgTag`, `TryReuseExistingPin`, `PinFresh`, `UnlinkAllPins`.
- All Chunk 2 public methods: `LoadAndPin`, `WriteConfig`, `WriteListenerFd`, `PinProgForTesting`, `LoadProgramForTesting`.

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
