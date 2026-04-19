# BPF Loader Rewrite: Skeleton-Based Build and Load

Date: 2026-04-19
Status: approved design, ready for implementation planning

## Goal

Rewrite the inline proxy's BPF loader so that the TC ingress-redirect program is **written in C, compiled by clang, and loaded through a bpftool-generated skeleton** instead of hand-built `bpf_insn` arrays and raw `bpf()` syscalls.

This is a cleanup: **no external behavior changes**. The `BpfLoader` public API and the program's observable packet-processing behavior stay identical.

## Motivation

The current loader at `src/bpf/loader.cpp` contains roughly 400 lines of handwritten BPF instruction emission (`ProgramBuilder`, `MakeInsn`, `EmitTracePrintk*`, `BuildIngressProgram`) plus raw `SysBpf(BPF_MAP_CREATE)` / `BPF_PROG_LOAD` / `BPF_MAP_UPDATE_ELEM` calls. The handwritten `.bpf.c` source at `src/bpf/ingress_redirect.bpf.c` is stale and unused — it references a `redirect_ifindex` field that does not exist in `struct ingress_redirect_config`.

Replacing the builder with clang-compiled source and a libbpf skeleton:

- deletes the handwritten codegen entirely
- lets the C compiler own offset math, jump patching, and register allocation
- aligns with the standard modern libbpf workflow
- makes future BPF changes editable by anyone who reads C, not only those who read BPF assembly

## Scope

In scope:

- vendoring libbpf and bpftool as third-party sources
- a custom Bazel rule that compiles a `.bpf.c` and emits a skeleton header
- checking in a `vmlinux.h` for CO-RE
- a full rewrite of `src/bpf/ingress_redirect.bpf.c`
- a rewrite of `src/bpf/loader.cpp` internals with the public `BpfLoader` API unchanged
- adjusting tests: removing the two that are specific to the handwritten codegen; adding one skeleton-load sanity test

Out of scope:

- changing any behavior observable outside `BpfLoader` (packet handling, attach points, map contents)
- a hermetic clang toolchain (continue to use host `clang-19`)
- changes to the `proxy/`, `cni/`, or `shared/` subsystems
- any coordination with the pending router-style redesign (docs/superpowers/specs/2026-04-19-router-style-inline-proxy-design.md); this cleanup is independent of that redesign

## Decisions

### 1. Vendor libbpf and bpftool from source

Both land under `third_party/` with hand-written `BUILD.bazel` files, mirroring the existing yajl vendoring pattern. The root `MODULE.bazel` declares them with `version = "0.0.0"` and `local_path_override`.

Upstream versions pinned:

- **libbpf v1.5.0** — matches `libbpf1 1:1.5.0-3` installed on the development host, has all CO-RE APIs the skeleton uses.
- **bpftool v7.5.0** — paired with libbpf 1.5. bpftool's own source tree bundles libbpf as a submodule; we let bpftool use its bundled submodule for its own build rather than wiring it to our separately-vendored copy. Rationale: bpftool is a build-time tool that never ships to runtime, and this simplifies integrating its Makefile-driven build into Bazel.

libbpf is compiled as a **static archive** and linked statically into `proxy_daemon` so the deployed container image does not need a runtime `libbpf.so`.

### 2. One custom Bazel rule: `bpf_skeleton`

A single macro in `//bazel/bpf:defs.bzl`:

```python
bpf_skeleton(
    name = "ingress_redirect_skel",
    src = "ingress_redirect.bpf.c",
    hdrs = ["ingress_redirect_common.h", "vmlinux.h"],
)
```

Expands to:

1. **Compile step** (`genrule` invoking host `clang-19`):
   `clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -I<hdrs dir> -c $(SRC) -o $(name).bpf.o`

2. **Link step** (`genrule` invoking the vendored bpftool):
   `bpftool gen object $(name).linked.o $(name).bpf.o`

3. **Skeleton step** (`genrule` invoking bpftool):
   `bpftool gen skeleton $(name).linked.o > $(name).skel.h`

4. **Wrap step**:
   `cc_library(name = "<name>", hdrs = ["<name>.skel.h"], deps = ["@libbpf//:libbpf"], include_prefix = "bpf")`

Consumers write `#include "bpf/ingress_redirect_skel.skel.h"` and add `//src/bpf:ingress_redirect_skel` to their `cc_library` deps.

A hermetic clang toolchain is explicitly out of scope. The project's main C++ toolchain (see `toolchain/cc_toolchain_config.bzl`) continues to be GCC 14; clang is not added to the C++ build. The `bpf_skeleton` macro shells out to host-installed `clang-19` via `/usr/bin/clang-19` **for the BPF compile step only**, and fails clearly if not found. A future change can swap in `toolchains_llvm` without touching consumers of the macro.

### 3. CO-RE with checked-in `vmlinux.h`

The rewritten `.bpf.c` uses `#include "vmlinux.h"` and libbpf's `bpf_helpers.h` / `bpf_endian.h` macros. `vmlinux.h` is generated once and checked into `src/bpf/vmlinux.h`. The new `scripts/regenerate_vmlinux_h.sh` is a thin wrapper that runs exactly:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

(The script also `cd`s to the repo root so the output path is correct regardless of where it's invoked.) Checking the file in keeps the build hermetic — the file is a source input, not a build-time side effect of the host kernel — and matches how production BPF projects like Cilium ship.

### 4. Functional rewrite of the BPF program

The existing `src/bpf/ingress_redirect.bpf.c` is stale and is rewritten from scratch. The rewrite targets **behavioral parity** with the current handwritten program in `BuildIngressProgram`, not with the existing stale source file.

Program source outline:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "ingress_redirect_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ingress_redirect_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} listener_map SEC(".maps");

SEC("tc")
int ingress_redirect(struct __sk_buff *skb) { /* body per section 5 */ }

char LICENSE[] SEC("license") = "GPL";
```

Debug `bpf_printk` calls are retained behind a compile-time `-DDEBUG_TRACE`, **on by default**, to match the current build's `kEnableDebugPrintk = true`. The `-DDEBUG_TRACE` flag is set by the `bpf_skeleton` macro itself (hardcoded inside `bazel/bpf/defs.bzl` — not per-call-site), so every BPF source processed by the macro gets the same default. A follow-up can lift this into a macro keyword argument if more than one `.bpf.c` ever needs different tracing defaults.

### 5. Semantic parity table

Every behavior the current handwritten program exhibits must be preserved verbatim:

| Behavior | Current (handwritten) | After rewrite |
|---|---|---|
| Skip if config missing / disabled | missing-config jump → exit | `if (!cfg \|\| !cfg->enabled) return TC_ACT_OK;` |
| IPv4 / TCP filter | ethertype + IP protocol load+compare | same checks, written in C |
| Dynamic IHL-based TCP header offset | `(ihl & 0x0f) << 2` | `iph->ihl * 4` (clang emits equivalent) |
| Minimum IPv4 header length check | explicit 20-byte lower bound | same check |
| Dst-port match against `cfg->listener_port` | explicit `BPF_END FROM_BE` + compare | `bpf_ntohs(tcph->dest) == cfg->listener_port` |
| Primary socket lookup | `bpf_skc_lookup_tcp` over IPv4 4-tuple, `netns_id=-1`, `flags=0` | same helper, same args |
| Fallback path when skc lookup misses | `listener_map[0]` lookup (SOCKMAP) | same |
| Redirect: `bpf_sk_assign(skb, sk, 0)` + `bpf_sk_release(sk)` | present | same |
| Write `cfg->skb_mark` to `skb->mark` before assign | present via `STX` to `__sk_buff.mark` | `skb->mark = cfg->skb_mark` |
| Return code on match | `sk_assign` return value | same |
| Return code on any parse failure | `TC_ACT_OK` (which is `0`) | same |
| Program type | `BPF_PROG_TYPE_SCHED_CLS` | same (implied by `SEC("tc")`) |
| Attach point | TC clsact ingress with `direct_action` | **same; existing netlink code kept** |
| Filter name | `"ingress_redirect"` | same (netlink path unchanged) |
| Config map | `ARRAY`, key=`__u32`, value=`ingress_redirect_config`, `max_entries=1` | same, now created by libbpf from `SEC(".maps")` |
| Listener map | `SOCKMAP`, key=`__u32`, value=`__u32`, `max_entries=1` | same |
| `runtime_config_` layout | `{enabled, listener_port, skb_mark}` at key 0 | identical struct (shared header unchanged) |
| Debug `bpf_printk` | present, compiled in | present, gated by `-DDEBUG_TRACE` (on by default) |

The implementation plan must walk this table row-by-row when writing the new program and confirm each row is satisfied.

### 6. Loader internals — what goes and what stays

**Deleted from `src/bpf/loader.cpp`** (~400 LOC):

- All instruction-emission scaffolding: `ProgramBuilder`, `MakeInsn`, `MakeLoadMapFdInsn`, `EmitTracePrintk` / `EmitTracePrintk1` / `EmitTracePrintk2`, all `kCode*` / `kTupleIpv4StackOffset` / `kIpv4*` constants.
- `BuildIngressProgram` (the handwritten codegen entry point).
- `SysBpf`, `CreateConfigMap`, `CreateListenerMap`, `LoadProgram`, `UpdateConfigMap`, `UpdateListenerMap` — all replaced by libbpf APIs driven through the skeleton.

**Kept verbatim** — the netlink TC attach/detach path:

- `AppendAttr`, `AppendStringAttr`, `MakeNetlinkMessage`, `FinalizeNetlinkMessage`
- `NetlinkSocket`, `SendNetlinkRequest`
- `EnsureClsactQdisc`, `RemoveIngressFilter`, `AttachIngressFilter`

The netlink code already works and this rewrite is narrowly about the load path. Using libbpf's `bpf_tc_*` APIs is a valid follow-up but not part of this change.

**Public API unchanged** (`src/bpf/loader.hpp`):

- `AttachIngress(std::string_view)`
- `DetachIngress(std::string_view)`
- `ConfigureListenerSocket(int listener_fd, std::uint32_t intercept_port = 0)`
- `listener_socket_fd()`, `listener_port()`, `IsIngressAttached(std::string_view)`

**Public API removed** (used only by the deleted tests):

- `BuildIngressProgramForTesting()` — obsolete; the program comes from the skeleton
- `MarkIngressAttachedForTesting(std::string_view)` — its last consumer (`PreservesAttachedStateWhenDetachFails`) is being dropped

**New test hook:**

- `bool BpfLoader::LoadProgramForTesting()` — calls `ingress_redirect__open` + `ingress_redirect__load` without any netlink attach, returns `true` on success. This is the only new public method. It is the entry point for the `LoadsSkeleton` test (see Testing); it exists specifically so the test can verify the skeleton loads without needing a real interface or the netlink path. Marked clearly as a test-only hook in a comment.

**New member state** in `BpfLoader`:

- A pointer to the skeleton struct (`struct ingress_redirect_skel*`), opaque to the header via forward declaration. Freed in the destructor via the generated `ingress_redirect__destroy` helper.

`AttachIngress` logic (same sequence as today, just delegated):

1. Validate the interface name and cached listener state — unchanged.
2. Lazy-load on first attach: `ingress_redirect__open()` → `ingress_redirect__load()`. Cache the skeleton pointer.
3. `bpf_map__update_elem(skel->maps.config_map, &key_zero, &runtime_config_, sizeof(runtime_config_), BPF_ANY)`.
4. `bpf_map__update_elem(skel->maps.listener_map, &key_zero, &listener_fd, sizeof(listener_fd), BPF_ANY)`.
5. `EnsureClsactQdisc(*ifindex)` — **existing code, unchanged**.
6. `AttachIngressFilter(*ifindex, bpf_program__fd(skel->progs.ingress_redirect))` — existing code, unchanged.
7. Insert into `attached_interfaces_` — unchanged.

`ConfigureListenerSocket` keeps its existing logic; when the skeleton is already loaded, it calls `bpf_map__update_elem` on the live maps to push the updated config — same idempotency behavior as today.

## Testing

**Removed:**

- `tests/bpf_loader_test.cpp :: GeneratedProgramUsesConfiguredListenerPort` — asserts specific opcodes of the handwritten program that no longer exists.
- `tests/bpf_loader_test.cpp :: PreservesAttachedStateWhenDetachFails` — only consumer of `MarkIngressAttachedForTesting`; the behavior it asserts is covered by the netns end-to-end test.

**Kept, unchanged:**

- `RejectsMissingInterfaceName`
- `RejectsNonWanInterfaceNamesAfterListenerConfiguration`
- `CapturesListenerPortFromConfiguredSocket`
- `RejectsConfigureListenerSocketWhenGetsocknameFails`
- `tests/ebpf_intercept_fd_netns_test.cpp :: InterceptsPort80TrafficTransparentlyWithCleanTeardown` — this is the **ground-truth behavior test**. It must pass before and after the rewrite without modification. It is the primary acceptance criterion for semantic parity.

**Added:**

- `BpfLoaderTest :: LoadsSkeleton` — constructs a loader, invokes an internal helper that performs `ingress_redirect__open` + `ingress_redirect__load`, asserts success. Skipped (not failed) when running without `CAP_BPF`, reusing the existing `FdNetnsHarness::HasRequiredPrivileges()` skip pattern. Guards against trivial build breakage (bad `.bpf.c`, broken skeleton gen) without needing full netns setup.

## File-level change list

**New:**

- `bazel/bpf/BUILD.bazel` (empty package marker)
- `bazel/bpf/defs.bzl` (the `bpf_skeleton` macro)
- `third_party/bpftool/` (vendored source + hand-written `BUILD.bazel` + `MODULE.bazel`)
- `src/bpf/vmlinux.h` (checked-in BTF header)
- `scripts/regenerate_vmlinux_h.sh`

**Rewritten / filled in:**

- `third_party/libbpf/` — stub replaced with real vendored libbpf 1.5.0 source and a `BUILD.bazel` producing `@libbpf//:libbpf` static `cc_library`
- `src/bpf/ingress_redirect.bpf.c` — full rewrite in CO-RE style, per section 4/5
- `src/bpf/loader.cpp` — internals replaced; netlink path retained
- `src/bpf/loader.hpp` — drops `BuildIngressProgramForTesting` and `MarkIngressAttachedForTesting`; adds opaque skeleton pointer member
- `src/bpf/BUILD.bazel` — loads `bpf_skeleton`, declares `ingress_redirect_skel` target, makes `:loader` depend on it; drops the now-unused `filegroup(name = "ingress_redirect_bpf")`
- Root `MODULE.bazel` — adds `bpftool` `bazel_dep` + `local_path_override`

**Removed:**

- `tests/bpf_loader_test.cpp` — two specific test cases (see Testing section)

**Unchanged:**

- `src/bpf/ingress_redirect_common.h` — the `struct ingress_redirect_config` remains (shared between `.bpf.c` and `loader.cpp`). The `INGRESS_REDIRECT_HELPER_*` enum values become dead (no user-space or BPF-side consumer once the handwritten codegen is gone) but are left in the header to avoid churn and deleted in a separate follow-up commit. The `INGRESS_REDIRECT_MAP_KEY_ZERO`, `INGRESS_REDIRECT_IPV4_WIRE_VALUE`, and `INGRESS_REDIRECT_TCP_PROTOCOL` constants: the new `.bpf.c` replaces them with libbpf/CO-RE idioms (a local `__u32 key = 0;`, `bpf_htons(ETH_P_IP)` via `bpf_endian.h`, `IPPROTO_TCP` from `vmlinux.h`), so these three constants also become dead and follow the same "leave for a separate cleanup commit" rule. `loader.cpp` does not reference them.
- All of `src/proxy/`, `src/cni/`, `src/shared/`
- All netlink helpers in `loader.cpp`

## Implementation order

Each step is an independent commit. Steps 1–3 do not touch the runtime loader and can be reverted without affecting the proxy.

1. **Vendor libbpf sources.** Replace the stub `third_party/libbpf/BUILD.bazel` with a real static-archive build of libbpf 1.5.0. Verify `@libbpf//:libbpf` builds.
2. **Vendor bpftool sources.** Add `third_party/bpftool/` with a `cc_binary` target. Add the `bazel_dep` to root `MODULE.bazel`. Verify `bazel run //third_party/bpftool` works.
3. **Land the macro, `vmlinux.h`, and the rewritten `.bpf.c`.** Add `bazel/bpf/defs.bzl`; add `scripts/regenerate_vmlinux_h.sh`; generate `src/bpf/vmlinux.h`; rewrite `src/bpf/ingress_redirect.bpf.c`; declare the `bpf_skeleton` target in `src/bpf/BUILD.bazel` **without** wiring it into `:loader`. Verify the skeleton header builds.
4. **Rewrite `loader.cpp` and `loader.hpp`.** Delete the handwritten codegen; wire in the skeleton; drop the two test-only helpers; update `src/bpf/BUILD.bazel` to depend on the skeleton.
5. **Update tests.** Delete the two opcode- and test-hook-dependent test cases from `tests/bpf_loader_test.cpp`; add `LoadsSkeleton`.
6. **Verify.** `bazel build //...` succeeds. `bazel test //tests/...` passes, including `ebpf_intercept_fd_netns_test.cpp` unchanged.

The netns end-to-end test passing on step 6 without modification is the acceptance criterion for behavioral parity.
