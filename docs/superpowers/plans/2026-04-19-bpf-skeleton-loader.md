# BPF Skeleton Loader Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the handwritten BPF instruction builder in `src/bpf/loader.cpp` with a clang-compiled `.bpf.c` loaded via a bpftool-generated skeleton, with **no external behavior change**.

**Architecture:** Vendor libbpf under `third_party/`, expose host-installed `bpftool` as a Bazel repository, add one custom Bazel macro (`//bazel/bpf:defs.bzl bpf_skeleton`) that runs clang + `bpftool gen skeleton`, rewrite `src/bpf/ingress_redirect.bpf.c` as CO-RE source over a checked-in `vmlinux.h`, and convert `BpfLoader::AttachIngress` to drive the skeleton. The netlink TC attach/detach path is kept verbatim.

**Tech Stack:** Bazel (bzlmod), C++23 (GCC 14 toolchain, unchanged), libbpf 1.5.0 (vendored, static-linked), bpftool (host-installed, build-time only), clang-19 (host-installed, BPF compile step only), GoogleTest.

**Reference spec:** `docs/superpowers/specs/2026-04-19-bpf-skeleton-loader-design.md`

**Host prerequisite check (run before starting):**

```bash
which clang-19 && clang-19 --version && \
  (command -v bpftool || ls /usr/sbin/bpftool) && \
  ls /sys/kernel/btf/vmlinux && \
  pkg-config --exists libelf && \
  pkg-config --exists zlib && \
  echo OK
```

All must succeed and print `OK`. Clang-19 is required only for the BPF compile step. `bpftool` must be installed on the build host (`apt install bpftool` or `apt install linux-tools-common`) and is used by the `bpf_skeleton` macro for skeleton generation; it is not shipped to runtime. `/sys/kernel/btf/vmlinux` is needed once, at Chunk 3, for regenerating `vmlinux.h`. `libelf` and `zlib` (install via `apt install libelf-dev zlib1g-dev` if missing) are required by libbpf.

**Baseline capture (run before starting, so later "no regression" checks are concrete):**

```bash
bazel test //tests/... 2>&1 | tee /tmp/bpf-skel-plan-baseline.txt
```

Record the pass/fail summary line. Subsequent chunks verify that the same set of tests still pass or are skipped for the same reasons.

---

## Chunk 1: Vendor libbpf 1.5.0

**Objective:** Replace the empty-stub `third_party/libbpf` with a real libbpf 1.5.0 source tree and a `BUILD.bazel` that produces a usable static `cc_library`. At the end of this chunk, `bazel build @libbpf//:libbpf` succeeds. No other source is touched yet.

### Task 1.1: Fetch libbpf sources into the vendored tree

**Files:**
- Modify: `third_party/libbpf/` (directory; add many files from upstream tarball)
- Keep: `third_party/libbpf/MODULE.bazel` (unchanged — already has `name = "libbpf", version = "0.0.0"`)
- Replace: `third_party/libbpf/BUILD.bazel`

- [ ] **Step 1.1.1: Remove the stub BUILD.bazel contents (we'll rewrite it in Task 1.2)**

Leave the file present but empty for now:

```bash
: > third_party/libbpf/BUILD.bazel
```

- [ ] **Step 1.1.2: Fetch libbpf v1.5.0 release tarball and extract its `src/` and `include/` trees into `third_party/libbpf/`**

```bash
cd /tmp && \
  curl -L -o libbpf-1.5.0.tar.gz https://github.com/libbpf/libbpf/archive/refs/tags/v1.5.0.tar.gz && \
  tar xzf libbpf-1.5.0.tar.gz && \
  cd - && \
  cp -r /tmp/libbpf-1.5.0/src third_party/libbpf/src && \
  cp -r /tmp/libbpf-1.5.0/include third_party/libbpf/include && \
  cp /tmp/libbpf-1.5.0/LICENSE.LGPL-2.1 third_party/libbpf/LICENSE.LGPL-2.1 && \
  cp /tmp/libbpf-1.5.0/LICENSE.BSD-2-Clause third_party/libbpf/LICENSE.BSD-2-Clause && \
  cp /tmp/libbpf-1.5.0/VERSION third_party/libbpf/VERSION
```

The resulting layout:

```
third_party/libbpf/
  BUILD.bazel       (empty; will be written in Task 1.2)
  LICENSE.BSD-2-Clause
  LICENSE.LGPL-2.1
  MODULE.bazel      (pre-existing, unchanged)
  VERSION
  include/
    asm/
    linux/
    uapi/linux/bpf.h
    ...
  src/
    bpf.c
    bpf.h
    bpf_core_read.h
    bpf_endian.h
    bpf_helpers.h
    btf.c
    btf.h
    libbpf.c
    libbpf.h
    ...
```

- [ ] **Step 1.1.3: Verify the expected files are present**

```bash
test -f third_party/libbpf/src/libbpf.c && \
  test -f third_party/libbpf/src/libbpf.h && \
  test -f third_party/libbpf/src/bpf_helpers.h && \
  test -f third_party/libbpf/src/bpf_endian.h && \
  test -f third_party/libbpf/include/uapi/linux/bpf.h && \
  echo OK
```

Expected output: `OK`.

- [ ] **Step 1.1.4: Commit the vendored source drop**

```bash
git add third_party/libbpf
git commit -m "Vendor libbpf 1.5.0 source tree"
```

### Task 1.2: Write `third_party/libbpf/BUILD.bazel`

**Files:**
- Modify: `third_party/libbpf/BUILD.bazel` (write fresh contents)

- [ ] **Step 1.2.1: Write the BUILD.bazel**

Replace the file with:

```python
package(default_visibility = ["//visibility:public"])

# libbpf 1.5.0 static library.
#
# Source files are compiled from the upstream `src/` directory, with the
# upstream header-search paths set up so that `<bpf/libbpf.h>` resolves.
# The library is consumed by:
#   - //src/bpf:loader (C++ loader)
#   - //bazel/bpf:defs.bzl (the bpf_skeleton macro, as the runtime dep for
#     generated skeleton headers)

_LIBBPF_SRCS = [
    "src/bpf.c",
    "src/btf.c",
    "src/btf_dump.c",
    "src/gen_loader.c",
    "src/hashmap.c",
    "src/libbpf.c",
    "src/libbpf_errno.c",
    "src/libbpf_probes.c",
    "src/linker.c",
    "src/netlink.c",
    "src/nlattr.c",
    "src/relo_core.c",
    "src/ringbuf.c",
    "src/str_error.c",
    "src/strset.c",
    "src/usdt.c",
    "src/elf.c",
    "src/features.c",
    "src/zip.c",
]

# Public headers consumers can `#include <bpf/...>`.
_LIBBPF_PUBLIC_HDRS = [
    "src/bpf.h",
    "src/bpf_core_read.h",
    "src/bpf_endian.h",
    "src/bpf_gen_internal.h",
    "src/bpf_helper_defs.h",
    "src/bpf_helpers.h",
    "src/bpf_tracing.h",
    "src/btf.h",
    "src/libbpf.h",
    "src/libbpf_common.h",
    "src/libbpf_legacy.h",
    "src/libbpf_version.h",
    "src/skel_internal.h",
    "src/usdt.bpf.h",
]

# Private implementation headers (needed during compilation of .c files).
# Explicitly exclude the public headers so they appear only via `hdrs`,
# making missing/renamed public headers a loud error instead of a silent
# fallback to the glob.
_LIBBPF_PRIVATE_HDRS = glob(["src/*.h"], exclude = _LIBBPF_PUBLIC_HDRS)

genrule(
    name = "make_bpf_include_dir",
    srcs = _LIBBPF_PUBLIC_HDRS,
    outs = ["bpf/" + h.removeprefix("src/") for h in _LIBBPF_PUBLIC_HDRS],
    cmd = "for f in $(SRCS); do cp \"$$f\" \"$(RULEDIR)/bpf/$$(basename $$f)\"; done",
)

cc_library(
    name = "libbpf",
    srcs = _LIBBPF_SRCS + _LIBBPF_PRIVATE_HDRS,
    hdrs = [":make_bpf_include_dir"],
    includes = ["."],
    copts = [
        "-std=gnu11",
        "-D_LARGEFILE64_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-Wno-unused-parameter",
        "-Wno-sign-compare",
        "-Wno-missing-field-initializers",
        "-Wno-unused-result",
        "-Wno-address-of-packed-member",
    ],
    linkopts = ["-lelf", "-lz"],
    linkstatic = True,
)
```

Notes for the implementer:
- The `make_bpf_include_dir` genrule places public headers under `bpf/` so consumers can `#include <bpf/libbpf.h>`, matching upstream install behavior.
- `linkopts = ["-lelf", "-lz"]` pulls in system `libelf` and `libz`, which libbpf requires. These are already installed on this host (`libelf-dev`, `zlib1g-dev`). If absent, `apt install libelf-dev zlib1g-dev` is required.
- `linkstatic = True` ensures the archive is linked statically into `proxy_daemon`.
- `_LIBBPF_SRCS` is the source set libbpf 1.5.0's `src/Makefile` compiles into its shared object (effectively `wildcard *.c`). Verify after extraction that every listed file exists; also run Step 1.2.3 below to assert the list has **no extra and no missing** files compared to `ls third_party/libbpf/src/*.c`, so an upstream file addition does not get silently dropped.

- [ ] **Step 1.2.2: Verify every source file listed in `_LIBBPF_SRCS` exists**

```bash
for f in bpf btf btf_dump gen_loader hashmap libbpf libbpf_errno libbpf_probes \
         linker netlink nlattr relo_core ringbuf str_error strset usdt elf \
         features zip; do
  test -f "third_party/libbpf/src/${f}.c" || { echo "missing: $f.c"; exit 1; }
done
echo OK
```

Expected output: `OK`. If any file is missing, libbpf 1.5.0's layout has diverged and the source list in BUILD.bazel must be corrected before proceeding.

- [ ] **Step 1.2.3: Verify no **extra** `*.c` files exist in `src/` beyond the list**

```bash
expected=$(ls third_party/libbpf/src/*.c | sort)
listed=$(printf 'third_party/libbpf/src/%s.c\n' \
  bpf btf btf_dump gen_loader hashmap libbpf libbpf_errno libbpf_probes \
  linker netlink nlattr relo_core ringbuf str_error strset usdt elf features zip | sort)
diff <(echo "$expected") <(echo "$listed") && echo OK
```

Expected output: `OK`. A non-empty diff means upstream libbpf added or removed source files in v1.5.0 (or the tarball extracted a different set than expected) and the `_LIBBPF_SRCS` list must be reconciled before proceeding.

### Task 1.3: Smoke-test that libbpf builds

**Files:**
- No changes. Pure Bazel invocation.

- [ ] **Step 1.3.1: Build `@libbpf//:libbpf` in isolation**

```bash
bazel build @libbpf//:libbpf
```

Expected output: one target built successfully. No warnings about missing headers. Exit code 0.

If it fails:
- `fatal error: 'bpf/libbpf.h' file not found` → the `make_bpf_include_dir` genrule output layout is wrong. Inspect under `bazel-bin/external/*libbpf*/bpf/` (the exact external-repo path varies by Bazel version and module extension naming) to confirm headers landed where the `includes = ["."]` expects them.
- Missing `elf.h` → install `libelf-dev` on the host.
- Missing `zlib.h` → install `zlib1g-dev`.

- [ ] **Step 1.3.2: Commit the BUILD.bazel**

```bash
git add third_party/libbpf/BUILD.bazel
git commit -m "Build vendored libbpf 1.5.0 as a static cc_library"
```

### Task 1.4: Verify the existing build is not broken

**Files:**
- No changes.

- [ ] **Step 1.4.1: Build everything**

```bash
bazel build //...
```

Expected: all pre-existing targets still build successfully. `@libbpf//:libbpf` is now a real library but nothing depends on it yet, so the rest of the repo is unaffected.

- [ ] **Step 1.4.2: Run the existing test suite and diff against the baseline**

```bash
bazel test //tests/... 2>&1 | tee /tmp/bpf-skel-plan-chunk1.txt
diff /tmp/bpf-skel-plan-baseline.txt /tmp/bpf-skel-plan-chunk1.txt || true
```

Expected: no **substantive** differences (timestamps and cache-status lines are fine; the same set of tests must pass/skip/fail as in the baseline). No regressions introduced. If a previously-passing test now fails, stop and investigate before continuing.

If either step fails with errors unrelated to `@libbpf//:libbpf`, something has gone wrong with the vendor drop. Stop and investigate before continuing.

---

## Chunk 2: Expose host-installed bpftool to Bazel

**Objective:** Add a small Bazel repository rule that locates the host's `bpftool` binary and exposes it at `@host_bpftool//:bpftool` for build-time use by the `bpf_skeleton` macro in Chunk 3. No vendored bpftool source, no runtime dependency. At the end of this chunk, `bazel run @host_bpftool//:bpftool -- version` prints a version string.

### Task 2.1: Add the `host_bpftool` repository rule

**Files:**
- Create: `bazel/bpf/BUILD.bazel` (empty package marker)
- Create: `bazel/bpf/host_bpftool.bzl`

- [ ] **Step 2.1.1: Create the `bazel/bpf/` package directory and empty BUILD**

```bash
mkdir -p bazel/bpf
: > bazel/bpf/BUILD.bazel
```

- [ ] **Step 2.1.2: Write `bazel/bpf/host_bpftool.bzl`**

Create the file with exactly these contents:

```python
"""Repository rule + module extension that locates the host `bpftool`.

bpftool is treated as a host build-time tool (like `clang-19`). It is NOT
vendored, and is never shipped to runtime. The repository rule symlinks the
host binary into a Bazel-managed external repo so downstream rules can
reference it as `@host_bpftool//:bpftool`.

See the spec at
`docs/superpowers/specs/2026-04-19-bpf-skeleton-loader-design.md`,
Decisions section 1, for the rationale.
"""

def _host_bpftool_impl(rctx):
    # `command -v` is not exposed by repository_ctx; use which().
    # Check common install locations if PATH does not have it.
    path = rctx.which("bpftool")
    if not path:
        for candidate in ("/usr/sbin/bpftool", "/sbin/bpftool", "/usr/bin/bpftool"):
            if rctx.path(candidate).exists:
                path = rctx.path(candidate)
                break
    if not path:
        fail(
            "`bpftool` not found on PATH. Install via " +
            "`apt install bpftool` or `apt install linux-tools-common`.",
        )
    rctx.symlink(path, "bpftool")
    rctx.file(
        "BUILD.bazel",
        'exports_files(["bpftool"], visibility = ["//visibility:public"])\n',
    )

host_bpftool_repo = repository_rule(
    implementation = _host_bpftool_impl,
    local = True,
    doc = "Locates the host-installed bpftool binary.",
)

def _host_bpftool_extension_impl(_):
    host_bpftool_repo(name = "host_bpftool")

host_bpftool = module_extension(
    implementation = _host_bpftool_extension_impl,
    doc = "Module extension that registers the @host_bpftool repo.",
)
```

Key points for the implementer:
- `rctx.which("bpftool")` returns `None` (not an empty string) when not found. The explicit `if not path:` fallback checks common sbin locations because Bazel's repository-rule `PATH` is scrubbed and may omit `/usr/sbin`.
- `local = True` tells Bazel this rule is not cacheable across machines and should re-run if the host binary moves. For a locator rule this is correct.
- `exports_files` with `visibility = ["//visibility:public"]` lets any Bazel target reference `@host_bpftool//:bpftool` in `tools = [...]` or via `$(location ...)`.

### Task 2.2: Register the extension in the root `MODULE.bazel`

**Files:**
- Modify: `MODULE.bazel`

- [ ] **Step 2.2.1: Add the extension and `use_repo` lines**

Edit the root `MODULE.bazel`. After the existing `local_path_override(module_name = "libbpf", path = "third_party/libbpf")` line (which is the last `local_path_override`), add a blank line and then:

```python
# ============================================================================
# Host-installed bpftool (build-time only)
# ============================================================================

host_bpftool_ext = use_extension("//bazel/bpf:host_bpftool.bzl", "host_bpftool")
use_repo(host_bpftool_ext, "host_bpftool")
```

- [ ] **Step 2.2.2: Verify bpftool resolves through Bazel**

```bash
bazel run @host_bpftool//:bpftool -- version
```

Expected: prints something like `bpftool v7.x.x` (the exact version depends on the host package). Exit code 0.

If it fails with `bpftool not found on PATH`: install the host package (`apt install bpftool` or `apt install linux-tools-common`) and retry.

If it fails with a symlink error under `bazel-out/.../external/host_bpftool/`: inspect that directory to confirm the symlink target. The repository rule re-runs on every invocation (because `local = True`), so simply running `bazel shutdown && bazel run @host_bpftool//:bpftool -- version` refreshes it.

- [ ] **Step 2.2.3: Run the full existing build and tests**

```bash
bazel build //... && bazel test //tests/... 2>&1 | tee /tmp/bpf-skel-plan-chunk2.txt && diff /tmp/bpf-skel-plan-baseline.txt /tmp/bpf-skel-plan-chunk2.txt
```

Expected: no substantive differences vs. the baseline. Nothing depends on `@host_bpftool` yet, so pre-existing targets are unaffected. (The `diff` is informational; `|| true` is intentionally omitted here so a real regression is visible as a non-zero exit — ignore only whitespace/timestamp differences.)

- [ ] **Step 2.2.4: Commit**

```bash
git add bazel/bpf/BUILD.bazel bazel/bpf/host_bpftool.bzl MODULE.bazel
git commit -m "Expose host-installed bpftool as @host_bpftool//:bpftool"
```

---


## Chunk 3: Skeleton build rule, `vmlinux.h`, and rewritten `.bpf.c`

**Objective:** Land the custom Bazel macro (`bpf_skeleton`), check in a `vmlinux.h` via a new regeneration script, refactor the shared `ingress_redirect_common.h` so it can be included from a CO-RE BPF program, rewrite `src/bpf/ingress_redirect.bpf.c` as CO-RE source preserving semantic parity with today's handwritten codegen, and declare a `//src/bpf:ingress_redirect_skel` target. **`//src/bpf:loader` is not modified in this chunk** — the skeleton target is built and verified in isolation. The loader rewrite is Chunk 4.

### Task 3.0: Make `ingress_redirect_common.h` BPF-safe

The current `ingress_redirect_common.h` starts with `#include <linux/bpf.h>`, which will collide with the types already declared in `vmlinux.h` when the shared header is included from the BPF program. We refactor the header so it works from both sides:

- user-space (`loader.cpp`) keeps its kernel-uapi-backed types via the existing include
- BPF side (`ingress_redirect.bpf.c`) includes the header after `vmlinux.h` and does not want a second copy of `<linux/bpf.h>`

**Files:**
- Modify: `src/bpf/ingress_redirect_common.h`

- [ ] **Step 3.0.1: Rewrite `ingress_redirect_common.h` to guard the kernel-uapi include**

Replace the file with:

```c
#ifndef INLINE_PROXY_BPF_INGRESS_REDIRECT_COMMON_H_
#define INLINE_PROXY_BPF_INGRESS_REDIRECT_COMMON_H_

// This header is included from both:
//   - src/bpf/loader.cpp (user-space C++; wants <linux/bpf.h> for __u32 etc.)
//   - src/bpf/ingress_redirect.bpf.c (CO-RE BPF program; already has
//     vmlinux.h's kernel type definitions, must not re-include <linux/bpf.h>)
// __VMLINUX_H__ is the include-guard bpftool's `btf dump format c` output
// defines; its presence means vmlinux.h has already been included.

#ifndef __VMLINUX_H__
#include <linux/bpf.h>
#endif

struct ingress_redirect_config {
    __u32 enabled;
    __u32 listener_port;
    __u32 skb_mark;
};

typedef struct ingress_redirect_config IngressRedirectConfig;

// The INGRESS_REDIRECT_HELPER_* enum and INGRESS_REDIRECT_IPV4_WIRE_VALUE /
// INGRESS_REDIRECT_TCP_PROTOCOL / INGRESS_REDIRECT_MAP_KEY_ZERO constants
// used by the old handwritten codegen are deliberately removed — the
// CO-RE BPF program uses libbpf's idiomatic forms (bpf_htons(ETH_P_IP),
// IPPROTO_TCP from vmlinux.h, a local __u32 key = 0).

#endif  // INLINE_PROXY_BPF_INGRESS_REDIRECT_COMMON_H_
```

- [ ] **Step 3.0.2: Verify `loader.cpp` still compiles** (it still uses the struct, via the unchanged include)

```bash
bazel build //src/bpf:loader
```

Expected: builds cleanly. `loader.cpp` has no `__VMLINUX_H__` guard defined at its include point, so it will still pull in `<linux/bpf.h>` as before.

- [ ] **Step 3.0.3: Commit**

```bash
git add src/bpf/ingress_redirect_common.h
git commit -m "Make ingress_redirect_common.h safe to include from CO-RE BPF"
```

### Task 3.1: Generate and check in `vmlinux.h`

**Files:**
- Create: `scripts/regenerate_vmlinux_h.sh`
- Create: `src/bpf/vmlinux.h`

- [ ] **Step 3.1.1: Create the regeneration script**

Write `scripts/regenerate_vmlinux_h.sh` with exactly this content:

```bash
#!/usr/bin/env bash
# Regenerate src/bpf/vmlinux.h from the running kernel's BTF.
#
# Run from anywhere inside the repo. Requires `bpftool` on PATH (see
# `apt install bpftool` or `apt install linux-tools-common`) and
# /sys/kernel/btf/vmlinux to be readable.
#
# Output is checked into the repo. Regenerate only when intentionally
# updating vmlinux.h (typically during a kernel version bump on the
# development host); do NOT auto-regenerate in CI.
set -euo pipefail
repo_root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$repo_root"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
echo "Wrote $(wc -l < src/bpf/vmlinux.h) lines to src/bpf/vmlinux.h"
```

Make it executable:

```bash
chmod +x scripts/regenerate_vmlinux_h.sh
```

- [ ] **Step 3.1.2: Run the script to generate `src/bpf/vmlinux.h`**

```bash
./scripts/regenerate_vmlinux_h.sh
```

Expected: prints `Wrote <N> lines to src/bpf/vmlinux.h` with `N` in the low tens of thousands. Exit code 0.

- [ ] **Step 3.1.3: Sanity-check the generated header**

```bash
head -5 src/bpf/vmlinux.h
grep -c '^struct ' src/bpf/vmlinux.h
grep -q '^struct __sk_buff ' src/bpf/vmlinux.h && echo HAS_SK_BUFF
grep -q '^struct iphdr ' src/bpf/vmlinux.h && echo HAS_IPHDR
grep -q '^struct tcphdr ' src/bpf/vmlinux.h && echo HAS_TCPHDR
grep -q '^struct ethhdr ' src/bpf/vmlinux.h && echo HAS_ETHHDR
grep -q '^struct bpf_sock_tuple ' src/bpf/vmlinux.h && echo HAS_SOCK_TUPLE
```

Expected: all five `HAS_*` markers print, plus a struct count in the thousands. If any is missing, the kernel BTF does not have the types the BPF program needs — stop and investigate (likely a kernel-config issue on the host).

- [ ] **Step 3.1.4: Commit**

```bash
git add scripts/regenerate_vmlinux_h.sh src/bpf/vmlinux.h
git commit -m "Check in vmlinux.h and its regeneration script"
```

### Task 3.2: Write the `bpf_skeleton` Bazel macro

**Files:**
- Create: `bazel/bpf/defs.bzl`

- [ ] **Step 3.2.1: Write `bazel/bpf/defs.bzl`**

Create with exactly this content:

```python
"""Custom Bazel rules for building BPF programs via clang + bpftool skeleton.

The single public entry point is `bpf_skeleton`, which compiles a `.bpf.c`
file to a BPF ELF, links it via `bpftool gen object`, and generates a
skeleton header via `bpftool gen skeleton`. Consumers #include the skeleton
header and depend on the resulting cc_library.

See the spec at
`docs/superpowers/specs/2026-04-19-bpf-skeleton-loader-design.md`,
Decisions section 2, for the rationale and rule shape.
"""

# Host clang-19. Shelled out via absolute path; if clang-19 is not at
# /usr/bin/clang-19 on the build host, override this constant. A future
# change can swap this for a hermetic toolchain without changing the macro
# interface.
_CLANG = "/usr/bin/clang-19"

def bpf_skeleton(name, src, hdrs = [], copts = []):
    """Compile a .bpf.c into a libbpf skeleton cc_library.

    Args:
        name: target name. Consumers see a cc_library at //<pkg>:<name>
              whose header is `<name>.skel.h` with `#include` path
              `bpf/<name>.skel.h`.
        src:  the .bpf.c source file (string label).
        hdrs: extra headers the .bpf.c depends on (e.g. vmlinux.h,
              ingress_redirect_common.h). Passed to clang via -I on the
              source file's package directory.
        copts: additional clang copts to append after the defaults.
    """
    obj = name + ".bpf.o"
    linked = name + ".linked.o"
    skel = name + ".skel.h"

    # -target bpf emits BPF bytecode; -g is required for BTF; -O2 is
    # required for the verifier to accept the output. -DDEBUG_TRACE is
    # applied unconditionally to match the handwritten loader's
    # kEnableDebugPrintk = true default.
    _default_copts = [
        "-target bpf",
        "-O2",
        "-g",
        "-Wall",
        "-Werror",
        "-D__TARGET_ARCH_x86",
        "-DDEBUG_TRACE",
    ]
    _clang_copts = " ".join(_default_copts + copts)

    native.genrule(
        name = name + "_compile",
        srcs = [src] + hdrs,
        outs = [obj],
        cmd = " ".join([
            _CLANG,
            _clang_copts,
            "-I $$(dirname $(location " + src + "))",
            "-c $(location " + src + ")",
            "-o $@",
        ]),
        message = "Compiling BPF program " + src,
    )

    native.genrule(
        name = name + "_link",
        srcs = [obj],
        outs = [linked],
        cmd = "$(location @host_bpftool//:bpftool) gen object $@ $(location " + obj + ")",
        tools = ["@host_bpftool//:bpftool"],
        message = "Linking BPF object " + linked,
    )

    native.genrule(
        name = name + "_skel",
        srcs = [linked],
        outs = [skel],
        cmd = "$(location @host_bpftool//:bpftool) gen skeleton $(location " + linked + ") > $@",
        tools = ["@host_bpftool//:bpftool"],
        message = "Generating BPF skeleton " + skel,
    )

    native.cc_library(
        name = name,
        hdrs = [skel],
        deps = ["@libbpf//:libbpf"],
        include_prefix = "bpf",
        visibility = ["//visibility:public"],
    )
```

Implementation notes:
- Each step is a separate `genrule` so failures are localized: clang compile errors surface in `_compile`; bpftool BTF problems in `_link`; skeleton-generation issues in `_skel`.
- `-DDEBUG_TRACE` is applied unconditionally inside the macro (not per-call) per the spec's Decisions section 4. If more than one BPF program is ever added with different tracing needs, lift this into a macro keyword argument.
- `include_prefix = "bpf"` matches the existing `//src/bpf:loader` include prefix so consumers write `#include "bpf/ingress_redirect_skel.skel.h"`.

- [ ] **Step 3.2.2: Commit**

```bash
git add bazel/bpf/defs.bzl
git commit -m "Add bpf_skeleton Bazel macro"
```

### Task 3.3: Rewrite `src/bpf/ingress_redirect.bpf.c`

**Files:**
- Modify (overwrite): `src/bpf/ingress_redirect.bpf.c`

- [ ] **Step 3.3.1: Replace the file contents**

Overwrite `src/bpf/ingress_redirect.bpf.c` with:

```c
// CO-RE-style TC ingress redirector.
//
// Replaces the handwritten bpf_insn codegen in src/bpf/loader.cpp. The
// program's observable behavior must match the handwritten program
// exactly; see the parity table in
// docs/superpowers/specs/2026-04-19-bpf-skeleton-loader-design.md
// (Decisions section 5).

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "ingress_redirect_common.h"

#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define TC_ACT_OK   0

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

#ifdef DEBUG_TRACE
#define ipx_trace(fmt, ...) bpf_printk("ipx " fmt, ##__VA_ARGS__)
#else
#define ipx_trace(fmt, ...) ((void)0)
#endif

SEC("tc")
int ingress_redirect(struct __sk_buff *skb) {
    __u32 cfg_key = 0;
    struct ingress_redirect_config *cfg =
        bpf_map_lookup_elem(&config_map, &cfg_key);
    if (!cfg || !cfg->enabled) {
        return TC_ACT_OK;
    }

    // Ethertype at L2 offset 12.
    __u16 eth_proto = 0;
    if (bpf_skb_load_bytes(skb, 12, &eth_proto, sizeof(eth_proto)) != 0) {
        return TC_ACT_OK;
    }
    if (eth_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    // IP protocol at offset 23 (L2 14 + IP 9).
    __u8 ip_proto = 0;
    if (bpf_skb_load_bytes(skb, 23, &ip_proto, sizeof(ip_proto)) != 0) {
        return TC_ACT_OK;
    }
    if (ip_proto != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    // IHL byte at offset 14. Compute TCP header offset from it.
    __u8 ihl_byte = 0;
    if (bpf_skb_load_bytes(skb, 14, &ihl_byte, sizeof(ihl_byte)) != 0) {
        return TC_ACT_OK;
    }
    __u32 ihl_bytes = (ihl_byte & 0x0f) << 2;
    if (ihl_bytes < 20) {
        return TC_ACT_OK;
    }
    __u32 tcp_off = 14 + ihl_bytes;

    // TCP destination port (big-endian, 2 bytes at tcp_off + 2).
    __u16 dst_port_be = 0;
    if (bpf_skb_load_bytes(skb, tcp_off + 2, &dst_port_be, sizeof(dst_port_be)) != 0) {
        return TC_ACT_OK;
    }
    __u16 dst_port = bpf_ntohs(dst_port_be);
    if (dst_port != (__u16)cfg->listener_port) {
        return TC_ACT_OK;
    }
    ipx_trace("port80\n");

    // TCP flags at tcp_off + 13.
    __u8 tcp_flags = 0;
    if (bpf_skb_load_bytes(skb, tcp_off + 13, &tcp_flags, sizeof(tcp_flags)) != 0) {
        return TC_ACT_OK;
    }
    ipx_trace("flags=%d\n", tcp_flags);

    // IPv4 + TCP 4-tuple: 8 bytes of IPs at offset 26, then 4 bytes of
    // ports at tcp_off (src port then dst port).
    struct bpf_sock_tuple tuple = {};
    if (bpf_skb_load_bytes(skb, 26, &tuple.ipv4.saddr, 8) != 0) {
        return TC_ACT_OK;
    }
    if (bpf_skb_load_bytes(skb, tcp_off, &tuple.ipv4.sport, 4) != 0) {
        return TC_ACT_OK;
    }
    ipx_trace("s=%x d=%x\n", tuple.ipv4.saddr, tuple.ipv4.daddr);
    ipx_trace("sp=%d dp=%d\n",
              bpf_ntohs(tuple.ipv4.sport), bpf_ntohs(tuple.ipv4.dport));

    // Primary: look up an established socket on the 4-tuple.
    struct bpf_sock *sk = bpf_skc_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4),
                                             BPF_F_CURRENT_NETNS, 0);
    if (sk) {
        ipx_trace("lookup hit\n");
        ipx_trace("state=%d\n", sk->state);
    } else {
        // Fallback: the listener socket from the sockmap. This mirrors the
        // handwritten program's trace+lookup sequence verbatim, including
        // the "listener map" trace line before the lookup call.
        ipx_trace("listener map\n");
        __u32 lmap_key = 0;
        sk = (struct bpf_sock *)bpf_map_lookup_elem(&listener_map, &lmap_key);
        if (!sk) {
            return TC_ACT_OK;
        }
        ipx_trace("listener use\n");
    }

    skb->mark = cfg->skb_mark;
    int assign_rc = bpf_sk_assign(skb, sk, 0);
    ipx_trace("assign=%d\n", assign_rc);
    bpf_sk_release(sk);
    return assign_rc == 0 ? TC_ACT_OK : assign_rc;
}

char LICENSE[] SEC("license") = "GPL";
```

Notes for the implementer:
- `BPF_F_CURRENT_NETNS` (value `-1`) matches the handwritten loader's `MovImm BPF_REG_4, 0, -1` (loader.cpp:318). If the constant is missing from the installed `vmlinux.h`, substitute the literal `(__u64)-1` and leave a comment.
- `bpf_sk_release(sk)` runs after both branches — this matches the handwritten program's behavior verbatim (both paths fall through into the common assign block which ends with `bpf_sk_release`). Whether the sockmap-derived socket is a fully refcounted `bpf_sock *` is a kernel-verifier concern and is the same concern the handwritten program has today; if the verifier later rejects this in the rewritten program, that is the same regression surface and a separate follow-up.
- The `(struct bpf_sock *)` cast on the sockmap lookup exists because `bpf_map_lookup_elem` is declared as returning `void *` in C, while the verifier tracks the sockmap return as a typed `PTR_TO_SOCKET_OR_NULL`. The cast is a type hint for clang; it does not affect verifier behavior.
- Before committing, walk the parity table in the spec (Decisions section 5) row by row against this code. Any divergence must be deliberate and recorded in the commit message.

- [ ] **Step 3.3.2: Dry-run compile outside Bazel**

First ensure `@libbpf//:libbpf`'s headers are materialized, then discover the exact include path (it varies by Bazel version):

```bash
bazel build @libbpf//:libbpf
LIBBPF_HDR_DIR=$(find bazel-bin/external -path '*/bpf/bpf_helpers.h' -printf '%h\n' | head -1 | sed 's|/bpf$||')
test -n "$LIBBPF_HDR_DIR" || { echo "could not locate libbpf headers"; exit 1; }
```

Then run the compile with that directory as `-I`:

```bash
clang-19 -target bpf -O2 -g -D__TARGET_ARCH_x86 -DDEBUG_TRACE -Wall -Werror \
  -I src/bpf \
  -I "$LIBBPF_HDR_DIR" \
  -c src/bpf/ingress_redirect.bpf.c -o /tmp/ingress_redirect.bpf.o
```

Expected: compiles with no errors. Any warning is fatal because the macro uses `-Werror`; fix it before proceeding.

This dry-run check is outside Bazel, to localize problems before the macro runs. A successful compile here does not guarantee the BPF verifier will accept the program at load time — that check happens in Chunk 4's `LoadsSkeleton` test.

- [ ] **Step 3.3.3: Commit**

```bash
git add src/bpf/ingress_redirect.bpf.c
git commit -m "Rewrite ingress_redirect.bpf.c as CO-RE source"
```

### Task 3.4: Declare the `ingress_redirect_skel` Bazel target

**Files:**
- Modify: `src/bpf/BUILD.bazel`

- [ ] **Step 3.4.1: Rewrite `src/bpf/BUILD.bazel`**

Replace the file with:

```python
load("//bazel/bpf:defs.bzl", "bpf_skeleton")

package(default_visibility = ["//visibility:public"])

exports_files([
    "BUILD.bazel",
    "ingress_redirect.bpf.c",
    "ingress_redirect_common.h",
])

bpf_skeleton(
    name = "ingress_redirect_skel",
    src = "ingress_redirect.bpf.c",
    hdrs = [
        "ingress_redirect_common.h",
        "vmlinux.h",
    ],
)

cc_library(
    name = "loader",
    srcs = ["loader.cpp"],
    hdrs = [
        "ingress_redirect_common.h",
        "loader.hpp",
    ],
    deps = ["//src/shared:shared"],
    include_prefix = "bpf",
)
```

Note: the `filegroup(name = "ingress_redirect_bpf", srcs = ["ingress_redirect.bpf.c"])` from the previous BUILD.bazel is removed; it has no remaining consumer.

`:loader` intentionally does **not** yet depend on `:ingress_redirect_skel` — the loader consumes the skeleton in Chunk 4. Keeping them decoupled here lets us verify the skeleton target builds in isolation before we touch runtime code.

- [ ] **Step 3.4.2: Build the skeleton target in isolation**

```bash
bazel build //src/bpf:ingress_redirect_skel
```

Expected: three genrule steps (`_compile`, `_link`, `_skel`) + a cc_library build. Inspect the generated header:

```bash
head -30 bazel-bin/src/bpf/ingress_redirect_skel.skel.h
```

Expected: output starts with bpftool-generated boilerplate (an `#ifndef __INGRESS_REDIRECT_SKEL_H__` guard or similar) followed by a `struct ingress_redirect_skel { ... }` declaration exposing `obj`, `progs`, `maps`, and possibly `rodata`/`bss` fields.

If it fails:
- **`_compile` genrule fails with "file not found"** on a header: the macro's `-I $(dirname ...)` is not catching a header. Confirm `hdrs = [...]` in Task 3.4.1 lists every header referenced by `.bpf.c` (including `vmlinux.h`).
- **`_link` fails with "no BTF found"**: the clang `-g` flag is missing; verify `defs.bzl` still has `-g` in `_default_copts`.
- **`_skel` fails with "no programs found"**: the `.bpf.c` is missing `SEC("tc")` on the function; re-check Task 3.3.1 output.

- [ ] **Step 3.4.3: Run the full existing build and tests (no regressions)**

```bash
bazel build //... && \
bazel test //tests/... 2>&1 | tee /tmp/bpf-skel-plan-chunk3.txt && \
diff /tmp/bpf-skel-plan-baseline.txt /tmp/bpf-skel-plan-chunk3.txt
```

Expected: no substantive regressions. `//src/bpf:loader` still builds from the unchanged `loader.cpp`; the new `:ingress_redirect_skel` target is not yet consumed, so nothing it breaks can affect the rest of the build.

- [ ] **Step 3.4.4: Commit**

```bash
git add src/bpf/BUILD.bazel
git commit -m "Declare ingress_redirect_skel skeleton target"
```

---


## Chunk 4: Rewrite `loader.cpp` to use the skeleton

**Objective:** Replace the ~400 lines of handwritten BPF codegen and raw syscalls in `src/bpf/loader.cpp` with libbpf skeleton calls. The netlink TC attach path is kept verbatim. The `BpfLoader` public API is preserved except for the two test-only hooks that have no remaining consumer. At the end of this chunk, `//src/bpf:loader` is rebuilt against the skeleton, `ebpf_intercept_fd_netns_test.cpp` still passes unchanged, and the two opcode/test-hook-dependent tests are removed from `tests/bpf_loader_test.cpp`.

### Task 4.1: Update `loader.hpp`

**Files:**
- Modify: `src/bpf/loader.hpp`

- [ ] **Step 4.1.1: Rewrite the header**

Replace `src/bpf/loader.hpp` with:

```cpp
#pragma once

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>

#include "bpf/ingress_redirect_common.h"
#include "shared/scoped_fd.hpp"

// Forward declaration of the bpftool-generated skeleton struct; the
// concrete definition lives in bazel-bin/.../ingress_redirect_skel.skel.h
// and is only included from loader.cpp.
struct ingress_redirect_skel;

namespace inline_proxy {

class BpfLoader {
public:
    BpfLoader() = default;
    ~BpfLoader();

    BpfLoader(const BpfLoader&) = delete;
    BpfLoader& operator=(const BpfLoader&) = delete;

    bool AttachIngress(std::string_view interface_name);
    bool DetachIngress(std::string_view interface_name);

    bool ConfigureListenerSocket(int listener_fd, std::uint32_t intercept_port = 0);
    std::optional<int> listener_socket_fd() const noexcept;
    std::uint32_t listener_port() const noexcept;

    bool IsIngressAttached(std::string_view interface_name) const;

    // Test-only hook: opens and loads the skeleton without attaching to any
    // interface. Returns true on success. Skipped in tests that lack
    // CAP_BPF. See tests/bpf_loader_test.cpp.
    bool LoadProgramForTesting();

private:
    bool EnsureSkeletonLoaded();
    bool UpdateConfigAndListenerMaps(const IngressRedirectConfig& config,
                                     std::optional<int> listener_fd);

    std::set<std::string> attached_interfaces_;
    std::optional<int> listener_socket_fd_;
    std::uint32_t listener_port_ = 0;
    IngressRedirectConfig runtime_config_{};
    struct ingress_redirect_skel* skel_ = nullptr;
};

}  // namespace inline_proxy
```

Key shape changes:
- `BuildIngressProgramForTesting()` — **removed**; no consumer after the corresponding test is deleted in Task 4.3.
- `MarkIngressAttachedForTesting()` — **removed** for the same reason.
- `LoadProgramForTesting()` — **added**; thin wrapper for the new `LoadsSkeleton` test in Task 4.3.
- A forward-declared `ingress_redirect_skel*` replaces the three `ScopedFd` members (`config_map_`, `listener_map_`, `program_fd_`) — the skeleton owns those fds.
- The destructor is now explicit (closes the skeleton via `ingress_redirect_skel__destroy`).
- Copy is explicitly deleted; the skeleton pointer makes copying unsafe.

- [ ] **Step 4.1.2: Commit**

```bash
git add src/bpf/loader.hpp
git commit -m "Shape BpfLoader header for skeleton-based internals"
```

### Task 4.2: Rewrite `loader.cpp`

**Files:**
- Modify: `src/bpf/loader.cpp`

This is the largest single change in the plan. The approach is to keep the file's top-level structure (public method definitions in the same order, netlink helpers intact) and replace only the now-obsolete handwritten codegen / raw-syscall sections.

- [ ] **Step 4.2.1: Identify keep/remove/rewrite sections**

In the current `src/bpf/loader.cpp` (approximate line ranges — the section boundaries are what matter, not exact line numbers):

| Approx. lines | Content | Action |
|------|---------|--------|
| ~34-201 | `ProgramBuilder`, `MakeInsn*`, `EmitTracePrintk*`, BPF-asm constants | **Delete** |
| ~203 | `SysBpf` helper | **Delete** |
| ~211-381 | `BuildIngressProgram(...)` | **Delete** |
| ~383-486 | `AppendAttr` / `AppendStringAttr` / `MakeNetlinkMessage` / `NetlinkSocket` / `SendNetlinkRequest` | **Keep verbatim** |
| ~488-533 | `FinalizeNetlinkMessage`, `EnsureClsactQdisc`, `RemoveIngressFilter`, `AttachIngressFilter` | **Keep verbatim** |
| ~535-565 | `CreateConfigMap`, `CreateListenerMap` | **Delete** (libbpf creates maps from skeleton) |
| ~567-607 | `LoadProgram(...)` (raw `BPF_PROG_LOAD`) | **Delete** |
| ~609-632 | `UpdateConfigMap`, `UpdateListenerMap` | **Delete** (replaced by `bpf_map__update_elem`) |
| ~636-698 | `BpfLoader::AttachIngress` | **Rewrite** to use skeleton |
| ~700-722 | `BpfLoader::DetachIngress` | **Keep** (uses only netlink path) |
| ~724-767 | `BpfLoader::ConfigureListenerSocket` | **Rewrite** to call `bpf_map__update_elem` instead of the deleted helpers |
| ~769-787 | listener_socket_fd / listener_port / IsIngressAttached / testing helpers | **Partial rewrite** (delete `BuildIngressProgramForTesting` and `MarkIngressAttachedForTesting`; add `LoadProgramForTesting`) |

The simplest execution pattern is: **overwrite the file wholesale** with the body in Step 4.2.2 rather than incrementally delete sections. The table above is for review and comprehension only.

- [ ] **Step 4.2.2: Overwrite `src/bpf/loader.cpp`**

Write the new file with the content below. The netlink helpers in the anonymous namespace are copied verbatim from today's `loader.cpp`; only load/map creation and the lifecycle methods change.

**Skeleton naming:** the generated header creates a struct named after the `.bpf.c` basename minus `.bpf.c`, combined with the skeleton target name. Because the `bpf_skeleton` target is named `ingress_redirect_skel` and the `.linked.o` file is `ingress_redirect_skel.linked.o`, bpftool emits `struct ingress_redirect_skel { ... }` with functions `ingress_redirect_skel__open` / `__load` / `__destroy`. The Chunk 3 Step 3.4.2 verification (`head -30 bazel-bin/src/bpf/ingress_redirect_skel.skel.h`) is the authoritative check for this naming; if bpftool's actual output uses a different struct name, search-replace `ingress_redirect_skel__` across this file accordingly.

```cpp
#include "bpf/loader.hpp"

#include "bpf/ingress_redirect_skel.skel.h"
#include "shared/netlink.hpp"
#include "shared/scoped_fd.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace inline_proxy {
namespace {

// ---------------------------------------------------------------------------
// Netlink TC attach/detach helpers (copied verbatim from the pre-skeleton
// loader; unchanged by this rewrite).
// ---------------------------------------------------------------------------

bool AppendAttr(std::vector<char>& buffer, std::uint16_t type, const void* data, std::size_t size, bool nested = false) {
    constexpr std::size_t kAlignTo = 4;
    const auto align = [](std::size_t value) { return (value + kAlignTo - 1) & ~(kAlignTo - 1); };

    const auto old_size = buffer.size();
    const auto total_size = NLA_HDRLEN + size;
    buffer.resize(old_size + align(total_size));

    auto* attr = reinterpret_cast<nlattr*>(buffer.data() + old_size);
    attr->nla_type = nested ? static_cast<std::uint16_t>(type | NLA_F_NESTED) : type;
    attr->nla_len = static_cast<std::uint16_t>(total_size);
    std::memcpy(reinterpret_cast<char*>(attr) + NLA_HDRLEN, data, size);
    std::memset(reinterpret_cast<char*>(attr) + total_size, 0, align(total_size) - total_size);
    return true;
}

bool AppendStringAttr(std::vector<char>& buffer, std::uint16_t type, const std::string& value, bool nested = false) {
    return AppendAttr(buffer, type, value.c_str(), value.size() + 1, nested);
}

std::vector<char> MakeNetlinkMessage(std::uint16_t type, std::uint16_t flags, unsigned int ifindex = 0) {
    std::vector<char> message(NLMSG_LENGTH(sizeof(tcmsg)));
    auto* header = reinterpret_cast<nlmsghdr*>(message.data());
    header->nlmsg_len = static_cast<std::uint32_t>(message.size());
    header->nlmsg_type = type;
    header->nlmsg_flags = static_cast<std::uint16_t>(flags | NLM_F_REQUEST | NLM_F_ACK);
    header->nlmsg_seq = 1;

    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(header));
    std::memset(tc, 0, sizeof(*tc));
    tc->tcm_family = AF_UNSPEC;
    tc->tcm_ifindex = static_cast<int>(ifindex);
    tc->tcm_handle = 0;
    tc->tcm_parent = TC_H_UNSPEC;
    return message;
}

class NetlinkSocket {
public:
    static std::optional<NetlinkSocket> Open() {
        ScopedFd fd(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
        if (!fd) {
            return std::nullopt;
        }
        sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        local.nl_pid = static_cast<unsigned int>(::getpid());
        if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            return std::nullopt;
        }
        return NetlinkSocket(std::move(fd));
    }

    bool Send(const std::vector<char>& request) const {
        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        return ::sendto(fd_.get(), request.data(), request.size(), 0,
                        reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel)) >= 0;
    }

    bool ReceiveAck() const {
        std::array<char, 8192> buffer{};
        while (true) {
            const auto length = ::recv(fd_.get(), buffer.data(), buffer.size(), 0);
            if (length < 0) {
                if (errno == EINTR) continue;
                return false;
            }
            auto remaining = static_cast<unsigned int>(length);
            for (nlmsghdr* header = reinterpret_cast<nlmsghdr*>(buffer.data());
                 NLMSG_OK(header, remaining);
                 header = NLMSG_NEXT(header, remaining)) {
                if (header->nlmsg_type == NLMSG_ERROR) {
                    const auto* error = reinterpret_cast<nlmsgerr*>(NLMSG_DATA(header));
                    return error->error == 0;
                }
                if (header->nlmsg_type == NLMSG_DONE) return true;
            }
        }
    }

private:
    explicit NetlinkSocket(ScopedFd fd) : fd_(std::move(fd)) {}
    ScopedFd fd_;
};

bool SendNetlinkRequest(std::vector<char> request) {
    auto socket = NetlinkSocket::Open();
    if (!socket) return false;
    if (!socket->Send(request)) return false;
    return socket->ReceiveAck();
}

void FinalizeNetlinkMessage(std::vector<char>& request) {
    auto* header = reinterpret_cast<nlmsghdr*>(request.data());
    header->nlmsg_len = static_cast<std::uint32_t>(request.size());
}

bool EnsureClsactQdisc(unsigned int ifindex) {
    auto request = MakeNetlinkMessage(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_CLSACT;
    tc->tcm_handle = 0;
    AppendStringAttr(request, TCA_KIND, "clsact");
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool RemoveIngressFilter(unsigned int ifindex) {
    auto request = MakeNetlinkMessage(RTM_DELTFILTER, 0, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    tc->tcm_handle = 0;
    tc->tcm_info = htons(ETH_P_ALL);
    AppendStringAttr(request, TCA_KIND, "bpf");
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

bool AttachIngressFilter(unsigned int ifindex, int program_fd) {
    auto request = MakeNetlinkMessage(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE, ifindex);
    auto* tc = reinterpret_cast<tcmsg*>(NLMSG_DATA(reinterpret_cast<nlmsghdr*>(request.data())));
    tc->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    tc->tcm_handle = 0;
    tc->tcm_info = htons(ETH_P_ALL);

    AppendStringAttr(request, TCA_KIND, "bpf");

    std::vector<char> options;
    AppendAttr(options, TCA_BPF_FD, &program_fd, sizeof(program_fd));
    const std::string name = "ingress_redirect";
    AppendStringAttr(options, TCA_BPF_NAME, name);
    const std::uint32_t flags = TCA_BPF_FLAG_ACT_DIRECT;
    AppendAttr(options, TCA_BPF_FLAGS, &flags, sizeof(flags));

    AppendAttr(request, TCA_OPTIONS, options.data(), options.size(), true);
    FinalizeNetlinkMessage(request);
    return SendNetlinkRequest(std::move(request));
}

}  // namespace

// ---------------------------------------------------------------------------
// BpfLoader public API
// ---------------------------------------------------------------------------

BpfLoader::~BpfLoader() {
    if (skel_ != nullptr) {
        ingress_redirect_skel__destroy(skel_);
        skel_ = nullptr;
    }
}

bool BpfLoader::EnsureSkeletonLoaded() {
    if (skel_ != nullptr) {
        return true;
    }
    skel_ = ingress_redirect_skel__open();
    if (skel_ == nullptr) {
        std::cerr << "ingress_redirect_skel__open failed errno=" << errno << '\n';
        return false;
    }
    if (int err = ingress_redirect_skel__load(skel_); err != 0) {
        std::cerr << "ingress_redirect_skel__load failed errno=" << -err << " ("
                  << std::strerror(-err) << ")\n";
        ingress_redirect_skel__destroy(skel_);
        skel_ = nullptr;
        return false;
    }
    return true;
}

bool BpfLoader::UpdateConfigAndListenerMaps(const IngressRedirectConfig& config,
                                            std::optional<int> listener_fd) {
    if (skel_ == nullptr) return false;

    const std::uint32_t key = 0;
    if (int err = bpf_map__update_elem(skel_->maps.config_map,
                                       &key, sizeof(key),
                                       &config, sizeof(config),
                                       BPF_ANY);
        err != 0) {
        std::cerr << "bpf_map__update_elem(config_map) failed err=" << err << '\n';
        return false;
    }
    if (listener_fd) {
        const std::uint32_t fd_value = static_cast<std::uint32_t>(*listener_fd);
        if (int err = bpf_map__update_elem(skel_->maps.listener_map,
                                           &key, sizeof(key),
                                           &fd_value, sizeof(fd_value),
                                           BPF_ANY);
            err != 0) {
            std::cerr << "bpf_map__update_elem(listener_map) failed err=" << err << '\n';
            return false;
        }
    }
    return true;
}

bool BpfLoader::AttachIngress(std::string_view interface_name) {
    if (interface_name.empty() || interface_name.rfind("wan_", 0) != 0) {
        std::cerr << "attach-ingress rejected invalid interface name: " << interface_name << '\n';
        return false;
    }
    if (!listener_socket_fd_ || listener_port_ == 0) {
        std::cerr << "attach-ingress missing configured listener socket/port for "
                  << interface_name << '\n';
        return false;
    }
    if (IsIngressAttached(interface_name)) {
        return true;
    }

    const std::string iface_name(interface_name);
    const auto ifindex = LinkIndex(iface_name);
    if (!ifindex || *ifindex == 0) {
        std::cerr << "attach-ingress failed to resolve ifindex for " << iface_name << '\n';
        return false;
    }

    if (!EnsureSkeletonLoaded()) {
        std::cerr << "attach-ingress failed to load skeleton for " << iface_name << '\n';
        return false;
    }
    if (!UpdateConfigAndListenerMaps(runtime_config_, listener_socket_fd_)) {
        std::cerr << "attach-ingress failed to populate maps for " << iface_name << '\n';
        return false;
    }
    if (!EnsureClsactQdisc(*ifindex)) {
        std::cerr << "attach-ingress failed to ensure clsact qdisc for " << iface_name
                  << " ifindex=" << *ifindex << '\n';
        return false;
    }
    const int program_fd = bpf_program__fd(skel_->progs.ingress_redirect);
    if (program_fd < 0) {
        std::cerr << "attach-ingress could not obtain program fd for " << iface_name << '\n';
        return false;
    }
    if (!AttachIngressFilter(*ifindex, program_fd)) {
        std::cerr << "attach-ingress failed to attach tc filter for " << iface_name
                  << " ifindex=" << *ifindex << " program_fd=" << program_fd << '\n';
        return false;
    }

    std::cerr << "attach-ingress ok iface=" << iface_name
              << " ifindex=" << *ifindex
              << " intercept_port=" << runtime_config_.listener_port
              << " listener_fd=" << *listener_socket_fd_ << '\n';
    attached_interfaces_.insert(iface_name);
    return true;
}

bool BpfLoader::DetachIngress(std::string_view interface_name) {
    if (interface_name.empty() || interface_name.rfind("wan_", 0) != 0) {
        return false;
    }
    const std::string iface_name(interface_name);
    const auto attached = attached_interfaces_.find(iface_name);
    if (attached == attached_interfaces_.end()) {
        return false;
    }
    const auto ifindex = LinkIndex(iface_name);
    if (!ifindex || *ifindex == 0) {
        return false;
    }
    if (!RemoveIngressFilter(*ifindex)) {
        return false;
    }
    attached_interfaces_.erase(attached);
    return true;
}

bool BpfLoader::ConfigureListenerSocket(int listener_fd, std::uint32_t intercept_port) {
    if (listener_fd < 0) {
        return false;
    }
    sockaddr_storage addr{};
    socklen_t addrlen = sizeof(addr);
    if (::getsockname(listener_fd, reinterpret_cast<sockaddr*>(&addr), &addrlen) != 0) {
        return false;
    }
    std::uint32_t listener_port = 0;
    if (addr.ss_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(&addr);
        listener_port = ntohs(v4->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        listener_port = ntohs(v6->sin6_port);
    }
    if (listener_port == 0) {
        return false;
    }
    if (intercept_port == 0) {
        intercept_port = listener_port;
    }

    IngressRedirectConfig new_runtime_config{};
    new_runtime_config.enabled = 1;
    new_runtime_config.listener_port = intercept_port;
    new_runtime_config.skb_mark = 0x100;

    // Push into the live maps only if the skeleton has already been
    // loaded; otherwise cache and we flush at lazy AttachIngress load.
    // Mirrors today's loader, which also does not roll back cached state
    // on partial map-update failure.
    if (skel_ != nullptr) {
        if (!UpdateConfigAndListenerMaps(new_runtime_config, listener_fd)) {
            return false;
        }
    }
    listener_socket_fd_ = listener_fd;
    listener_port_ = listener_port;
    runtime_config_ = new_runtime_config;
    return true;
}

std::optional<int> BpfLoader::listener_socket_fd() const noexcept {
    return listener_socket_fd_;
}

std::uint32_t BpfLoader::listener_port() const noexcept {
    return listener_port_;
}

bool BpfLoader::IsIngressAttached(std::string_view interface_name) const {
    return attached_interfaces_.find(std::string(interface_name)) != attached_interfaces_.end();
}

bool BpfLoader::LoadProgramForTesting() {
    return EnsureSkeletonLoaded();
}

}  // namespace inline_proxy
```

- [ ] **Step 4.2.3: Update `src/bpf/BUILD.bazel` so `:loader` depends on the skeleton target and libbpf**

Edit `src/bpf/BUILD.bazel` to add the dependency. The `cc_library(name = "loader", ...)` rule becomes:

```python
cc_library(
    name = "loader",
    srcs = ["loader.cpp"],
    hdrs = [
        "ingress_redirect_common.h",
        "loader.hpp",
    ],
    deps = [
        ":ingress_redirect_skel",
        "//src/shared:shared",
        "@libbpf//:libbpf",
    ],
    include_prefix = "bpf",
)
```

- [ ] **Step 4.2.4: Build `//src/bpf:loader`**

```bash
bazel build //src/bpf:loader
```

Expected: builds cleanly. If it fails:
- **"ingress_redirect_skel.skel.h: No such file or directory"** → the `:loader` target does not depend on `:ingress_redirect_skel`; re-check Step 4.2.3.
- **Undefined reference to `bpf_map__update_elem` or `bpf_program__fd`** → `@libbpf//:libbpf` is not being pulled in; re-check Step 4.2.3 and Chunk 1's libbpf BUILD.
- **Undefined reference to `ingress_redirect_skel__open`** → the skeleton header is found at compile time but the function is defined inline in the `.skel.h` and must be compiled into the object. This is normal bpftool-generated code; the only way this fails is if the skeleton header is truncated. Re-run `bazel build //src/bpf:ingress_redirect_skel` and inspect it.

- [ ] **Step 4.2.5: Build the full tree**

```bash
bazel build //...
```

Expected: everything builds. `proxy_daemon` now statically links libbpf.

- [ ] **Step 4.2.6: Commit**

```bash
git add src/bpf/loader.cpp src/bpf/BUILD.bazel
git commit -m "Drive BpfLoader through the generated skeleton"
```

### Task 4.3: Update tests

**Files:**
- Modify: `tests/bpf_loader_test.cpp`

- [ ] **Step 4.3.1: Delete the two tests that target removed helpers**

In `tests/bpf_loader_test.cpp`, delete:

- `TEST(BpfLoaderTest, PreservesAttachedStateWhenDetachFails)` — its only mechanism, `MarkIngressAttachedForTesting`, is gone.
- `TEST(BpfLoaderTest, GeneratedProgramUsesConfiguredListenerPort)` — the handwritten opcode generator it asserts is gone.

- [ ] **Step 4.3.2: Add the new `LoadsSkeleton` test**

Append to `tests/bpf_loader_test.cpp`:

```cpp
#include <unistd.h>  // geteuid

TEST(BpfLoaderTest, LoadsSkeleton) {
    if (::geteuid() != 0) {
        GTEST_SKIP() << "Requires root / CAP_BPF";
    }
    inline_proxy::BpfLoader loader;
    EXPECT_TRUE(loader.LoadProgramForTesting());
}
```

This mirrors the skip pattern used by `FdNetnsHarness::HasRequiredPrivileges()` in the existing netns test and avoids pulling in a new libcap link-time dependency. A non-root developer without `CAP_BPF` sees the test skip rather than fail — matching the spec's "skipped (not failed) when running without CAP_BPF" requirement.

- [ ] **Step 4.3.3: Build and run the test suite**

```bash
bazel test //tests:bpf_loader_test
```

Expected: the three kept tests plus the new `LoadsSkeleton` test run. `LoadsSkeleton` may skip if the test runner lacks CAP_BPF; skipping is not a failure.

- [ ] **Step 4.3.4: Run the full netns end-to-end test unchanged**

```bash
bazel test //tests:ebpf_intercept_fd_netns_test
```

Expected: passes, unchanged. This is the **ground-truth behavior test** — if it fails, the rewritten program has a behavior regression vs. the handwritten one, and the parity table in the spec must be re-walked against the `.bpf.c`.

If it fails:
- Inspect kernel logs (`dmesg | tail -50`) for verifier rejection messages.
- If the verifier rejects the program, the rewritten `.bpf.c` has a CO-RE-level mismatch with what the handwritten program emitted. The two most likely culprits: the sockmap-derived socket being passed to `bpf_sk_release`, or a missing `__VMLINUX_H__` guard on the shared header.

- [ ] **Step 4.3.5: Run the full test suite and diff against the baseline**

```bash
bazel test //tests/... 2>&1 | tee /tmp/bpf-skel-plan-chunk4.txt
diff /tmp/bpf-skel-plan-baseline.txt /tmp/bpf-skel-plan-chunk4.txt || true
```

Expected: the two removed tests no longer appear; one new test (`LoadsSkeleton`) appears in place; no other test transitions from pass to fail.

- [ ] **Step 4.3.6: Commit**

```bash
git add tests/bpf_loader_test.cpp
git commit -m "Retire handwritten-codegen tests; add skeleton-load sanity test"
```

---


## Chunk 5: Full verification

**Objective:** Confirm the rewrite is complete, the spec's parity table is satisfied, and nothing else regressed. This chunk produces no code; it is a checklist.

### Task 5.1: Parity-table walkthrough

**Files:**
- No changes. Review only.

- [ ] **Step 5.1.1: Open the spec's parity table alongside the rewritten `.bpf.c`**

Open both side by side:

```bash
less docs/superpowers/specs/2026-04-19-bpf-skeleton-loader-design.md
less src/bpf/ingress_redirect.bpf.c
```

Walk every row in the "Semantic parity table" (Decisions section 5). For each row, find the corresponding construct in `ingress_redirect.bpf.c` and confirm the mapping is faithful. Record any divergence; there should be none.

- [ ] **Step 5.1.2: Record the walkthrough result**

If every row maps cleanly, no action. If any row does not map, stop and fix either the `.bpf.c` or (if the divergence is intentional and justified) the spec.

### Task 5.2: End-to-end test as the acceptance criterion

**Files:**
- No changes.

- [ ] **Step 5.2.1: Run the ground-truth test**

```bash
bazel test //tests:ebpf_intercept_fd_netns_test
```

Expected: passes. This is the acceptance criterion for the rewrite — the test exercises a real BPF program in a real netns and verifies interception end-to-end. It was kept deliberately **unchanged** through the rewrite so that a passing run is strong evidence the new program matches the old program's observable behavior.

If it fails, the root cause is almost always one of:
- Verifier rejection (check `dmesg | tail`)
- A missing trace line or re-ordered instruction that affects the program shape
- A mis-sized struct in `ingress_redirect_common.h` (the config struct layout must match what the BPF side sees)

### Task 5.3: Full test suite and full build

**Files:**
- No changes.

- [ ] **Step 5.3.1: Full build**

```bash
bazel build //...
```

Expected: everything builds cleanly, including `proxy_daemon` now statically linked against vendored libbpf.

- [ ] **Step 5.3.2: Full test suite with baseline diff**

```bash
bazel test //tests/... 2>&1 | tee /tmp/bpf-skel-plan-final.txt
diff /tmp/bpf-skel-plan-baseline.txt /tmp/bpf-skel-plan-final.txt || true
```

Expected changes vs. baseline:
- `PreservesAttachedStateWhenDetachFails` and `GeneratedProgramUsesConfiguredListenerPort` no longer appear.
- `LoadsSkeleton` appears.
- All other tests pass or skip identically.

No pre-existing test that used to pass should fail after the rewrite.

### Task 5.4: Binary size sanity check

**Files:**
- No changes.

- [ ] **Step 5.4.1: Confirm static linking worked**

```bash
ls -l bazel-bin/src/proxy/proxy_daemon
file bazel-bin/src/proxy/proxy_daemon
ldd bazel-bin/src/proxy/proxy_daemon | grep -i bpf || echo "no dynamic libbpf (good)"
```

Expected:
- `file` reports an ELF executable.
- `ldd` does **not** list `libbpf.so.*` (the rewrite links libbpf statically).
- Binary size grew by roughly the size of the libbpf static archive (~500 KB-1 MB); note the delta for the commit message.

### Task 5.5: Deploy-path sanity (optional, manual)

**Files:**
- No changes.

- [ ] **Step 5.5.1: Rebuild the proxy container image and smoke-deploy (optional)**

If the team's deploy flow (`deploy/scripts/install-cni.sh`, the Kustomize manifests under `deploy/base/`) is exercisable locally, run it and confirm the annotated-pod interception demo still works. This is out of scope for the strict spec ("No coordination with the pending router-style redesign"), but is a cheap final confidence check. Skipping is fine.

### Task 5.6: Final cleanup

**Files:**
- No changes expected. Verify nothing stray.

- [ ] **Step 5.6.1: Check there are no leftover references to removed APIs**

```bash
grep -rEn 'BuildIngressProgramForTesting|MarkIngressAttachedForTesting|ProgramBuilder|MakeInsn|SysBpf' src tests
```

Expected output: empty. If any match appears, the corresponding file was missed during the rewrite.

- [ ] **Step 5.6.2: Check the stale helper-ID enum can now be removed in a follow-up** (per spec, this is a separate future commit; do not remove here)

```bash
grep -rn 'INGRESS_REDIRECT_HELPER_' src tests
```

Expected: the enum is still referenced only by `ingress_redirect_common.h`. Confirmed unused by everything else — recorded as an open follow-up cleanup, not part of this rewrite.

- [ ] **Step 5.6.3: Ensure commits are in a clean state**

```bash
git log --oneline origin/main..HEAD
```

Expected: a tidy series of commits, one per task, matching the commit messages listed in the plan.

---

## Done

The skeleton loader rewrite is complete. Follow-up cleanups (explicitly out of scope for this plan; recorded in the spec):

1. Delete the obsolete `INGRESS_REDIRECT_HELPER_*` enum and `INGRESS_REDIRECT_MAP_KEY_ZERO` / `INGRESS_REDIRECT_IPV4_WIRE_VALUE` / `INGRESS_REDIRECT_TCP_PROTOCOL` constants from `ingress_redirect_common.h` once an appropriate moment arises.
2. Switch the TC attach path from hand-rolled netlink to libbpf's `bpf_tc_*` APIs, if the redundancy becomes bothersome.
3. Introduce a hermetic LLVM toolchain via `toolchains_llvm` so the macro no longer depends on host `/usr/bin/clang-19`.

None of these are required for correctness.
