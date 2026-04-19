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
