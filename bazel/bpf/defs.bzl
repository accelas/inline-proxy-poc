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

    # libbpf BPF-side headers needed by CO-RE programs (#include <bpf/...>).
    # Adding them as srcs makes Bazel place them in the sandbox and lets us
    # derive the -I path from one sentinel file.
    _libbpf_bpf_hdrs = [
        "@libbpf//:bpf/bpf_core_read.h",
        "@libbpf//:bpf/bpf_endian.h",
        "@libbpf//:bpf/bpf_helper_defs.h",
        "@libbpf//:bpf/bpf_helpers.h",
        "@libbpf//:bpf/bpf_tracing.h",
    ]
    # Sentinel used to derive the -I path: strip the trailing "/bpf/bpf_helpers.h".
    _sentinel = "@libbpf//:bpf/bpf_helpers.h"

    native.genrule(
        name = name + "_compile",
        srcs = [src] + hdrs + _libbpf_bpf_hdrs,
        outs = [obj],
        cmd = " ".join([
            _CLANG,
            _clang_copts,
            "-I $$(dirname $(location " + src + "))",
            # Parent of the bpf/ directory, so #include <bpf/bpf_helpers.h> works.
            "-I $$(dirname $$(dirname $(location " + _sentinel + ")))",
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
        cmd = "$(location @host_bpftool//:bpftool) gen skeleton $(location " + linked + ") name " + name + " > $@",
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
