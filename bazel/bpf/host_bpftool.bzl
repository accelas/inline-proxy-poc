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
