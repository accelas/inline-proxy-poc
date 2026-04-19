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
