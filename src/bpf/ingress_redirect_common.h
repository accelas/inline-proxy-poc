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

// Temporarily retained so the not-yet-rewritten loader.cpp keeps building
// through Chunks 3 and 4. Removed in Chunk 4 once loader.cpp uses the
// skeleton and no longer references these helper IDs.
enum {
    INGRESS_REDIRECT_MAP_KEY_ZERO = 0u,
    INGRESS_REDIRECT_HELPER_MAP_LOOKUP_ELEM = 1,
    INGRESS_REDIRECT_HELPER_TRACE_PRINTK = 6,
    INGRESS_REDIRECT_HELPER_SKB_LOAD_BYTES = 26,
    INGRESS_REDIRECT_HELPER_SKC_LOOKUP_TCP = 99,
    INGRESS_REDIRECT_HELPER_SK_LOOKUP_TCP = 84,
    INGRESS_REDIRECT_HELPER_SK_RELEASE = 86,
    INGRESS_REDIRECT_HELPER_SK_ASSIGN = 124,
};

static const __u32 INGRESS_REDIRECT_IPV4_WIRE_VALUE = 0x0008u;
static const __u32 INGRESS_REDIRECT_TCP_PROTOCOL = 6u;

// The INGRESS_REDIRECT_HELPER_* enum and INGRESS_REDIRECT_IPV4_WIRE_VALUE /
// INGRESS_REDIRECT_TCP_PROTOCOL / INGRESS_REDIRECT_MAP_KEY_ZERO constants
// are kept for now but scheduled for removal in Chunk 4's follow-up cleanup.
// The CO-RE BPF program uses libbpf's idiomatic forms (bpf_htons(ETH_P_IP),
// IPPROTO_TCP from vmlinux.h, a local __u32 key = 0).

#endif  // INLINE_PROXY_BPF_INGRESS_REDIRECT_COMMON_H_
