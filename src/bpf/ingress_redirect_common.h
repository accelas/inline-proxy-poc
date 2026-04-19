#ifndef INLINE_PROXY_BPF_INGRESS_REDIRECT_COMMON_H_
#define INLINE_PROXY_BPF_INGRESS_REDIRECT_COMMON_H_

// This header is included from both:
//   - src/bpf/loader.cpp (user-space C++; wants <linux/bpf.h> for __u32 etc.)
//   - src/bpf/ingress_redirect.bpf.c (CO-RE BPF program; already has
//     vmlinux.h's kernel type definitions, must not re-include <linux/bpf.h>)
// __VMLINUX_H__ is the include guard bpftool's `btf dump format c` output
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

#endif  // INLINE_PROXY_BPF_INGRESS_REDIRECT_COMMON_H_
