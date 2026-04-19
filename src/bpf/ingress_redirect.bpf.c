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
