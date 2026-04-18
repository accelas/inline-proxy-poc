#ifndef __BPF_INGRESS_REDIRECT_BPF_C__
#define __BPF_INGRESS_REDIRECT_BPF_C__

/*
 * Ingress steering program skeleton for WAN-facing interfaces.
 *
 * The first pass intentionally keeps the policy small:
 * - inspect the skb for Ethernet/IPv4/TCP
 * - consult a single runtime config entry
 * - redirect matching traffic to the configured ingress handoff target
 *
 * The loader updates the config map before attaching the program.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <stddef.h>

#define SEC(NAME) __attribute__((section(NAME), used))

struct ingress_redirect_config {
    __u32 enabled;
    __u32 listener_port;
    __u32 redirect_ifindex;
};

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
};

static void* (*bpf_map_lookup_elem)(void* map, const void* key) = (void*)1;
static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int offset, void* to, int len) = (void*)26;
static int (*bpf_redirect)(int ifindex, __u64 flags) = (void*)23;

enum {
    BPF_MAP_TYPE_ARRAY = 2,
};

SEC("maps")
struct bpf_map_def redirect_config_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct ingress_redirect_config),
    .max_entries = 1,
};

static inline int load_runtime_config(struct ingress_redirect_config** config, struct __sk_buff* skb) {
    __u32 key = 0;
    *config = bpf_map_lookup_elem(&redirect_config_map, &key);
    return *config != 0;
}

SEC("tc")
int redirect_ingress(struct __sk_buff* skb) {
    struct ingress_redirect_config* config = 0;
    __u16 eth_proto = 0;
    __u8 ip_proto = 0;

    if (!load_runtime_config(&config, skb)) {
        return TC_ACT_OK;
    }
    if (!config->enabled || !config->redirect_ifindex) {
        return TC_ACT_OK;
    }
    if (bpf_skb_load_bytes(skb, 12, &eth_proto, sizeof(eth_proto)) < 0) {
        return TC_ACT_OK;
    }
    if (eth_proto != __builtin_bswap16(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    if (bpf_skb_load_bytes(skb, (int)sizeof(struct ethhdr) + offsetof(struct iphdr, protocol), &ip_proto, sizeof(ip_proto)) < 0) {
        return TC_ACT_OK;
    }
    if (ip_proto != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    return bpf_redirect((int)config->redirect_ifindex, BPF_F_INGRESS);
}

char _license[] SEC("license") = "GPL";

#endif  // __BPF_INGRESS_REDIRECT_BPF_C__
