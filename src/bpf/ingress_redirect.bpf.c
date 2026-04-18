#ifndef __BPF_INGRESS_REDIRECT_BPF_C__
#define __BPF_INGRESS_REDIRECT_BPF_C__

/*
 * First-pass ingress steering for WAN interfaces.
 *
 * The program:
 * - looks up a single runtime config record
 * - checks for Ethernet/IPv4/TCP traffic
 * - matches the TCP destination port against the configured listener port
 * - redirects matching traffic to the configured ingress handoff target
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

static inline struct ingress_redirect_config* lookup_runtime_config(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&redirect_config_map, &key);
}

SEC("tc")
int redirect_ingress(struct __sk_buff* skb) {
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    struct ingress_redirect_config* config = lookup_runtime_config();
    struct ethhdr* eth;
    struct iphdr* iph;
    struct tcphdr* tcph;
    __u8 ihl_bytes;

    if (!config || !config->enabled || !config->listener_port || !config->redirect_ifindex) {
        return TC_ACT_OK;
    }

    eth = data;
    if ((void*)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    iph = (void*)(eth + 1);
    if ((void*)(iph + 1) > data_end) {
        return TC_ACT_OK;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    ihl_bytes = (__u8)(iph->ihl * 4);
    if (ihl_bytes < sizeof(*iph)) {
        return TC_ACT_OK;
    }

    tcph = (void*)((char*)iph + ihl_bytes);
    if ((void*)(tcph + 1) > data_end) {
        return TC_ACT_OK;
    }
    if (tcph->dest != (__be16)config->listener_port) {
        return TC_ACT_OK;
    }

    return bpf_redirect((int)config->redirect_ifindex, BPF_F_INGRESS);
}

char _license[] SEC("license") = "GPL";

#endif  // __BPF_INGRESS_REDIRECT_BPF_C__
