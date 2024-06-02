#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define DUPLICATION_MARKER 0xcafe


struct udp_event {
    u32 saddr;
    u16 sport;

    u32 daddr;
    u16 dport;

    u16 length;
};


BPF_HASH(deduplicate_ports, u16, u8);

int xdp_handle_ingress(struct xdp_md *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = (data + sizeof(struct ethhdr));
    struct udphdr *udp = ((void *) ip + sizeof(struct iphdr));

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    struct udp_event event = {};
    event.saddr = bpf_htonl(ip->saddr);
    event.daddr = bpf_htonl(ip->daddr);
    event.sport = bpf_htons(udp->source);
    event.dport = bpf_htons(udp->dest);
    event.length = bpf_htons(udp->len);

    if (deduplicate_ports.lookup(&event.dport) == NULL) {
        return XDP_PASS;
    }

    u16 marker;
    long ret = bpf_xdp_load_bytes(
            ctx,
            sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr),
            &marker,
            sizeof(marker)
    );

    if (ret != 0) {
        return XDP_PASS;
    }

    marker = bpf_htons(marker);
    if (marker == DUPLICATION_MARKER) {
        return XDP_DROP;
    }

    return XDP_PASS;
}
