#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

BPF_PERF_OUTPUT(skb_events);

BPF_HASH(tracking_ports, u16, u8);

struct udp_event {
    u32 saddr;
    u16 sport;

    u32 daddr;
    u16 dport;

    u16 length;
    u32 marker;
};



int handle_egress(struct __sk_buff *skb) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    u32 marker;
    struct ethhdr *eth = data;
    struct iphdr *ip = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_UDP) {
        return TC_ACT_OK;
    }
    struct udp_event event = {};
    event.saddr = bpf_htonl(ip->saddr);
    event.daddr = bpf_htonl(ip->daddr);
    event.sport = bpf_htons(udp->source);
    event.dport = bpf_htons(udp->dest);
    event.length = bpf_htons(udp->len);

    if (tracking_ports.lookup(&event.dport) == NULL) {
        return TC_ACT_OK;
    }

    int ret = bpf_skb_load_bytes(
            skb,
            sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr),
            &marker,
            sizeof(marker)
    );

    event.marker = marker;

    if (ret != 0) {
        return TC_ACT_OK;
    }

	skb_events.perf_submit_skb(skb, skb->len, &event, sizeof(event));

    return TC_ACT_OK;
//
//    if (marker == 0xCAFE) {
//        return TC_ACT_OK;
//    }
//
//    skb_events.perf_submit_skb(skb, skb->len, &event, sizeof(event));
//    return TC_ACT_SHOT;
}