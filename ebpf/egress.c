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


struct processed_request_key {
    char key[32];
};


BPF_PERF_OUTPUT(skb_events);

BPF_HASH(processed_requests, struct processed_request_key, u8);

BPF_HASH(ingress_ports, u16, u8);

BPF_HASH(egress_ports, u16, u8);


static int check_is_udp_packet(void *data, void *data_end) {
    struct ethhdr *eth = data;
    struct iphdr *ip = (data + sizeof(struct ethhdr));

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
        return 0;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    if (ip->protocol != IPPROTO_UDP) {
        return 0;
    }

    return 1;
}


int tc_handle_egress(struct __sk_buff *skb) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    struct iphdr *ip = (data + sizeof(struct ethhdr));
    struct udphdr *udp = ((void *) ip + sizeof(struct iphdr));

    if (check_is_udp_packet(data, data_end) == 0) {
        return TC_ACT_OK;
    }

    struct udp_event event = {};
    event.saddr = bpf_htonl(ip->saddr);
    event.daddr = bpf_htonl(ip->daddr);
    event.sport = bpf_htons(udp->source);
    event.dport = bpf_htons(udp->dest);
    event.length = bpf_htons(udp->len);

    if (egress_ports.lookup(&event.dport) == NULL) {
        return TC_ACT_OK;
    }

    u16 udp_body_length = bpf_ntohs(udp->len) - 8;
    if (2 + 32 + 2 > udp_body_length) {
        goto shot;
    }

    u16 marker;
    int ret = bpf_skb_load_bytes(
            skb,
            sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + udp_body_length - 2,
            &marker,
            sizeof(marker)
    );
    if (ret != 0) {
        return TC_ACT_OK;
    }

    marker = bpf_htons(marker);
    if (marker == DUPLICATION_MARKER) {
        return TC_ACT_OK;
    }


shot:
    skb_events.perf_submit_skb(skb, skb->len, &event, sizeof(event));
    return TC_ACT_SHOT;
}