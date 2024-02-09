import dnslib
import fcntl
import os
import sys

from bcc import BPF

BPF_APP = r'''
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bcc/proto.h>
int dns_matching(struct __sk_buff *skb) {
    u8 *cursor = 0;
     // Checking the IP protocol:
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (ethernet->type == ETH_P_IP) {
         // Checking the UDP protocol:
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        if (ip->nextp == IPPROTO_UDP) {
	    bpf_trace_printk("incoming udp\\n");
        }
    }
    return 0;
}
'''


bpf = BPF(text=BPF_APP)
function_dns_matching = bpf.load_func("dns_matching", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(function_dns_matching, 'eno1')
bpf.trace_print()

