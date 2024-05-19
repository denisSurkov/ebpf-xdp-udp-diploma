from bcc import BPF
import ctypes as ct
import pyroute2

import socket, struct


EGRESS_PARENT = 0xFFFFFFF3


def print_skb_event(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ = [
            ("saddr", ct.c_uint32),
            ("sport", ct.c_uint16),

            ("daddr", ct.c_uint32),
            ("dport", ct.c_uint16),
            ("raw", ct.c_ubyte * (size - (ct.sizeof(ct.c_uint32) * 2 + ct.sizeof(ct.c_uint16) * 2)))
        ]

    print(size)
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    bytes_src = struct.pack('!L', skb_event.saddr)
    bytes_dst = struct.pack('!L', skb_event.daddr)

    src = socket.inet_ntoa(bytes_src)
    dst = socket.inet_ntoa(bytes_dst)
    print("%-32s %-16s %-32s %-16s %d" % (src, skb_event.sport, dst, skb_event.dport, len(skb_event.raw)))
    print(bytearray(skb_event.raw[-32:]).decode('ascii'))


ipr = pyroute2.IPRoute()
b = BPF(src_file="ebpf/egress.c")
fn = b.load_func("handle_egress", BPF.SCHED_CLS)
ethernet = ipr.link_lookup(ifname="eno1")[0]


filter_payload = {
    'kind': 'bpf',
    'index': ethernet,
    'classid': 1,
    'fd': fn.fd,
    'name': fn.name,
    'parent': EGRESS_PARENT,
    'direct_action': True,
    'handle': '0:1',
}

ipr.tc(
        "add-filter",
        **filter_payload,
)

b["skb_events"].open_perf_buffer(print_skb_event)
print("%-32s %-16s %-32s %-16s payload-length" % ("SRC IP", "SRC PORT", "DST IP", "DST PORT"))
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass
