import hashlib
from _socket import gethostbyaddr

from bcc import BPF
import ctypes as ct
import pyroute2
gethostbyaddr

from scapy.all import *

from pyroute2 import NetlinkError
from scapy.layers.inet import IP, UDP

from conf import read_configuration

FLAG_BYTES = bytearray(b'\xca\xfe')

EGRESS_PARENT = 0xFFFFFFF3
ETHERNET_HEADER_BYTES = 14
IP_HEADER_BYTES = 20
UDP_HEADER_BYTES = 8
count = 0

config = read_configuration('config.ini')

PORTS_TO_TRACK = config.sender_ports_to_duplicate


def print_skb_event(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ = [
            ("saddr", ct.c_uint32),
            ("sport", ct.c_uint16),

            ("daddr", ct.c_uint32),
            ("dport", ct.c_uint16),

            ("length", ct.c_uint16),
            ("raw", ct.c_ubyte * size),
        ]

    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    bytes_src = struct.pack('!L', skb_event.saddr)
    bytes_dst = struct.pack('!L', skb_event.daddr)

    src = socket.inet_ntoa(bytes_src)
    dst = socket.inet_ntoa(bytes_dst)

    payload_length = skb_event.length - UDP_HEADER_BYTES
    body_bytearray = bytearray(skb_event.raw[ETHERNET_HEADER_BYTES + IP_HEADER_BYTES + UDP_HEADER_BYTES:][:payload_length])
    print("%-32s %-16s %-32s %-16s %d" % (src, skb_event.sport, dst, skb_event.dport, len(skb_event.raw)))

    hash_bytearray = bytearray(hashlib.sha256(body_bytearray).digest())
    body_and_hash = bytearray(body_bytearray)
    body_and_hash.extend(FLAG_BYTES)
    body_and_hash.extend(hash_bytearray)
    body_and_hash.extend(count.to_bytes(4, byteorder='big'))
    body_and_hash.extend(FLAG_BYTES)

    if config.sender_interface == 'lo':
        conf.L3socket = L3RawSocket
    send(IP(dst=dst) / UDP(dport=skb_event.dport, sport=skb_event.sport) / Raw(body_and_hash), iface=config.sender_interface)


ipr = pyroute2.IPRoute()
b = BPF(src_file="ebpf.c")
fn = b.load_func("tc_handle_egress", BPF.SCHED_CLS)
ethernet = ipr.link_lookup(ifname=config.sender_interface)[0]

try:
    ipr.tc(
            "add",
            "clsact",
            ethernet,
    )
except NetlinkError:
    ...

ipr.tc(
        "add-filter",
        "bpf",
        ethernet,
        "0:1",
        fd=fn.fd,
        name=fn.name,
        parent=0xFFFFFFF3,
        classid=1,
        direct_action=True,
)

b["egress_ports"].clear()
value = ct.c_int(1)
for port in PORTS_TO_TRACK:
    key = ct.c_int(port)
    b["egress_ports"][key] = value

b["skb_events"].open_perf_buffer(print_skb_event)
print("%-32s %-16s %-32s %-16s payload-length" % ("SRC IP", "SRC PORT", "DST IP", "DST PORT"))
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    ...
