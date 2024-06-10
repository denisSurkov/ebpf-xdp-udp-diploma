import hashlib
import socket
import struct
from signal import signal, SIGUSR1
from threading import Lock as ThreadLock

from bcc import BPF
import ctypes as ct
import pyroute2

from threading import Thread

from pyroute2 import NetlinkError
from scapy.all import send, Raw
from scapy.config import conf
from scapy.layers.inet import IP, UDP
from scapy.supersocket import L3RawSocket

from conf import Configuration, read_configuration
from constants import UDP_HEADER_BYTES, ETHERNET_HEADER_BYTES, IP_HEADER_BYTES, FLAG_BYTES, PACKETS_MULTIPLIER
from daemon import daemonize

count = 0
_packets_to_process = []
_lock = ThreadLock()
_should_run = True
_processing_thread = None


def _usr1_handler(*_, **__):
    global _should_run
    _should_run = False


def run_egress_handler(config: Configuration):
    global _should_run

    daemonize()
    signal(SIGUSR1, _usr1_handler)

    while True:
        _run_egress_handler(config)

        config = read_configuration(config.config_path)
        _should_run = True


def _run_egress_handler(config):
    ipr = pyroute2.IPRoute()
    ebpf_program = BPF(src_file="ebpf/egress.c")
    fn = ebpf_program.load_func("tc_handle_egress", BPF.SCHED_CLS)
    interface = ipr.link_lookup(ifname=config.sender_interface)[0]

    _add_clact_filter(ipr, interface, fn)
    _set_ports_to_track(ebpf_program, config.sender_ports_to_duplicate)

    _start_processing_thread(config)

    ebpf_program["skb_events"].open_perf_buffer(process_packet)
    print("%-32s %-16s %-32s %-16s payload-length" % ("SRC IP", "SRC PORT", "DST IP", "DST PORT"))
    try:
        while _should_run:
            ebpf_program.perf_buffer_poll()
    except KeyboardInterrupt:
        ...


def _add_clact_filter(ipr, interface, function_to_add):
    try:
        ipr.tc(
                "add",
                "clsact",
                interface,
        )
    except NetlinkError:
        ...

    ipr.tc(
            "add-filter",
            "bpf",
            interface,
            "0:1",
            fd=function_to_add.fd,
            name=function_to_add.name,
            parent=0xFFFFFFF3,
            classid=1,
            direct_action=True,
    )


def _set_ports_to_track(ebpf_program, ports):
    ebpf_program["egress_ports"].clear()
    value = ct.c_int(1)

    for port in ports:
        key = ct.c_int(port)
        ebpf_program["egress_ports"][key] = value


def process_packet(cpu, data, size):
    class _SkbEvent(ct.Structure):
        _fields_ = [
            ("saddr", ct.c_uint32),
            ("sport", ct.c_uint16),

            ("daddr", ct.c_uint32),
            ("dport", ct.c_uint16),

            ("length", ct.c_uint16),
            ("raw", ct.c_ubyte * size),
        ]

    skb_event = ct.cast(data, ct.POINTER(_SkbEvent)).contents
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

    _enqueue_packet((dst, skb_event.dport, skb_event.sport, body_bytearray, hash_bytearray))


def _enqueue_packet(packet_to_add):
    with _lock:
        for _ in range(PACKETS_MULTIPLIER):
            _packets_to_process.append(packet_to_add)


def _start_processing_thread(config):
    global _processing_thread

    _processing_thread = Thread(target=_process_hashed_packets, args=(config,))
    _processing_thread.start()


def _process_hashed_packets(config):
    global count

    if config.sender_interface == 'lo':
        conf.L3socket = L3RawSocket

    while True:
        is_locked = _lock.acquire(blocking=False)
        if not is_locked:
            continue
        if not _packets_to_process:
            _lock.release()
            continue

        packet_to_process = _packets_to_process.pop()
        _lock.release()

        dst, dport, sport, body_bytes, hash_bytes = packet_to_process

        body_and_hash = bytearray(body_bytes)
        body_and_hash.extend(FLAG_BYTES)
        body_and_hash.extend(hash_bytes)
        body_and_hash.extend(count.to_bytes(4, byteorder='big'))
        body_and_hash.extend(FLAG_BYTES)

        count += 1

        send(IP(dst=dst) / UDP(dport=dport, sport=sport) / Raw(body_and_hash), iface=config.sender_interface)
