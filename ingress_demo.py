from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct

flags = 0

in_if = 'lo'

bpf_program = BPF(src_file="ebpf/ingress.c", cflags=["-w"])

in_fn = bpf_program.load_func("xdp_handle_ingress", BPF.XDP)

bpf_program.attach_xdp(in_if, in_fn, flags)

bpf_program["deduplicate_ports"].clear()
value = ct.c_int(1)
for port in [5555, 8000]:
    key = ct.c_int(port)
    bpf_program["deduplicate_ports"][key] = value


try:
    while 1:
        ...
finally:
    bpf_program.remove_xdp(in_if, flags)
