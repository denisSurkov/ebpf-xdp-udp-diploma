import os.path
from signal import signal, SIGUSR1

from bcc import BPF
import ctypes as ct

from conf import Configuration, read_configuration
from constants import ROOT_PATH
from daemon import daemonize

_should_run = True


def _usr1_handler(*_, **__):
    global _should_run
    _should_run = False


def run_ingress_handler(config: Configuration):
    global _should_run
    daemonize()
    signal(SIGUSR1, _usr1_handler)

    while True:
        _run_ingress_handler(config)

        config = read_configuration(config.config_path)
        _should_run = True


def _run_ingress_handler(config: Configuration):
    in_if = config.receiver_interface

    src_path = os.path.join(ROOT_PATH, "ebpf", "ingress.c")
    ebpf_program = BPF(src_file=src_path, cflags=["-w"])

    in_fn = ebpf_program.load_func("xdp_handle_ingress", BPF.XDP)

    ebpf_program.attach_xdp(in_if, in_fn, 0)

    _add_ports(ebpf_program, config)

    try:
        while True:
            ...
    finally:
        ebpf_program.remove_xdp(in_if, 0)


def _add_ports(ebpf_program, config):

    ebpf_program["deduplicate_ports"].clear()
    value = ct.c_int(1)
    for port in config.receiver_ports_to_deduplicate:
        key = ct.c_int(port)
        ebpf_program["deduplicate_ports"][key] = value
