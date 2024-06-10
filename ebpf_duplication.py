from argparse import ArgumentParser

from conf import read_configuration, run_config_reload
from egress_handler import run_egress_handler
from ingress_handler import run_ingress_handler


def get_parser() -> 'ArgumentParser':
    parser = ArgumentParser(description='eBPF udp packets duplication and deduplication')

    parser.add_argument('config', type=str, help='Full path to config file')
    parser.add_argument('mode', choices=['ingress', 'egress', 'config-reload'], type=str, help='Mode to run')

    return parser


if __name__ == '__main__':
    parser = get_parser()
    args = parser.parse_args()

    config = read_configuration(args.config)

    if args.mode == 'ingress':
        run_ingress_handler(config)
    elif args.mode == 'egress':
        run_egress_handler(config)
    elif args.mode == 'config-reload':
        run_config_reload()
