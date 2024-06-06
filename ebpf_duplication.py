from argparse import ArgumentParser


def get_parser() -> 'ArgumentParser':
    parser = ArgumentParser(description='eBPF udp packets duplication and deduplication')

    parser.add_argument('config', type=str, help='Full path to config file')
    parser.add_argument('mode', choices=['ingress', 'egress', 'config-reload'], type=str, help='Mode to run')

    return parser


if __name__ == '__main__':
    parser = get_parser()
    args = parser.parse_args()
    print(args)
