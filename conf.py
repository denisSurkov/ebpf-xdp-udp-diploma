import configparser
from typing import NamedTuple


class Configuration(NamedTuple):
    daemon_log_level: str

    receiver_interface: str
    receiver_ports_to_deduplicate: list[int]

    sender_interface: str
    sender_ports_to_duplicate: list[int]


CONFIGURATION: Configuration | None = None


def read_configuration(path_to_read: str) -> Configuration:
    global CONFIGURATION
    config = configparser.ConfigParser()
    config.read(path_to_read)

    daemon_log_level = config['DAEMON']['log_level']

    receiver_interface = config['RECEIVER SETTINGS']['interface']
    receiver_ports_to_duplicate = list(map(int, config['RECEIVER SETTINGS']['deduplicate_src_ports'].split(', ')))

    sender_interface = config['SENDER SETTINGS']['interface']
    sender_ports_to_duplicate = list(map(int, config['SENDER SETTINGS']['duplicate_src_ports'].split(', ')))

    CONFIGURATION = Configuration(
            daemon_log_level,
            receiver_interface,
            receiver_ports_to_duplicate,
            sender_interface,
            sender_ports_to_duplicate,
    )

    return CONFIGURATION
