import argparse
import itertools
import smtplib
import time
from typing import Iterable
from ping_manager import PingManager


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("targets",
                        action="append",
                        nargs="+",
                        help="target is str like <ip>:<port>\n"
                             "NO SPACES IN TARGET, "
                             "SPACES ONLY BETWEEN TARGETS\n"
                             "example: 1.1.1.1-50,59:80-90,5000")
    parser.add_argument("-se",
                        dest="sender_email",
                        help="sender email")
    parser.add_argument("-ps",
                        dest="sender_password",
                        help="sender email password")
    parser.add_argument("-re",
                        dest="recv_email",
                        help="receiver email")
    parser.add_argument("-ei",
                        dest="email_interval",
                        type=float,
                        help="email report interval in seconds",
                        default=8.)
    parser.add_argument("-n",
                        type=int,
                        dest="packages_number",
                        help="default=+inf")
    parser.add_argument("-t",
                        type=float,
                        dest="timeout",
                        default=None,
                        help="in seconds (float), default=+inf")
    parser.add_argument("-i",
                        type=float,
                        dest="interval",
                        help="in seconds (float)",
                        default=1.0)

    return parser


def get_permutations(iterables: list[Iterable[str]],
                     index: int = 0) -> Iterable[list]:
    iterable = iterables[index]
    if index == len(iterables) - 1:
        for element in iterable:
            yield [element]
        return

    pre_results = get_permutations(iterables, index + 1)
    for pre_result in pre_results:
        for element in iterable:
            yield [element] + pre_result


def strip_split(s: str, separator: str) -> list[str]:
    return list(map(lambda s: s.strip(), s.strip().split(separator)))


def parse_pure_str_range(str_range: str) -> list[int]:
    start, stop = map(int, strip_split(str_range, "-"))

    return list(range(start, stop + 1))


def parse_sequence(str_sequence: str) -> list[str]:
    """str('1-5, 9, 2-4') -> list([1, 2, 3, 4, 5, 9, 2, 3, 4])"""

    result = []
    for part in strip_split(str_sequence, ","):
        if "-" in part:
            result += map(str, parse_pure_str_range(part))
        else:
            result.append(part.strip())

    return result


def parse_ip_range(ip_range: str) -> list[str]:
    octet_ranges = []
    for octet_sequence in strip_split(ip_range, "."):
        octet_ranges.append(parse_sequence(octet_sequence))

    result = []
    for ip_list in get_permutations(octet_ranges):
        result.append(".".join(ip_list))

    return result


def parse_ports(ports_str: str) -> list[int]:
    return list(map(int, parse_sequence(ports_str)))


def parse_target(target: str) -> list[list[str, int]]:
    ip_range_str, ports_str = strip_split(target, ":")

    return list(get_permutations(
        [parse_ip_range(ip_range_str), parse_ports(ports_str)]
    ))


def parse_targets(target_list: list[str]) -> list[list[str, int]]:
    pre_result = []
    for target in target_list:
        # noinspection PyBroadException
        try:
            pre_result.append(parse_target(target))
        except Exception:
            pass

    return list(itertools.chain(*pre_result))


if __name__ == "__main__":
    arguments = create_parser().parse_args()

    ip_port_pairs = parse_targets(list(itertools.chain(*arguments.targets)))
    print(ip_port_pairs)

    server = None
    if not (arguments.sender_email is None
            or arguments.recv_email is None):
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.ehlo_or_helo_if_needed()
        if arguments.sender_password is not None:
            server.login(arguments.sender_email, arguments.sender_password)

    ping_manager = PingManager(ip_port_pairs,
                               server,
                               sender_email=arguments.sender_email,
                               recv_email=arguments.recv_email,
                               email_interval_sec=arguments.email_interval)
    ping_manager.start(arguments.interval, arguments.packages_number)

    try:
        if arguments.timeout is None:
            while not ping_manager.is_stoped:
                input()
        else:
            time.sleep(arguments.timeout)
            ping_manager.stop()
            ping_manager.stop_threadings()
    except KeyboardInterrupt:
        print()
        ping_manager.stop()
        ping_manager.stop_threadings()

    if server is not None:
        server.close()
