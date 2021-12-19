import argparse
import os
import time
from ping_manager import PingManager


def on_stop_ping(ping_manager: PingManager):
    answers_time = ping_manager.get_answers_sec()
    sent_packages_count = ping_manager.get_sent_packages_count()
    received_packages_count = len(answers_time)
    losses_percentage = (1
                         - received_packages_count / sent_packages_count) * 100

    print("==========")
    print(f"Sent packages count: {sent_packages_count}")
    print(f"Received packages count: {received_packages_count}")
    print(f"Lost packages: {losses_percentage}%")

    if answers_time:
        print(f"Min answ time: {min(answers_time) * 1000} ms")
        print(f"Max answ time: {max(answers_time) * 1000} ms")
        print(f"Avg answ time: "
              f"{sum(answers_time) / len(answers_time) * 1000} ms")

    os._exit(0)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("ip")
    parser.add_argument("-p",
                        type=int,
                        dest="port",
                        default=80,
                        help="default=80")
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


if __name__ == "__main__":
    arguments = create_parser().parse_args()

    ping_manager = PingManager(arguments.ip,
                               arguments.port,
                               lambda: on_stop_ping(ping_manager))
    ping_manager.start(arguments.interval, arguments.packages_number)

    try:
        if arguments.timeout is None:
            while True:
                input()
        else:
            time.sleep(arguments.timeout)
            ping_manager.stop()
    except KeyboardInterrupt:
        ping_manager.stop()
