import argparse
import os
import random
import socket
import time
from threading import Thread
from time import sleep
from typing import Optional
from cancellation_token import CancellationToken
from scapy.layers.inet import IP, TCP

sending_thread_cancellation_token = None
sending_time_by_seq = {}
answers_time = []


def stop_program():
    print("Completed")
    os._exit(0)


def start_sending_syn_pkgs(ip: str,
                           port: int,
                           cancellation_token: CancellationToken,
                           interval: Optional[float] = None,
                           packages_number: Optional[int] = None):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # REDUCE KERNEL CONTROL!
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #####################################################

    i = 0
    while not cancellation_token.is_cancelled:
        if packages_number is not None:
            if i == packages_number:
                break
        package = IP(dst=ip) / TCP(sport=random.randint(0, 65536),
                                   dport=port,
                                   seq=i,
                                   flags="S")
        raw_package = bytes(package)

        #                  just an internet ip (true ip in header of package)
        s.sendto(raw_package, ("1.1.1.1", 0))
        sending_time_by_seq[i] = time.time()

        if interval is not None:
            sleep(interval)
        i += 1


def start_receiving_ack(sending_thread: Thread = None):
    # catch all tcp package that was received by PC
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while True if sending_thread is None else sending_thread.is_alive():
        data, address = s.recvfrom(2500)
        parsed_data = IP(data)

        if "TCP" in parsed_data and parsed_data["TCP"].flags == 18:
            answer_time = time.time() \
                          - sending_time_by_seq[parsed_data["TCP"].ack - 1]
            answers_time.append(answer_time)

            print(f"{parsed_data['IP'].src}:{parsed_data['TCP'].sport} "
                  f"-> syn/ack time={answer_time * 1000} ms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ip")
    parser.add_argument("-p", type=int, dest="port", default=80)
    parser.add_argument("-n", type=int, dest="packages_number")
    parser.add_argument("-t", type=int, dest="timeout",
                        default=5, help="in seconds (int)")
    parser.add_argument("-i", type=float,
                        dest="interval", help="in seconds (float)",
                        default=1.0)

    arguments = parser.parse_args()

    sending_thread_cancellation_token = CancellationToken()

    thread = Thread(target=start_sending_syn_pkgs,
                    args=(socket.gethostbyname(arguments.ip),
                          arguments.port,
                          sending_thread_cancellation_token,
                          arguments.interval,
                          arguments.package_number))

    thread.start()

    start_receiving_ack(thread)
