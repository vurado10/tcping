import random
import socket
import time
from threading import Thread
from typing import Optional
from scapy.layers.inet import IP, TCP


class PingManager:
    def __init__(self, ip: str, port: int):
        self.__ip: str = ip
        self.__port: int = port
        self.__sending_thread: Optional[Thread] = None
        self.__receiving_thread: Optional[Thread] = None
        self.__sending_time_by_seq: dict[int, float] = {}
        self.__answer_time_by_seq: dict[int, float] = {}
        self.__is_stoped = True

    def start(self,
              interval: float,
              packages_number: Optional[int] = None):
        if not self.__is_stoped:
            raise RuntimeError("Manager is running")

        self.__sending_time_by_seq = {}
        self.__answer_time_by_seq = {}

        self.__sending_thread = Thread(
            target=self.__start_sending_syn_pkgs,
            args=(socket.gethostbyname(self.__ip),
                  self.__port,
                  interval,
                  packages_number)
        )

        self.__receiving_thread = Thread(
            target=self.__start_receiving_ack_pkgs())


        self.__is_stoped = False
        self.__sending_thread.start()
        self.__receiving_thread.start()

    def stop(self):
        self.__is_stoped = True
        self.__sending_thread.join()
        self.__receiving_thread.join()

    def get_answers_time(self) -> list[float]:
        return list(self.__answer_time_by_seq.values())

    def __start_sending_syn_pkgs(
            self,
            ip: str,
            port: int,
            interval: Optional[float] = None,
            packages_number: Optional[int] = None):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        # REDUCE KERNEL CONTROL!
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        #####################################################

        i = 0
        while not self.__is_stoped:
            if packages_number is not None:
                if i == packages_number:
                    break

            package = IP(dst=ip) / TCP(sport=random.randint(0, 65536),
                                       dport=port,
                                       seq=i,
                                       flags="S")

            #               just an internet ip (true ip in header of package)
            s.sendto(bytes(package), ("1.1.1.1", 0))
            self.__sending_time_by_seq[i] = time.time()

            if interval is not None:
                time.sleep(interval)

            i += 1

    def __start_receiving_ack_pkgs(self):
        # catch all tcp package that was received by OS
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        while not self.__is_stoped:
            data, address = s.recvfrom(2500)
            parsed_data = IP(data)

            if "TCP" in parsed_data and parsed_data["TCP"].flags == 18:
                seq = parsed_data["TCP"].ack - 1
                answer_time = time.time() - self.__sending_time_by_seq[seq]
                self.__answer_time_by_seq[seq] = answer_time

                print(f"{parsed_data['IP'].src}:{parsed_data['TCP'].sport} "
                      f"-> syn/ack time={answer_time * 1000} ms")
