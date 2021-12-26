import asyncio
import random
import socket
import time
from threading import Thread
from typing import Optional

from monitoring_manager import MonitoringManager
from scapy.layers.inet import IP, TCP
from statistics import Statistics


class PingManager:
    def __init__(self,
                 monitoring: MonitoringManager,
                 destinations: list[list[str, int]]):
        self.__destinations = list(destinations)
        self.__sending_thread: Optional[Thread] = None
        self.__receiving_thread: Optional[Thread] = None
        self.__sending_time_by_seq: dict[int, float] = {}
        self.__answer_sec_by_seq: dict[int, float] = {}
        self.__is_sending_stoped = True
        self.__monitoring = monitoring
        self.__statistics: dict[tuple[str, int], Statistics] = {}
        self.__is_receiving_running = False

    @property
    def is_sending_stoped(self) -> bool:
        return self.__is_sending_stoped

    def start(self,
              interval: float,
              packages_number: Optional[int] = None):
        if not self.__is_sending_stoped:
            raise RuntimeError("Manager is running")

        self.__sending_thread = Thread(
            target=self.__start_sending_syn_pkgs,
            args=(interval,
                  packages_number)
        )

        self.__receiving_thread = Thread(
            target=self.__start_receiving_ack_pkgs)


        self.__is_sending_stoped = False
        self.__is_receiving_running = True
        self.__sending_thread.start()
        self.__receiving_thread.start()

    def stop(self):
        if self.__is_sending_stoped:
            raise RuntimeError("Manager is already stopped")

        self.__is_sending_stoped = True
        self.__is_receiving_running = False

        print(self.__make_full_statistics_report())

    def stop_threadings(self):
        self.__sending_thread.join(timeout=10.)
        self.__receiving_thread.join(timeout=10.)

    def get_sent_packages_count(self) -> int:
        return len(self.__sending_time_by_seq.keys())

    def get_answers_sec(self) -> list[float]:
        return list(self.__answer_sec_by_seq.values())

    def __start_sending_syn_pkgs(
            self,
            interval: Optional[float] = None,
            packages_number: Optional[int] = None):
        try:
            asyncio.run(self.__start_sending_syn_pkgs_for_all_async(
                interval,
                packages_number))
            self.stop()
        except RuntimeError:
            pass

    async def __start_sending_syn_pkgs_for_all_async(
            self,
            interval: Optional[float] = None,
            packages_number: Optional[int] = None):
        tasks = []
        for ip, port in self.__destinations:
            tasks.append(asyncio.create_task(
                self.__start_sending_syn_pkgs_async(
                    socket.gethostbyname(ip), port,
                    interval, packages_number)))

        await asyncio.gather(*tasks)


    async def __start_sending_syn_pkgs_async(
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
        while not self.__is_sending_stoped:
            if packages_number is not None:
                if i == packages_number:
                    break

            package = IP(dst=ip) / TCP(sport=random.randint(0, 65536),
                                       dport=port,
                                       seq=i,
                                       flags="S")

            #               just an internet ip (true ip in header of package)
            s.sendto(bytes(package), ("1.1.1.1", 0))

            stat = self.__statistics.get((ip, port), None)
            if stat is None:
                stat = Statistics()
                self.__statistics[(ip, port)] = stat

            stat.register_sending_time(i, time.time())

            if interval is not None:
                await asyncio.sleep(interval)
            else:
                await asyncio.sleep(0.01)

            i += 1

    def __start_receiving_ack_pkgs(self):
        # catch all tcp packages that was received by OS
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(1.)

        while self.__is_receiving_running:
            try:
                data, address = s.recvfrom(2500)
            except socket.timeout:
                continue
            recv_time = time.time()
            parsed_data = IP(data)

            if "TCP" in parsed_data and parsed_data["TCP"].flags == 18:
                ip = parsed_data['IP'].src
                port = parsed_data['TCP'].sport
                stat = self.__statistics.get((ip, port), None)
                if stat is None:
                    continue

                seq = parsed_data["TCP"].ack - 1
                stat.register_recv_time(seq, recv_time)
                answer_time = stat.get_answer_time_by_pk_id(seq)

                print(f"{parsed_data['IP'].src}:{parsed_data['TCP'].sport} "
                      f"-> syn/ack time={answer_time * 1000} ms")

    def __make_full_statistics_report(self) -> str:
        parts = []
        for ip, port in self.__statistics:
            parts.append(
                f"==========\n{ip}:{port}\n"
                + str(self.__statistics[(ip, port)]))

        return "\n".join(parts)

    def __make_statistics_report(self, ip: str, port: int) -> str:
        answers_time = self.get_answers_sec()
        sent_packages_count = self.get_sent_packages_count()
        received_packages_count = len(answers_time)
        losses_percentage = (1 - received_packages_count
                             / sent_packages_count) * 100

        parts = [
            "==========",
            f"Sent packages count: {sent_packages_count}",
            f"Received packages count: {received_packages_count}",
            f"Lost packages: {losses_percentage}%"
        ]

        if answers_time:
            parts.append(f"Min answ time: {min(answers_time) * 1000} ms")
            parts.append(f"Max answ time: {max(answers_time) * 1000} ms")
            parts.append(f"Avg answ time: "
                         f"{sum(answers_time) / len(answers_time) * 1000} ms")

        return "\n".join(parts)
