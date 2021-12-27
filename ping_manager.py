import asyncio
import random
import socket
import time
from smtplib import SMTP
from threading import Thread
from typing import Optional

from package_builders import create_ip_header, create_tcp_syn_segment
from package_parsers import get_ipv4_protocol_type, is_tcp_syn_ack, \
    get_ipv4_source, get_tcp_source_port, get_tcp_ack
from statistics import Statistics


class PingManager:
    def __init__(self,
                 destinations: list[list[str, int]],
                 smtp: Optional[SMTP] = None,
                 email_interval_sec: float = 15.,
                 sender_email: Optional[str] = None,
                 recv_email: Optional[str] = None):
        self.__sender_email = sender_email
        self.__recv_email = recv_email
        self.__email_interval_sec = email_interval_sec
        self.__email_thread = None
        self.__destinations = list(destinations)
        self.__sending_thread: Optional[Thread] = None
        self.__receiving_thread: Optional[Thread] = None
        self.__sending_time_by_seq: dict[int, float] = {}
        self.__answer_sec_by_seq: dict[int, float] = {}
        self.__is_sending_stoped = True
        self.__smtp = smtp
        self.__statistics: dict[tuple[str, int], Statistics] = {}
        self.__is_receiving_running = False

    @property
    def is_stoped(self) -> bool:
        return self.__is_sending_stoped and not self.__is_receiving_running

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

        if not (self.__smtp is None
                or self.__recv_email is None
                or self.__sender_email is None):
            self.__email_thread = Thread(
                target=self.__start_sending_email_reports,
                args=(self.__email_interval_sec,)
            )

        self.__is_sending_stoped = False
        self.__is_receiving_running = True
        self.__sending_thread.start()
        self.__receiving_thread.start()
        if self.__email_thread is not None:
            self.__email_thread.start()

    def stop(self):
        if self.__is_sending_stoped:
            raise RuntimeError("Manager is already stopped")

        self.__is_sending_stoped = True
        self.__is_receiving_running = False

        print(self.__make_full_statistics_report())
        self.__send_email_report("PING IS OVER\n")

    def stop_threadings(self):
        self.__sending_thread.join(timeout=2.)
        self.__receiving_thread.join(timeout=2.)
        if self.__email_thread is not None:
            self.__email_thread.join(timeout=2.)

    def get_sent_packages_count(self) -> int:
        return len(self.__sending_time_by_seq.keys())

    def get_answers_sec(self) -> list[float]:
        return list(self.__answer_sec_by_seq.values())

    def __start_sending_email_reports(self, iterval_sec: float):
        if self.__smtp is None:
            return

        while self.__is_receiving_running:
            time.sleep(iterval_sec)
            if not self.__is_receiving_running:
                break
            print(f"EMAIL: sending report on {self.__recv_email}")
            self.__send_email_report()

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

            sport = random.randint(0, 65536)

            ip_header = create_ip_header(ip)
            tcp_segment = create_tcp_syn_segment(
                ip_header, sport, port, i)

            package = ip_header + tcp_segment

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

            if (get_ipv4_protocol_type(data) == 6
                    and is_tcp_syn_ack(data)):
                ip = get_ipv4_source(data)
                port = get_tcp_source_port(data)
                stat = self.__statistics.get((ip, port), None)
                if stat is None:
                    continue

                seq = get_tcp_ack(data) - 1
                stat.register_recv_time(seq, recv_time)
                answer_time = stat.get_answer_time_by_pk_id(seq)

                print(f"{ip}:{port} "
                      f"-> syn/ack time={answer_time * 1000} ms")

    def __make_full_statistics_report(self) -> str:
        parts = []
        for ip, port in self.__statistics:
            parts.append(
                f"==========\n{ip}:{port}\n"
                + str(self.__statistics[(ip, port)]))

        return "\n".join(parts)

    def __send_email_report(self, pre_msg=""):
        if not (self.__smtp is None
                or self.__recv_email is None
                or self.__sender_email is None):
            self.__smtp.sendmail(self.__sender_email,
                                 self.__recv_email,
                                 pre_msg
                                 + self.__make_full_statistics_report())
