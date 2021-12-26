import asyncio
import smtplib
from asyncio import AbstractEventLoop
from threading import Thread

from scapy.compat import Optional
from statistics import Statistics

SENT = "st"
RECEIVED = "rc"


class MonitoringManager:
    def __init__(self,
                 sender_email: Optional[str],
                 sender_password: Optional[str],
                 recv_email: str,
                 email_report_interval_sec: float):
        if email_report_interval_sec < 5.:
            raise ValueError("Too small email sending interval")

        self.__email_report_interval_sec = email_report_interval_sec
        self.__recv_email = recv_email
        self.__sender_password = sender_password
        self.__sender_email = sender_email
        self.__message_queue = asyncio.Queue()
        self.__is_running = False
        self.__thread = None
        self.__event_loop: Optional[AbstractEventLoop] = None

        # ip, port -> Statistics
        self.__statistics: dict[tuple[str, int], Statistics] = {}

    def register_syn_sending(self,
                             ip: str,
                             port: int,
                             seq: int,
                             time_stamp: float) -> None:
        self.__message_queue.put_nowait((SENT, ip, port, seq, time_stamp))

    def register_syn_ack_receiving(self,
                                   ip: str,
                                   port: int,
                                   ack: int,
                                   time_stamp: float) -> None:
        self.__message_queue.put_nowait((RECEIVED, ip, port, ack, time_stamp))

    def stop(self) -> None:
        self.__is_running = False
        self.__event_loop.stop()
        self.__thread.join()

        report = "END OF WORK\n" + self.__make_full_statistics_report()
        print(report)
        if self.__sender_email is not None:
            self.__send_email(report)

    def start(self) -> None:
        if self.__is_running:
            raise RuntimeError("Manager is running")

        self.__thread = Thread(target=self.__start_event_loop)
        self.__thread.start()

    def __start_event_loop(self):
        try:
            asyncio.run(self.__start_async())
        except RuntimeError:
            pass


    async def __start_async(self):
        self.__event_loop = asyncio.get_running_loop()

        collecting_task = asyncio.create_task(
            self.__start_collect_statistics())
        email_task = asyncio.create_task(
            self.__start_sending_emails_reports())

        await asyncio.gather(collecting_task, email_task)


    async def __start_collect_statistics(self):
        while self.__is_running:
            message = await self.__message_queue.get()

            msg_type, ip, port, number, time_stamp = message

            if msg_type == SENT:
                self.__update_sending_statistics(ip, port,
                                                 number, time_stamp)
            elif msg_type == RECEIVED:
                self.__update_receiving_statistics(ip, port,
                                                   number, time_stamp)

            raise RuntimeError(f"Message type is invalid: {msg_type}")

    async def __start_sending_emails_reports(self):
        if self.__sender_email is None:
            return
        while self.__is_running:
            await asyncio.sleep(self.__email_report_interval_sec)
            if not self.__is_running:
                break

            self.__send_email(self.__make_full_statistics_report())


    def __update_sending_statistics(self, ip, port, seq, time_stamp) -> None:
        stat = self.__statistics.get((ip, port), None)
        if stat is None:
            stat = Statistics()
            self.__statistics[(ip, port)] = stat

        stat.register_sending_time(seq, time_stamp)

    def __update_receiving_statistics(self, ip, port, ack, time_stamp) -> None:
        stat = self.__statistics.get((ip, port), None)
        if stat is None:
            raise KeyError

        stat.register_recv_time(ack - 1, time_stamp)

        print(MonitoringManager.__make_syn_ack_report(ip, port, time_stamp))

    def __get_answers_sec(self, ip: str, port: int) -> list[float]:
        return self.__statistics[(ip, port)].get_answers_sec()

    def __get_sent_packages_count(self, ip: str, port: int) -> int:
        return self.__statistics[(ip, port)].get_sent_packages_count()

    @staticmethod
    def __make_syn_ack_report(ip,
                              port,
                              time_stamp,
                              pre_msg="") -> str:
        return f"{pre_msg}{ip}:{port} " \
               f"-> syn/ack time={time_stamp * 1000} ms"

    def __make_full_statistics_report(self) -> str:
        parts = []
        for ip, port in self.__statistics:
            parts.append(self.__make_statistics_report(ip, port))

        return "\n".join(parts)

    def __make_statistics_report(self, ip: str, port: int) -> str:
        return f"==========\n{ip}:{port}\n" \
               + str(self.__statistics[(ip, port)])

    def __send_email(self, msg: str) -> None:
        try:
            server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
            server.ehlo_or_helo_if_needed()
            if self.__sender_password is not None:
                server.login(self.__sender_email, self.__sender_password)
            server.sendmail(self.__sender_email, self.__recv_email, msg)
            server.close()
        except Exception as e:
            print(f"Email sending error: {e}")
