class Statistics:
    def __init__(self):
        self.__sending_time_by_pk_id: dict[int, float] = {}
        self.__answer_sec_by_pk_id: dict[int, float] = {}

    def __str__(self) -> str:
        answers_time = self.get_answers_sec()
        sent_packages_count = self.get_sent_packages_count()
        received_packages_count = len(answers_time)
        losses_percentage = (1 - received_packages_count
                             / sent_packages_count) * 100

        parts = [
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

    def get_sent_packages_count(self) -> int:
        return len(self.__sending_time_by_pk_id.keys())

    def get_answers_sec(self) -> list[float]:
        return list(self.__answer_sec_by_pk_id.values())

    def get_answer_time_by_pk_id(self, pk_id: int):
        return self.__answer_sec_by_pk_id[pk_id]

    def register_sending_time(self, pk_id: int, time_stamp: float):
        self.__sending_time_by_pk_id[pk_id] = time_stamp

    def register_recv_time(self, pk_id: int, time_stamp: float):
        self.__answer_sec_by_pk_id[pk_id] = \
            time_stamp - self.__sending_time_by_pk_id[pk_id]
