import environment
from scapy.arch import get_if_addr
from scapy.config import conf

OVERFLOW_MASK = 0b1_0000_0000_0000_0000


def calculate_checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        raise ValueError(f"odd length: {len(data)}")
    current_sum = 0
    for i in range(len(data) // 2):
        offset = 2 * i
        word = int.from_bytes(data[offset:offset+2], "big")

        next_sum = current_sum + word
        while next_sum & OVERFLOW_MASK != 0:
            next_sum &= OVERFLOW_MASK - 1
            next_sum += 1

        current_sum = next_sum

    return OVERFLOW_MASK - 1 - current_sum


def calculate_tcp_checksum(ip_header: bytes, tcp_segment: bytes) -> int:
    pseudo_header = (ip_header[12:16]
                     + ip_header[16:20]
                     + b'\x00'
                     + b'\x06'
                     + len(tcp_segment).to_bytes(2, "big"))

    return calculate_checksum(pseudo_header + tcp_segment)


def create_tcp_syn_segment(ip_header: bytes,
                           sport: int,
                           dport: int,
                           seq: int) -> bytes:
    fields = {
        "sport_bytes": int.to_bytes(sport, 2, "big"),
        "dport_bytes": int.to_bytes(dport, 2, "big"),
        "seq_bytes": int.to_bytes(seq, 4, "big"),
        "ack_bytes": b'\x00' * 4,
        "header_length_and_ns_flag": b'P',
        "flags": b'\x02',
        "windows_size": b' \x00',
        "check_sum": b'\x00\x00',
        "urgent_point": b'\x00\x00'
    }

    fields["check_sum"] = int.to_bytes(calculate_tcp_checksum(
        ip_header,
        b''.join(fields.values())),
        2,
        "big"
    )

    return b''.join(fields.values())


def create_ip_header(destination_ip: str) -> bytes:
    fields = {
        "version_and_header_size": b'E',
        "service_type": b'\x00',
        "full_length": b'\x00\x28',
        "package_id": b'\x00\x01',
        "flags_and_offset": b'\x00\x00',
        "ttl": b'@',
        "protocol_type": b'\x06',
        "check_sum": b'\x00\x00',
        "src_ip_bytes": bytes(map(int,
                                  get_if_addr(environment.NET_INTERFACE_NAME)
                                  .split("."))),
        "dst_ip_bytes": bytes(map(int, destination_ip.split(".")))
    }

    fields["check_sum"] = \
        calculate_checksum(b''.join(fields.values())).to_bytes(2, "big")

    return b''.join(fields.values())
