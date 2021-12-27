def get_ipv4_header_size(package: bytes) -> int:
    return (package[0] & 0b00001111) * 4


def get_ipv4_protocol_type(package: bytes) -> int:
    return package[9]


def get_ipv4_source(package: bytes) -> str:
    return ".".join(map(str, package[12:16]))


def is_tcp_syn_ack(ip_package: bytes) -> bool:
    offset = get_ipv4_header_size(ip_package)

    return ip_package[offset+13] & 0b0001_0010 == 0b0001_0010


def get_tcp_source_port(ip_package: bytes) -> int:
    offset = get_ipv4_header_size(ip_package)

    return int.from_bytes(ip_package[offset:offset+2], "big")


def get_tcp_ack(ip_package: bytes) -> int:
    offset = get_ipv4_header_size(ip_package)

    return int.from_bytes(ip_package[offset+8:offset+12], "big")
