# detection_engine/utils/parser.py
"""
Utility helpers for packet field interpretation.
"""

PROTOCOL_NAMES = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    58: "ICMPv6",
}

FLAG_NAMES = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
}


def protocol_name(proto: int) -> str:
    return PROTOCOL_NAMES.get(proto, f"PROTO_{proto}")


def flags_str(flags: int) -> str:
    return "|".join(name for bit, name in FLAG_NAMES.items() if flags & bit) or "NONE"


def is_private_ip(ip: str) -> bool:
    """Returns True for RFC-1918 addresses."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
    )
