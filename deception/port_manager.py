# deception/port_manager.py
"""
Randomised port selection for honeypot listener ports.
Avoids known well-known ports and already-in-use ports.
"""

import random
from typing import Set

# Ports to never use as honeypots
RESERVED_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
    993, 995, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 27017,
}


def pick_ports(count: int, min_port: int, max_port: int,
               used: Set[int]) -> list:
    """
    Pick `count` random ports in [min_port, max_port] that are not
    in RESERVED_PORTS and not already in `used`.
    """
    candidates = list(range(min_port, max_port + 1))
    random.shuffle(candidates)
    selected = []
    for p in candidates:
        if p in RESERVED_PORTS or p in used:
            continue
        selected.append(p)
        if len(selected) >= count:
            break
    return selected
