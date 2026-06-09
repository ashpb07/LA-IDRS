# detection_engine/state/ip_state.py
"""
Per-IP mutable state: risk score, event history, block status.
Thread-safe. Used by scorer and decision engine.
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class IPEvent:
    timestamp: float
    event_type: str   # e.g. "syn_scan", "honeypot_contact", "brute_force"
    detail: str = ""
    score_delta: int = 0


@dataclass
class IPState:
    ip: str
    risk_score: int = 0
    is_blocked: bool = False
    blocked_at: float | None = None
    events: List[IPEvent] = field(default_factory=list)
    honeypot_contacts: int = 0
    syn_count: int = 0
    port_scan_ports: set = field(default_factory=set)
    last_seen: float = field(default_factory=time.time)

    def add_event(self, event: IPEvent) -> None:
        self.events.append(event)
        self.risk_score = min(self.risk_score + event.score_delta, 100)
        self.last_seen = time.time()

    def reset_score(self) -> None:
        self.risk_score = 0
        self.events.clear()
        self.syn_count = 0
        self.port_scan_ports.clear()
        self.honeypot_contacts = 0


class IPStateStore:
    def __init__(self):
        self._states: Dict[str, IPState] = {}
        self._lock = threading.Lock()

    def get_or_create(self, ip: str) -> IPState:
        with self._lock:
            if ip not in self._states:
                self._states[ip] = IPState(ip=ip)
            return self._states[ip]

    def get(self, ip: str) -> IPState | None:
        with self._lock:
            return self._states.get(ip)

    def all(self) -> List[IPState]:
        with self._lock:
            return list(self._states.values())

    def blocked_ips(self) -> List[str]:
        with self._lock:
            return [ip for ip, s in self._states.items() if s.is_blocked]

    def mark_blocked(self, ip: str) -> None:
        with self._lock:
            s = self._states.get(ip)
            if s:
                s.is_blocked = True
                s.blocked_at = time.time()
