# detection_engine/state/cache.py
"""
Rolling in-memory cache of recent packet events per IP.
Used to compute short-window statistics (e.g. SYN rate over last 5s).
"""

import collections
import threading
import time
from typing import Deque, Dict, List, NamedTuple


class PacketRecord(NamedTuple):
    timestamp: float
    dst_port: int
    tcp_flags: int
    payload_len: int


class RecentPacketCache:
    """
    Stores the last `maxlen` packets per IP within a sliding time window.
    """

    def __init__(self, window_sec: float = 10.0, maxlen: int = 500):
        self._window = window_sec
        self._maxlen = maxlen
        self._cache: Dict[str, Deque[PacketRecord]] = {}
        self._lock  = threading.Lock()

    def record(self, ip: str, dst_port: int, tcp_flags: int, payload_len: int) -> None:
        now = time.time()
        with self._lock:
            if ip not in self._cache:
                self._cache[ip] = collections.deque(maxlen=self._maxlen)
            q = self._cache[ip]
            q.append(PacketRecord(now, dst_port, tcp_flags, payload_len))

    def recent(self, ip: str) -> List[PacketRecord]:
        """Return all records within the time window."""
        cutoff = time.time() - self._window
        with self._lock:
            q = self._cache.get(ip)
            if not q:
                return []
            return [r for r in q if r.timestamp >= cutoff]

    def syn_count(self, ip: str) -> int:
        FLAG_SYN = 0x02
        return sum(1 for r in self.recent(ip) if r.tcp_flags & FLAG_SYN)

    def unique_ports(self, ip: str) -> set:
        return {r.dst_port for r in self.recent(ip) if r.dst_port}

    def packet_rate(self, ip: str) -> float:
        records = self.recent(ip)
        if len(records) < 2:
            return 0.0
        span = records[-1].timestamp - records[0].timestamp
        return len(records) / max(span, 0.001)

    def evict_old(self) -> None:
        """Remove IPs with no recent activity (called periodically)."""
        cutoff = time.time() - self._window * 6
        with self._lock:
            stale = [ip for ip, q in self._cache.items()
                     if not q or q[-1].timestamp < cutoff]
            for ip in stale:
                del self._cache[ip]