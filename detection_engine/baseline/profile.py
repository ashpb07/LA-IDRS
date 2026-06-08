# detection_engine/baseline/profile.py
"""
Per-network traffic profile — stores aggregated statistics learned
during the passive observation phase and used by the detector.
"""

import json
import os
import threading
import time
from dataclasses import dataclass, asdict, field
from typing import Dict


@dataclass
class IPProfile:
    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float  = field(default_factory=time.time)
    total_packets: int = 0
    total_bytes: int   = 0
    unique_dst_ports: set = field(default_factory=set)
    avg_pkt_rate: float = 0.0
    avg_byte_rate: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["unique_dst_ports"] = list(self.unique_dst_ports)
        return d


class NetworkProfile:
    """
    Maintains a per-IP dictionary of traffic profiles.
    Serialises/deserialises to JSON for persistence across restarts.
    """

    def __init__(self, profile_path: str | None = None):
        self._profiles: Dict[str, IPProfile] = {}
        self._lock = threading.Lock()
        self._path = profile_path

        if profile_path and os.path.exists(profile_path):
            self._load(profile_path)

    # ------------------------------------------------------------------ #
    def update(self, ip: str, dst_port: int, pkt_len: int) -> None:
        with self._lock:
            if ip not in self._profiles:
                self._profiles[ip] = IPProfile(ip=ip)
            p = self._profiles[ip]
            now = time.time()
            elapsed = max(now - p.first_seen, 1.0)
            p.total_packets += 1
            p.total_bytes   += pkt_len
            p.last_seen      = now
            p.avg_pkt_rate   = p.total_packets / elapsed
            p.avg_byte_rate  = p.total_bytes   / elapsed
            if dst_port:
                p.unique_dst_ports.add(dst_port)

    def get(self, ip: str) -> IPProfile | None:
        with self._lock:
            return self._profiles.get(ip)

    def unique_port_count(self, ip: str) -> int:
        with self._lock:
            p = self._profiles.get(ip)
            return len(p.unique_dst_ports) if p else 0

    def all_ips(self) -> list:
        with self._lock:
            return list(self._profiles.keys())

    # ------------------------------------------------------------------ #
    def save(self) -> None:
        if not self._path:
            return
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with self._lock:
            data = {ip: p.to_dict() for ip, p in self._profiles.items()}
        with open(self._path, "w") as f:
            json.dump(data, f, indent=2)

    def _load(self, path: str) -> None:
        with open(path) as f:
            data = json.load(f)
        for ip, d in data.items():
            p = IPProfile(ip=ip)
            p.first_seen       = d.get("first_seen", time.time())
            p.last_seen        = d.get("last_seen",  time.time())
            p.total_packets    = d.get("total_packets", 0)
            p.total_bytes      = d.get("total_bytes", 0)
            p.unique_dst_ports = set(d.get("unique_dst_ports", []))
            p.avg_pkt_rate     = d.get("avg_pkt_rate", 0.0)
            p.avg_byte_rate    = d.get("avg_byte_rate", 0.0)
            self._profiles[ip] = p