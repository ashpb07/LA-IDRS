# deception/honeypot.py
"""
Dynamic micro-honeypot spawner.
Opens randomised fake TCP listener ports when a port scan is detected.
Any inbound connection triggers an instant block signal.
"""

import logging
import random
import socket
import threading
import time
from typing import Callable, Dict, Set

from . import port_manager
from .signal import HoneypotSignal
from detection_engine import config

logger = logging.getLogger("netsentinel.honeypot")


class MicroHoneypot:
    def __init__(self, ip_target: str, port: int,
                 on_contact: Callable[[str, int], None]):
        self._target     = ip_target
        self._port       = port
        self._on_contact = on_contact
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._active = False

    def start(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self._port))
            self._sock.listen(5)
            self._sock.settimeout(0.5)
            self._active = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            logger.info("Honeypot listening on port %d (targeting %s)",
                        self._port, self._target)
            return True
        except OSError as e:
            logger.warning("Could not open honeypot port %d: %s", self._port, e)
            return False

    def stop(self) -> None:
        self._active = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _loop(self) -> None:
        while self._active:
            try:
                conn, addr = self._sock.accept()
                src_ip = addr[0]
                logger.warning("HONEYPOT CONTACT from %s on port %d",
                               src_ip, self._port)
                conn.close()
                self._on_contact(src_ip, self._port)
            except socket.timeout:
                continue
            except OSError:
                break


class HoneypotManager:
    def __init__(self, signal: HoneypotSignal):
        self._signal   = signal
        self._active: Dict[str, list] = {}   # ip -> [MicroHoneypot, ...]
        self._used_ports: Set[int] = set()
        self._lock = threading.Lock()

    def spawn_for_ip(self, ip: str) -> None:
        with self._lock:
            if ip in self._active:
                return  # already spawned

            ports = port_manager.pick_ports(
                config.HONEYPOT_PORT_COUNT,
                config.HONEYPOT_PORT_MIN,
                config.HONEYPOT_PORT_MAX,
                self._used_ports,
            )
            honeypots = []
            for p in ports:
                hp = MicroHoneypot(ip, p, self._on_contact)
                if hp.start():
                    self._used_ports.add(p)
                    honeypots.append(hp)
            self._active[ip] = honeypots
            logger.info("Spawned %d honeypot ports for %s", len(honeypots), ip)

    def teardown_for_ip(self, ip: str) -> None:
        with self._lock:
            for hp in self._active.pop(ip, []):
                self._used_ports.discard(hp._port)
                hp.stop()
            logger.info("Honeypot ports torn down for %s", ip)

    def _on_contact(self, src_ip: str, port: int) -> None:
        self._signal.emit(src_ip, port)
        # Tear down our traps for this IP — it's already getting blocked
        threading.Thread(target=self.teardown_for_ip,
                         args=(src_ip,), daemon=True).start()