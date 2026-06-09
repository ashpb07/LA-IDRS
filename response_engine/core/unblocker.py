# response_engine/core/unblocker.py
"""
Scheduled unblocker — automatically lifts bans after a configurable TTL.
"""

import logging
import threading
import time

from .blocker import IPBlocker

logger = logging.getLogger("netsentinel.response.unblocker")

DEFAULT_BAN_TTL_SEC = 3600  # 1 hour


class ScheduledUnblocker:
    def __init__(self, blocker: IPBlocker, ttl_sec: int = DEFAULT_BAN_TTL_SEC):
        self._blocker  = blocker
        self._ttl      = ttl_sec
        self._running  = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Unblocker started (TTL=%ds)", self._ttl)

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            now = time.time()
            to_unblock = []
            for ip, meta in list(self._blocker._banned.items()):
                blocked_at = meta.get("blocked_at", now)
                if now - blocked_at >= self._ttl:
                    to_unblock.append(ip)
            for ip in to_unblock:
                logger.info("TTL expired for %s — unblocking", ip)
                self._blocker.unblock(ip)
            time.sleep(60)
