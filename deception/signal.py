# deception/signal.py
"""
Translates honeypot contact events into scorer/decision engine calls.
Acts as the bridge between the deception layer and the detection pipeline.
"""

import logging
from typing import Callable, Optional

logger = logging.getLogger("netsentinel.honeypot.signal")


class HoneypotSignal:
    """
    When a honeypot contact is detected, calls the registered scorer
    callback so the detection pipeline can act on it immediately.
    """

    def __init__(self, on_contact: Optional[Callable[[str, int], None]] = None):
        self._on_contact = on_contact

    def register(self, callback: Callable[[str, int], None]) -> None:
        self._on_contact = callback

    def emit(self, src_ip: str, port: int) -> None:
        logger.warning("HoneypotSignal: contact from %s on port %d", src_ip, port)
        if self._on_contact:
            self._on_contact(src_ip, port)
