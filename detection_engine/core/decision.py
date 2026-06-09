# detection_engine/core/decision.py
"""
Decision engine: evaluates an IP's risk score and triggers appropriate actions.
Actions: LOG_ONLY | ALERT | BLOCK | HONEYPOT_SPAWN
"""

import logging
from typing import Callable, Optional

from ..state.ip_state import IPState, IPStateStore
from .. import config

logger = logging.getLogger("netsentinel.decision")

# Action constants
ACTION_LOG       = "log"
ACTION_ALERT     = "alert"
ACTION_BLOCK     = "block"
ACTION_HONEYPOT  = "honeypot"


class DecisionEngine:
    def __init__(self,
                 store: IPStateStore,
                 on_alert: Optional[Callable[[IPState], None]] = None,
                 on_block: Optional[Callable[[IPState], None]] = None,
                 on_honeypot: Optional[Callable[[str], None]] = None):
        self._store      = store
        self._on_alert   = on_alert
        self._on_block   = on_block
        self._on_honeypot = on_honeypot

    def evaluate(self, ip: str, port_scan_detected: bool = False) -> str:
        state = self._store.get(ip)
        if state is None:
            return ACTION_LOG
        if state.is_blocked:
            return ACTION_BLOCK

        score = state.risk_score

        if score >= config.SCORE_BLOCK:
            self._trigger_block(state)
            return ACTION_BLOCK

        if score >= config.SCORE_ALERT:
            if self._on_alert:
                self._on_alert(state)
            logger.info("[decision] ALERT: %s score=%d", ip, score)
            if port_scan_detected and self._on_honeypot:
                self._on_honeypot(ip)
                return ACTION_HONEYPOT
            return ACTION_ALERT

        if port_scan_detected and self._on_honeypot:
            self._on_honeypot(ip)
            return ACTION_HONEYPOT

        return ACTION_LOG

    def _trigger_block(self, state: IPState) -> None:
        self._store.mark_blocked(state.ip)
        logger.warning("[decision] BLOCK: %s score=%d", state.ip, state.risk_score)
        if self._on_block:
            self._on_block(state)
