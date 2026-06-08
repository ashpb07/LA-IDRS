# detection_engine/core/scorer.py
"""
Risk scorer: aggregates signature hits, behavior hits, and honeypot signals
into a single cumulative score for an IP.
"""

import logging
import time
from typing import List, Tuple

from ..state.ip_state import IPEvent, IPState, IPStateStore
from .. import config

logger = logging.getLogger("netsentinel.scorer")


class RiskScorer:
    def __init__(self, store: IPStateStore):
        self._store = store

    def apply_hits(self, ip: str,
                   hits: List[Tuple[str, int, str]]) -> IPState:
        """
        Apply a list of (name, score_delta, detail) findings to an IP.
        Returns the updated IPState.
        """
        state = self._store.get_or_create(ip)
        if state.is_blocked:
            return state

        for name, delta, detail in hits:
            event = IPEvent(
                timestamp=time.time(),
                event_type=name,
                detail=detail,
                score_delta=delta,
            )
            state.add_event(event)
            logger.info("[score] %s +%d → %d | %s", ip, delta, state.risk_score, name)

        return state

    def apply_honeypot_contact(self, ip: str, port: int) -> IPState:
        state = self._store.get_or_create(ip)
        state.honeypot_contacts += 1
        event = IPEvent(
            timestamp=time.time(),
            event_type="honeypot_contact",
            detail=f"Connected to honeypot port {port}",
            score_delta=config.HONEYPOT_SCORE,
        )
        state.add_event(event)
        logger.warning("[score] HONEYPOT CONTACT %s port %d → score %d",
                       ip, port, state.risk_score)
        return state

    def current_score(self, ip: str) -> int:
        state = self._store.get(ip)
        return state.risk_score if state else 0