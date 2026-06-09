# detection_engine/core/signature.py
"""
Signature-based detection engine.
Loads JSON rule files and evaluates them against per-IP cached packet data.
"""

import json
import logging
import os
from typing import List, Tuple

from ..state.cache import RecentPacketCache

logger = logging.getLogger("netsentinel.signature")

FLAG_SYN = 0x02
AUTH_PORTS = {21, 22, 23, 3389, 5900}

RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


def _load_rules() -> List[dict]:
    rules = []
    for fname in os.listdir(RULES_DIR):
        if fname.endswith(".json"):
            path = os.path.join(RULES_DIR, fname)
            try:
                with open(path) as f:
                    rules.append(json.load(f))
            except Exception as e:
                logger.warning("Failed to load rule %s: %s", fname, e)
    return rules


_RULES = _load_rules()


class SignatureEngine:
    def __init__(self, cache: RecentPacketCache):
        self._cache = cache

    def evaluate(self, ip: str, dst_port: int,
                 tcp_flags: int) -> List[Tuple[str, int, str]]:
        """
        Returns a list of (rule_name, score_delta, description) for
        every rule that fires for this IP.
        """
        hits = []
        recent = self._cache.recent(ip)
        if not recent:
            return hits

        unique_ports   = {r.dst_port for r in recent if r.dst_port}
        syn_count      = sum(1 for r in recent if r.tcp_flags & FLAG_SYN)
        auth_attempts  = sum(1 for r in recent if r.dst_port in AUTH_PORTS)

        for rule in _RULES:
            cond = rule.get("conditions", {})
            fired = False

            if rule["rule_id"] == "PORT_SCAN_001":
                threshold = cond.get("unique_dst_ports_in_window", {}).get("value", 15)
                if len(unique_ports) >= threshold:
                    fired = True

            elif rule["rule_id"] == "SYN_FLOOD_001":
                threshold = cond.get("syn_count_in_window", {}).get("value", 50)
                if syn_count >= threshold:
                    fired = True

            elif rule["rule_id"] == "BRUTE_FORCE_001":
                threshold = cond.get("connection_attempts_in_window", {}).get("value", 10)
                if auth_attempts >= threshold and dst_port in AUTH_PORTS:
                    fired = True

            if fired:
                hits.append((rule["name"], rule["score_delta"], rule["description"]))
                logger.debug("Rule FIRED: %s for IP %s", rule["name"], ip)

        return hits
