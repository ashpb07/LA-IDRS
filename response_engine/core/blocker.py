# response_engine/core/blocker.py
"""
Calls the iptables shell script to block/unblock IPs.
Maintains a JSON state file of currently banned IPs.
"""

import json
import logging
import os
import subprocess
import time

logger = logging.getLogger("netsentinel.response")

BANNED_IPS_PATH = os.path.join(os.path.dirname(__file__), "..", "state", "banned_ips.json")
IPTABLES_SCRIPT = os.path.join(os.path.dirname(__file__), "..", "firewall", "iptables.sh")


class IPBlocker:
    def __init__(self):
        self._banned: dict = {}      # ip -> {"blocked_at": float}
        self._load()

    # ------------------------------------------------------------------ #
    def block(self, ip: str) -> bool:
        if ip in self._banned:
            logger.debug("IP %s already blocked", ip)
            return True
        try:
            result = subprocess.run(
                ["bash", IPTABLES_SCRIPT, "block", ip],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                logger.error("iptables block failed for %s: %s", ip, result.stderr)
                return False
        except Exception as e:
            logger.error("iptables block exception for %s: %s", ip, e)
            return False

        self._banned[ip] = {"blocked_at": time.time()}
        self._save()
        logger.warning("BLOCKED: %s", ip)
        return True

    def unblock(self, ip: str) -> bool:
        if ip not in self._banned:
            return False
        try:
            result = subprocess.run(
                ["bash", IPTABLES_SCRIPT, "unblock", ip],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                logger.error("iptables unblock failed for %s: %s", ip, result.stderr)
                return False
        except Exception as e:
            logger.error("iptables unblock exception for %s: %s", ip, e)
            return False

        del self._banned[ip]
        self._save()
        logger.info("UNBLOCKED: %s", ip)
        return True

    def is_blocked(self, ip: str) -> bool:
        return ip in self._banned

    def all_banned(self) -> list:
        return list(self._banned.keys())

    # ------------------------------------------------------------------ #
    def _save(self) -> None:
        os.makedirs(os.path.dirname(BANNED_IPS_PATH), exist_ok=True)
        with open(BANNED_IPS_PATH, "w") as f:
            json.dump(self._banned, f, indent=2)

    def _load(self) -> None:
        if os.path.exists(BANNED_IPS_PATH):
            try:
                with open(BANNED_IPS_PATH) as f:
                    self._banned = json.load(f)
                logger.info("Loaded %d existing bans", len(self._banned))
            except Exception:
                self._banned = {}