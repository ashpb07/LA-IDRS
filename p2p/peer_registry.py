# p2p/peer_registry.py
"""
Manages known peer node addresses for the gossip network.
Peers can be seeded via config or discovered dynamically.
"""

import json
import logging
import os
import time
from typing import List

logger = logging.getLogger("netsentinel.p2p.registry")

REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "..",
                              "data", "db", "peers.json")


class PeerRegistry:
    def __init__(self, seed_peers: List[str] | None = None,
                 path: str = REGISTRY_PATH):
        self._path  = path
        self._peers: dict = {}   # host -> {"last_seen": float, "active": bool}
        self._load()
        for p in (seed_peers or []):
            self.register(p)

    def register(self, host: str) -> None:
        if host not in self._peers:
            self._peers[host] = {"last_seen": time.time(), "active": True}
            self._save()
            logger.info("Registered peer: %s", host)

    def seen(self, host: str) -> None:
        if host in self._peers:
            self._peers[host]["last_seen"] = time.time()
            self._peers[host]["active"] = True

    def active_peers(self) -> List[str]:
        return [h for h, m in self._peers.items() if m.get("active")]

    def all_peers(self) -> dict:
        return dict(self._peers)

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(self._peers, f, indent=2)

    def _load(self) -> None:
        if os.path.exists(self._path):
            try:
                with open(self._path) as f:
                    self._peers = json.load(f)
            except Exception:
                self._peers = {}