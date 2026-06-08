# attack_graph/store.py
"""
Persists attack graphs as JSON files on disk.
"""

import json
import logging
import os

from .builder import AttackGraph

logger = logging.getLogger("netsentinel.attack_graph.store")


class AttackGraphStore:
    def __init__(self, db_dir: str):
        self._dir = db_dir
        os.makedirs(db_dir, exist_ok=True)

    def save(self, graph: AttackGraph) -> str:
        path = os.path.join(self._dir, f"{graph.graph_id}.json")
        with open(path, "w") as f:
            json.dump(graph.to_dict(), f, indent=2)
        logger.info("Attack graph saved: %s", path)
        return path

    def load(self, graph_id: str) -> dict | None:
        path = os.path.join(self._dir, f"{graph_id}.json")
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return json.load(f)

    def list_all(self) -> list:
        results = []
        for fname in sorted(os.listdir(self._dir)):
            if fname.endswith(".json"):
                fpath = os.path.join(self._dir, fname)
                try:
                    with open(fpath) as f:
                        results.append(json.load(f))
                except Exception:
                    pass
        return results