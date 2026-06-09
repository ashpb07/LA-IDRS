# attack_graph/builder.py
"""
Causal attack graph builder.
Correlates sequential security events per IP into a directed graph
representing the attack narrative.
"""

import logging
import time
from typing import Dict, List, Optional

import networkx as nx

logger = logging.getLogger("netsentinel.attack_graph")


class AttackNode:
    def __init__(self, node_id: str, event_type: str, detail: str,
                 timestamp: float):
        self.node_id    = node_id
        self.event_type = event_type
        self.detail     = detail
        self.timestamp  = timestamp

    def to_dict(self) -> dict:
        return {
            "node_id":    self.node_id,
            "event_type": self.event_type,
            "detail":     self.detail,
            "timestamp":  self.timestamp,
        }


class AttackGraph:
    def __init__(self, graph_id: str, ip: str):
        self.graph_id = graph_id
        self.ip       = ip
        self.created  = time.time()
        self._graph   = nx.DiGraph()
        self._nodes: List[AttackNode] = []
        self._prev_node_id: Optional[str] = None

    def add_event(self, event_type: str, detail: str) -> AttackNode:
        node_id = f"{self.graph_id}_{len(self._nodes)}"
        node = AttackNode(node_id, event_type, detail, time.time())
        self._graph.add_node(node_id, **node.to_dict())
        if self._prev_node_id:
            self._graph.add_edge(self._prev_node_id, node_id)
        self._prev_node_id = node_id
        self._nodes.append(node)
        logger.debug("Graph %s: [%s] → %s", self.graph_id, event_type, detail)
        return node

    def to_dict(self) -> dict:
        return {
            "graph_id": self.graph_id,
            "ip":       self.ip,
            "created":  self.created,
            "nodes":    [n.to_dict() for n in self._nodes],
            "edges":    list(self._graph.edges()),
        }

    def narrative(self) -> str:
        return " --> ".join(f"[{n.event_type}]" for n in self._nodes)


class AttackGraphBuilder:
    def __init__(self):
        self._graphs: Dict[str, AttackGraph] = {}
        self._completed: List[AttackGraph] = []

    def get_or_create(self, ip: str) -> AttackGraph:
        if ip not in self._graphs:
            graph_id = f"graph_{ip.replace('.', '_')}_{int(time.time())}"
            self._graphs[ip] = AttackGraph(graph_id, ip)
            logger.info("New attack graph started for %s: %s", ip, graph_id)
        return self._graphs[ip]

    def record_event(self, ip: str, event_type: str, detail: str) -> AttackGraph:
        graph = self.get_or_create(ip)
        graph.add_event(event_type, detail)
        return graph

    def finalize(self, ip: str) -> Optional[AttackGraph]:
        """Mark a graph as complete when the IP is blocked."""
        graph = self._graphs.pop(ip, None)
        if graph:
            self._completed.append(graph)
            logger.info("Attack graph finalized for %s: %s",
                        ip, graph.narrative())
        return graph

    def all_completed(self) -> List[AttackGraph]:
        return list(self._completed)

    def active_graph(self, ip: str) -> Optional[AttackGraph]:
        return self._graphs.get(ip)
