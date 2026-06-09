# attack_graph/renderer.py
"""
Converts an AttackGraph into a serialisable dict for the API / dashboard.
"""

from .builder import AttackGraph


def render(graph: AttackGraph) -> dict:
    """Return a dashboard-friendly representation of the graph."""
    d = graph.to_dict()
    d["narrative"] = graph.narrative()
    d["node_count"] = len(d["nodes"])
    d["edge_count"] = len(d["edges"])
    return d


def render_all(graphs: list) -> list:
    return [render(g) for g in graphs]
