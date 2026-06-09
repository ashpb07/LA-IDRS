# tests/test_attack_graph.py
"""
Unit tests for attack graph builder, store, and renderer.
Run with: pytest tests/
"""

import os
import json
import tempfile
import pytest

from attack_graph.builder import AttackGraphBuilder, AttackGraph
from attack_graph.store import AttackGraphStore
from attack_graph.renderer import render


class TestAttackGraphBuilder:
    def test_creates_graph_for_ip(self):
        builder = AttackGraphBuilder()
        graph   = builder.record_event("10.0.0.1", "TCP Port Scan", "24 ports")
        assert graph.ip == "10.0.0.1"
        assert len(graph._nodes) == 1

    def test_sequential_events_form_chain(self):
        builder = AttackGraphBuilder()
        builder.record_event("10.0.0.2", "TCP Port Scan",    "scan")
        builder.record_event("10.0.0.2", "Service Enum",     "port 22")
        builder.record_event("10.0.0.2", "Brute Force",      "ssh")
        graph = builder.active_graph("10.0.0.2")
        assert len(graph._nodes) == 3
        assert len(list(graph._graph.edges())) == 2

    def test_narrative_builds_correctly(self):
        builder = AttackGraphBuilder()
        builder.record_event("10.0.0.3", "Port Scan",  "")
        builder.record_event("10.0.0.3", "Honeypot",   "")
        graph = builder.active_graph("10.0.0.3")
        assert "[Port Scan]" in graph.narrative()
        assert "[Honeypot]"  in graph.narrative()
        assert "-->"         in graph.narrative()

    def test_finalize_moves_to_completed(self):
        builder = AttackGraphBuilder()
        builder.record_event("10.0.0.4", "Scan", "")
        finalized = builder.finalize("10.0.0.4")
        assert finalized is not None
        assert builder.active_graph("10.0.0.4") is None
        assert finalized in builder.all_completed()

    def test_separate_graphs_per_ip(self):
        builder = AttackGraphBuilder()
        builder.record_event("10.0.0.5", "Scan", "")
        builder.record_event("10.0.0.6", "Flood", "")
        assert builder.active_graph("10.0.0.5").ip == "10.0.0.5"
        assert builder.active_graph("10.0.0.6").ip == "10.0.0.6"


class TestAttackGraphStore:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store   = AttackGraphStore(tmpdir)
            builder = AttackGraphBuilder()
            builder.record_event("10.1.1.1", "Scan", "details")
            graph = builder.finalize("10.1.1.1")
            store.save(graph)
            loaded = store.load(graph.graph_id)
            assert loaded is not None
            assert loaded["ip"] == "10.1.1.1"

    def test_list_all(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store   = AttackGraphStore(tmpdir)
            builder = AttackGraphBuilder()
            for ip in ["10.1.1.2", "10.1.1.3", "10.1.1.4"]:
                builder.record_event(ip, "Scan", "")
                store.save(builder.finalize(ip))
            all_graphs = store.list_all()
            assert len(all_graphs) == 3

    def test_load_nonexistent_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = AttackGraphStore(tmpdir)
            assert store.load("nonexistent_graph_id") is None


class TestRenderer:
    def test_render_includes_narrative(self):
        builder = AttackGraphBuilder()
        builder.record_event("10.2.2.1", "Port Scan", "")
        builder.record_event("10.2.2.1", "Honeypot Contact", "")
        graph     = builder.finalize("10.2.2.1")
        rendered  = render(graph)
        assert "narrative"   in rendered
        assert "node_count"  in rendered
        assert "edge_count"  in rendered
        assert rendered["node_count"] == 2
        assert rendered["edge_count"] == 1
