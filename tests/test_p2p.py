# tests/test_p2p.py
"""
Unit tests for P2P signature sanitizer and peer registry.
Run with: pytest tests/
"""

import os
import json
import tempfile
import pytest

from p2p.signature_sanitizer import sanitize, _derive_id
from p2p.peer_registry import PeerRegistry


class TestSignatureSanitizer:
    def test_strips_ip_fields(self):
        raw = {
            "ip":         "192.168.1.45",
            "src_ip":     "192.168.1.45",
            "dst_ip":     "10.0.0.1",
            "event_type": "block",
            "rule_ids":   ["PORT_SCAN_001"],
            "score":      87,
        }
        safe = sanitize(raw)
        assert "ip"     not in safe
        assert "src_ip" not in safe
        assert "dst_ip" not in safe

    def test_preserves_event_type(self):
        raw  = {"event_type": "block", "rule_ids": ["SYN_FLOOD_001"], "score": 90}
        safe = sanitize(raw)
        assert safe["event_type"] == "block"

    def test_sig_id_deterministic(self):
        raw = {"event_type": "block", "rule_ids": ["PORT_SCAN_001"], "tcp_flags": 2}
        id1 = _derive_id(raw)
        id2 = _derive_id(raw)
        assert id1 == id2
        assert id1.startswith("sig_")

    def test_sig_id_differs_for_different_events(self):
        r1 = {"event_type": "block", "rule_ids": ["PORT_SCAN_001"]}
        r2 = {"event_type": "block", "rule_ids": ["SYN_FLOOD_001"]}
        assert _derive_id(r1) != _derive_id(r2)

    def test_port_pattern_multi_port(self):
        raw  = {"event_type": "scan", "rule_ids": [], "ports": list(range(25))}
        safe = sanitize(raw)
        assert safe["port_pattern"] == "multi_port_sweep"

    def test_port_pattern_auth_ports(self):
        raw  = {"event_type": "brute", "rule_ids": [], "ports": [22, 23, 21]}
        safe = sanitize(raw)
        assert safe["port_pattern"] == "auth_ports"

    def test_has_timestamp(self):
        safe = sanitize({"event_type": "block"})
        assert "timestamp" in safe
        assert isinstance(safe["timestamp"], float)


class TestPeerRegistry:
    def test_register_and_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "peers.json")
            reg  = PeerRegistry(path=path)
            reg.register("10.0.0.1")
            reg.register("10.0.0.2")
            assert "10.0.0.1" in reg.active_peers()
            assert "10.0.0.2" in reg.active_peers()

    def test_no_duplicates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "peers.json")
            reg  = PeerRegistry(path=path)
            reg.register("10.0.0.3")
            reg.register("10.0.0.3")
            assert reg.active_peers().count("10.0.0.3") == 1

    def test_seed_peers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "peers.json")
            reg  = PeerRegistry(seed_peers=["10.0.0.4", "10.0.0.5"], path=path)
            peers = reg.active_peers()
            assert "10.0.0.4" in peers
            assert "10.0.0.5" in peers

    def test_persists_to_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "peers.json")
            reg  = PeerRegistry(path=path)
            reg.register("10.1.1.1")
            # Re-load from disk
            reg2 = PeerRegistry(path=path)
            assert "10.1.1.1" in reg2.active_peers()
