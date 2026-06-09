# tests/test_detection.py
"""
Unit tests for detection engine components.
Run with: pytest tests/
"""

import time
import pytest

from detection_engine.state.cache import RecentPacketCache
from detection_engine.state.ip_state import IPStateStore, IPEvent
from detection_engine.baseline.ema import EMATracker
from detection_engine.baseline.profile import NetworkProfile
from detection_engine.core.scorer import RiskScorer
from detection_engine.core.signature import SignatureEngine
from detection_engine.core.behavior import BehaviorEngine


# ── EMA ────────────────────────────────────────────────────────────────────

class TestEMATracker:
    def test_first_update_sets_mean(self):
        ema = EMATracker(alpha=0.1)
        state = ema.update("pkt_rate:1.2.3.4", 100.0)
        assert state.mean == 100.0

    def test_mean_converges(self):
        ema = EMATracker(alpha=0.3)
        for _ in range(50):
            ema.update("key", 100.0)
        s = ema.get("key")
        assert abs(s.mean - 100.0) < 1.0

    def test_deviation_zero_insufficient_data(self):
        ema = EMATracker()
        ema.update("x", 10.0)
        assert ema.deviation_score("x", 50.0) == 0.0

    def test_deviation_high_on_spike(self):
        ema = EMATracker(alpha=0.05)
        for _ in range(100):
            ema.update("rate", 10.0)
        dev = ema.deviation_score("rate", 1000.0)
        assert dev > 4.0


# ── Cache ──────────────────────────────────────────────────────────────────

class TestRecentPacketCache:
    def test_syn_count(self):
        cache = RecentPacketCache(window_sec=10.0)
        FLAG_SYN = 0x02
        for _ in range(5):
            cache.record("10.0.0.1", 80, FLAG_SYN, 60)
        assert cache.syn_count("10.0.0.1") == 5

    def test_unique_ports(self):
        cache = RecentPacketCache(window_sec=10.0)
        for port in [22, 80, 443, 8080, 3306]:
            cache.record("10.0.0.2", port, 0x02, 60)
        assert len(cache.unique_ports("10.0.0.2")) == 5

    def test_empty_ip(self):
        cache = RecentPacketCache()
        assert cache.syn_count("1.2.3.4") == 0
        assert cache.unique_ports("1.2.3.4") == set()
        assert cache.packet_rate("1.2.3.4") == 0.0


# ── IPStateStore ───────────────────────────────────────────────────────────

class TestIPStateStore:
    def test_create_and_retrieve(self):
        store = IPStateStore()
        state = store.get_or_create("192.168.1.1")
        assert state.ip == "192.168.1.1"
        assert state.risk_score == 0

    def test_score_accumulates(self):
        store = IPStateStore()
        state = store.get_or_create("192.168.1.2")
        state.add_event(IPEvent(timestamp=time.time(),
                                event_type="test", score_delta=25))
        state.add_event(IPEvent(timestamp=time.time(),
                                event_type="test2", score_delta=30))
        assert state.risk_score == 55

    def test_score_capped_at_100(self):
        store = IPStateStore()
        state = store.get_or_create("192.168.1.3")
        state.add_event(IPEvent(timestamp=time.time(),
                                event_type="big", score_delta=200))
        assert state.risk_score == 100

    def test_mark_blocked(self):
        store = IPStateStore()
        store.get_or_create("10.0.0.5")
        store.mark_blocked("10.0.0.5")
        assert "10.0.0.5" in store.blocked_ips()


# ── Scorer ─────────────────────────────────────────────────────────────────

class TestRiskScorer:
    def test_apply_hits(self):
        store  = IPStateStore()
        scorer = RiskScorer(store)
        hits   = [("TCP Port Scan", 35, "15 ports in 10s"),
                  ("Packet Rate Anomaly", 20, "spike")]
        state  = scorer.apply_hits("10.1.1.1", hits)
        assert state.risk_score == 55

    def test_honeypot_scores_max(self):
        store  = IPStateStore()
        scorer = RiskScorer(store)
        state  = scorer.apply_honeypot_contact("10.1.1.2", 31337)
        assert state.risk_score == 100


# ── Signature Engine ────────────────────────────────────────────────────────

class TestSignatureEngine:
    def _make_engine(self):
        cache = RecentPacketCache(window_sec=10.0)
        return SignatureEngine(cache), cache

    def test_no_hits_clean_traffic(self):
        engine, cache = self._make_engine()
        cache.record("10.2.2.1", 80, 0x18, 200)   # PSH|ACK — normal
        hits = engine.evaluate("10.2.2.1", 80, 0x18)
        assert hits == []

    def test_port_scan_detected(self):
        engine, cache = self._make_engine()
        FLAG_SYN = 0x02
        for port in range(1, 25):          # 24 unique ports
            cache.record("10.2.2.2", port, FLAG_SYN, 60)
        hits = engine.evaluate("10.2.2.2", 24, FLAG_SYN)
        rule_names = [h[0] for h in hits]
        assert "TCP Port Scan" in rule_names

    def test_brute_force_detected(self):
        engine, cache = self._make_engine()
        for _ in range(12):
            cache.record("10.2.2.3", 22, 0x02, 60)
        hits = engine.evaluate("10.2.2.3", 22, 0x02)
        rule_names = [h[0] for h in hits]
        assert "Brute Force Login Attempt" in rule_names
