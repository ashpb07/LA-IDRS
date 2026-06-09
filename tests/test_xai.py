# tests/test_xai.py
"""
Unit tests for XAI block report generator.
Run with: pytest tests/
"""

import os
import json
import tempfile
import time
import pytest

from detection_engine.state.ip_state import IPStateStore, IPEvent
from xai.report import XAIReportGenerator


class TestXAIReportGenerator:
    def _make_state(self, ip: str, score: int, events: list):
        store = IPStateStore()
        state = store.get_or_create(ip)
        for ev in events:
            state.add_event(IPEvent(
                timestamp=time.time(),
                event_type=ev["type"],
                detail=ev.get("detail", ""),
                score_delta=ev.get("delta", 0),
            ))
        state.risk_score = score
        return state

    def test_report_contains_required_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen   = XAIReportGenerator(reports_dir=tmpdir)
            state = self._make_state("10.0.0.1", 87, [
                {"type": "TCP Port Scan",    "detail": "24 ports in 5s", "delta": 35},
                {"type": "Honeypot Contact", "detail": "port 31337",     "delta": 52},
            ])
            report = gen.generate(state, attack_graph_id="graph_001")

            assert report["ip"]         == "10.0.0.1"
            assert report["risk_score"] == 87
            assert isinstance(report["reasons"], list)
            assert len(report["reasons"]) == 2
            assert report["attack_graph_id"] == "graph_001"
            assert "blocked_at" in report

    def test_report_saved_to_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen   = XAIReportGenerator(reports_dir=tmpdir)
            state = self._make_state("10.0.0.2", 71, [
                {"type": "SYN Flood", "detail": "50 SYN/5s", "delta": 40},
            ])
            gen.generate(state)
            files = [f for f in os.listdir(tmpdir) if f.endswith(".json")]
            assert len(files) == 1

    def test_list_reports(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = XAIReportGenerator(reports_dir=tmpdir)
            for i in range(3):
                state = self._make_state(f"10.0.0.{i+10}", 80, [
                    {"type": "Scan", "detail": "", "delta": 80}
                ])
                gen.generate(state)
            reports = gen.list_reports()
            assert len(reports) == 3

    def test_get_report_for_ip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen   = XAIReportGenerator(reports_dir=tmpdir)
            state = self._make_state("192.168.1.99", 95, [
                {"type": "Honeypot Contact", "detail": "port 54321", "delta": 95}
            ])
            gen.generate(state)
            report = gen.get_report("192.168.1.99")
            assert report is not None
            assert report["ip"] == "192.168.1.99"

    def test_get_report_missing_ip_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = XAIReportGenerator(reports_dir=tmpdir)
            assert gen.get_report("1.2.3.4") is None
