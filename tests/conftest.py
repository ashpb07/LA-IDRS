# tests/conftest.py
"""
Pytest configuration and shared fixtures for NetSentinel tests.
"""

import os
import sys
import tempfile
import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def ip_state_store():
    from detection_engine.state.ip_state import IPStateStore
    return IPStateStore()


@pytest.fixture
def packet_cache():
    from detection_engine.state.cache import RecentPacketCache
    return RecentPacketCache(window_sec=10.0)


@pytest.fixture
def ema_tracker():
    from detection_engine.baseline.ema import EMATracker
    return EMATracker(alpha=0.1)


@pytest.fixture
def network_profile(tmp_dir):
    from detection_engine.baseline.profile import NetworkProfile
    path = os.path.join(tmp_dir, "profile.json")
    return NetworkProfile(profile_path=path)


@pytest.fixture
def risk_scorer(ip_state_store):
    from detection_engine.core.scorer import RiskScorer
    return RiskScorer(ip_state_store)


@pytest.fixture
def attack_graph_store(tmp_dir):
    from attack_graph.store import AttackGraphStore
    return AttackGraphStore(tmp_dir)


@pytest.fixture
def xai_generator(tmp_dir):
    from xai.report import XAIReportGenerator
    return XAIReportGenerator(reports_dir=tmp_dir)
