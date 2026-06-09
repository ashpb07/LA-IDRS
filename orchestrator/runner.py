# orchestrator/runner.py
"""
Main orchestrator — instantiates every engine, wires callbacks together,
starts the API server, and keeps everything alive.
"""

import asyncio
import logging
import os
import subprocess
import sys
import threading
import time

import uvicorn

from .config_loader import get_config
from detection_engine.utils.logger import setup_logging
from detection_engine.baseline.ema import EMATracker
from detection_engine.baseline.profile import NetworkProfile
from detection_engine.baseline.learner import BaselineLearner
from detection_engine.state.ip_state import IPStateStore
from detection_engine.state.cache import RecentPacketCache
from detection_engine.core.detector import Detector
from detection_engine import config as de_config

from attack_graph.builder import AttackGraphBuilder
from attack_graph.store import AttackGraphStore
from attack_graph.renderer import render

from deception.signal import HoneypotSignal
from deception.honeypot import HoneypotManager

from xai.report import XAIReportGenerator

from response_engine.core.blocker import IPBlocker
from response_engine.core.unblocker import ScheduledUnblocker

from p2p.peer_registry import PeerRegistry
from p2p.gossip import GossipNode

from api.main import app as fastapi_app
from api.services import state_service

logger = logging.getLogger("netsentinel.orchestrator")


class NetSentinelRunner:
    def __init__(self):
        self._cfg = get_config()
        setup_logging(self._cfg["log_level"])

        os.makedirs(de_config.LOG_DIR, exist_ok=True)
        os.makedirs(de_config.DB_DIR,  exist_ok=True)

        # ── Core engines ──────────────────────────────────────────────
        self._blocker    = IPBlocker()
        self._unblocker  = ScheduledUnblocker(self._blocker,
                                               ttl_sec=self._cfg["ban_ttl_sec"])
        self._graph_builder = AttackGraphBuilder()
        self._graph_store   = AttackGraphStore(
            os.path.join(de_config.DB_DIR, "graphs"))
        self._xai        = XAIReportGenerator()

        # ── Honeypot layer ─────────────────────────────────────────────
        self._hp_signal  = HoneypotSignal()
        self._hp_manager = HoneypotManager(self._hp_signal)

        # ── P2P ────────────────────────────────────────────────────────
        self._peer_registry = PeerRegistry(seed_peers=self._cfg["p2p_peers"])
        self._gossip        = GossipNode(self._peer_registry,
                                          port=self._cfg["p2p_port"])

        # ── Detector ───────────────────────────────────────────────────
        self._detector = Detector(
            on_alert    = self._on_alert,
            on_block    = self._on_block,
            on_honeypot = self._on_honeypot,
            on_graph_event = self._on_graph_event,
            on_xai_report  = self._on_xai_report,
        )

        # Wire honeypot contact → scorer
        self._hp_signal.register(self._on_honeypot_contact)

        # Inject live references into the API service layer
        state_service.inject(
            state_store = self._detector._store,
            graph_store = self._graph_store,
            xai         = self._xai,
            blocker     = self._blocker,
            honeypots   = self._hp_manager,
            learner     = self._detector._learner,
        )

        if self._cfg["skip_baseline"]:
            logger.warning("NS_SKIP_BASELINE=true — forcing baseline complete")
            self._detector._learner.force_complete()

    # ── Callbacks ──────────────────────────────────────────────────────

    def _on_alert(self, state) -> None:
        logger.info("ALERT: %s score=%d", state.ip, state.risk_score)

    def _on_block(self, state) -> None:
        self._blocker.block(state.ip)
        graph = self._graph_builder.finalize(state.ip)
        if graph:
            self._graph_store.save(graph)

    def _on_honeypot(self, ip: str) -> None:
        self._hp_manager.spawn_for_ip(ip)

    def _on_honeypot_contact(self, ip: str, port: int) -> None:
        state_service.record_honeypot_contact(ip, port)
        self._detector._scorer.apply_honeypot_contact(ip, port)
        self._detector._decision.evaluate(ip)

    def _on_graph_event(self, ip: str, event_type: str, detail: str) -> None:
        self._graph_builder.record_event(ip, event_type, detail)

    def _on_xai_report(self, state) -> None:
        active = self._graph_builder.active_graph(state.ip)
        graph_id = active.graph_id if active else None
        self._xai.generate(state, attack_graph_id=graph_id)
        if self._cfg["p2p_enabled"]:
            sig = {
                "event_type": "block",
                "rule_ids":   [e.event_type for e in state.events],
                "score":      state.risk_score,
            }
            asyncio.run_coroutine_threadsafe(
                self._gossip.broadcast(sig), self._p2p_loop)

    # ── Startup ────────────────────────────────────────────────────────

    def start(self) -> None:
        logger.info("NetSentinel LA-IDRS starting …")

        self._unblocker.start()
        self._detector.start()

        if self._cfg["p2p_enabled"]:
            self._start_p2p()

        self._start_packet_engine()
        self._start_api()          # blocks — called last

    def _start_packet_engine(self) -> None:
        binary = os.path.join(
            os.path.dirname(__file__), "..", "packet_engine", "build", "packet_engine")
        if not os.path.exists(binary):
            logger.warning("Packet engine binary not found at %s — "
                           "run 'make' inside packet_engine/ first.", binary)
            return
        iface = self._cfg["interface"]
        def _run():
            logger.info("Starting packet engine on %s", iface)
            proc = subprocess.Popen([binary, iface])
            proc.wait()
            logger.warning("Packet engine exited with code %d", proc.returncode)
        t = threading.Thread(target=_run, daemon=True)
        t.start()

    def _start_p2p(self) -> None:
        self._p2p_loop = asyncio.new_event_loop()
        def _run():
            asyncio.set_event_loop(self._p2p_loop)
            self._p2p_loop.run_until_complete(
                self._gossip.listen(self._on_peer_signature))
        t = threading.Thread(target=_run, daemon=True, name="p2p-gossip")
        t.start()
        logger.info("P2P gossip node started on port %d", self._cfg["p2p_port"])

    def _on_peer_signature(self, sig: dict) -> None:
        logger.info("Absorbed peer signature: %s", sig.get("sig_id"))

    def _start_api(self) -> None:
        logger.info("API starting on %s:%d",
                    self._cfg["api_host"], self._cfg["api_port"])
        uvicorn.run(
            fastapi_app,
            host=self._cfg["api_host"],
            port=self._cfg["api_port"],
            log_level=self._cfg["log_level"].lower(),
        )
