# detection_engine/core/detector.py
"""
Main detection loop.
Runs a UNIX socket server that receives packet_meta_t structs from the C
packet engine, feeds them through baseline learning / signature / behavior
engines, then passes results to the decision engine.
"""

import logging
import os
import socket
import struct
import threading
import time
from typing import Optional

from ..baseline.ema import EMATracker
from ..baseline.learner import BaselineLearner
from ..baseline.profile import NetworkProfile
from ..state.cache import RecentPacketCache
from ..state.ip_state import IPStateStore
from .behavior import BehaviorEngine
from .decision import DecisionEngine
from .scorer import RiskScorer
from .signature import SignatureEngine
from .. import config

logger = logging.getLogger("netsentinel.detector")

# Matches packet_meta_t in emitter.h
# src_ip[16], dst_ip[16], src_port(H), dst_port(H), protocol(B),
# tcp_flags(B), payload_len(H), ts_sec(I), ts_usec(I)
PACKET_FMT  = "16s16sHHBBHII"
PACKET_SIZE = struct.calcsize(PACKET_FMT)


class Detector:
    def __init__(self,
                 on_alert=None,
                 on_block=None,
                 on_honeypot=None,
                 on_graph_event=None,
                 on_xai_report=None):
        # Shared state
        self._cache   = RecentPacketCache(window_sec=10.0)
        self._store   = IPStateStore()
        self._profile = NetworkProfile(
            os.path.join(config.DB_DIR, "network_profile.json"))
        self._ema     = EMATracker(alpha=config.EMA_ALPHA)

        # Engines
        self._sig     = SignatureEngine(self._cache)
        self._beh     = BehaviorEngine(self._cache, self._ema, self._profile)
        self._scorer  = RiskScorer(self._store)
        self._decision = DecisionEngine(
            self._store,
            on_alert=on_alert,
            on_block=on_block,
            on_honeypot=on_honeypot,
        )
        self._learner = BaselineLearner(
            config.BASELINE_DURATION_SEC, self._profile, self._ema)

        self._on_graph_event = on_graph_event
        self._on_xai_report  = on_xai_report
        self._running = False

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self._running = True
        t = threading.Thread(target=self._serve, daemon=True)
        t.start()
        logger.info("Detector listening on %s", config.SOCKET_PATH)

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------ #
    def _serve(self) -> None:
        if os.path.exists(config.SOCKET_PATH):
            os.unlink(config.SOCKET_PATH)

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(config.SOCKET_PATH)
        srv.listen(1)
        srv.settimeout(1.0)

        while self._running:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._handle_conn,
                              args=(conn,), daemon=True).start()

        srv.close()
        if os.path.exists(config.SOCKET_PATH):
            os.unlink(config.SOCKET_PATH)

    def _handle_conn(self, conn: socket.socket) -> None:
        buf = b""
        try:
            while self._running:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= PACKET_SIZE:
                    raw, buf = buf[:PACKET_SIZE], buf[PACKET_SIZE:]
                    self._process(raw)
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    def _process(self, raw: bytes) -> None:
        try:
            fields = struct.unpack(PACKET_FMT, raw)
        except struct.error:
            return

        src_ip     = fields[0].rstrip(b"\x00").decode()
        dst_ip     = fields[1].rstrip(b"\x00").decode()
        src_port   = fields[2]
        dst_port   = fields[3]
        protocol   = fields[4]
        tcp_flags  = fields[5]
        payload_len = fields[6]

        if not src_ip:
            return

        self._cache.record(src_ip, dst_port, tcp_flags, payload_len)
        pkt_rate = self._cache.packet_rate(src_ip)

        # Always feed the baseline learner
        self._learner.observe(src_ip, dst_port, payload_len, pkt_rate)

        # Skip detection during learning phase
        if self._learner.is_learning:
            return

        state = self._store.get_or_create(src_ip)
        if state.is_blocked:
            return

        # Signature hits
        sig_hits = self._sig.evaluate(src_ip, dst_port, tcp_flags)
        # Behavior hits
        beh_hits = self._beh.evaluate(src_ip, dst_port, protocol, pkt_rate)

        all_hits = sig_hits + beh_hits
        if all_hits:
            self._scorer.apply_hits(src_ip, all_hits)
            if self._on_graph_event:
                for name, _, detail in all_hits:
                    self._on_graph_event(src_ip, name, detail)

        # Port scan flag
        port_scan = any("PORT_SCAN" in h[0].upper() or "Scan" in h[0]
                        for h in sig_hits)

        action = self._decision.evaluate(src_ip, port_scan_detected=port_scan)

        if action in ("block",) and self._on_xai_report:
            s = self._store.get(src_ip)
            if s:
                self._on_xai_report(s)
