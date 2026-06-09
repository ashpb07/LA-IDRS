# detection_engine/baseline/learner.py
"""
24-hour passive observation phase.
Collects traffic data without triggering any detection or blocking.
Updates NetworkProfile and EMATracker continuously.
Transitions to active detection mode after BASELINE_DURATION_SEC.
"""

import logging
import threading
import time

from .ema import EMATracker
from .profile import NetworkProfile

logger = logging.getLogger("netsentinel.baseline")


class BaselineLearner:
    def __init__(self, duration_sec: int, profile: NetworkProfile,
                 ema: EMATracker):
        self._duration   = duration_sec
        self._profile    = profile
        self._ema        = ema
        self._start_time = time.time()
        self._active     = True          # True = still in learning phase
        self._lock       = threading.Lock()
        self._timer      = threading.Timer(duration_sec, self._complete)
        self._timer.daemon = True
        self._timer.start()
        logger.info("Baseline learning phase started (%.0f s)", duration_sec)

    # ------------------------------------------------------------------ #
    def observe(self, src_ip: str, dst_port: int, pkt_len: int,
                pkt_rate: float) -> None:
        """
        Feed a packet observation into the learner.
        Called for every packet during the learning phase.
        """
        self._profile.update(src_ip, dst_port, pkt_len)
        self._ema.update(f"pkt_rate:{src_ip}", pkt_rate)
        self._ema.update("global_pkt_rate", pkt_rate)

    # ------------------------------------------------------------------ #
    @property
    def is_learning(self) -> bool:
        with self._lock:
            return self._active

    def elapsed_pct(self) -> float:
        elapsed = time.time() - self._start_time
        return min(elapsed / self._duration * 100, 100.0)

    # ------------------------------------------------------------------ #
    def _complete(self) -> None:
        with self._lock:
            self._active = False
        self._profile.save()
        logger.info("Baseline learning phase complete. Active detection enabled.")

    def force_complete(self) -> None:
        """Skip remaining baseline time — useful for testing."""
        self._timer.cancel()
        self._complete()
