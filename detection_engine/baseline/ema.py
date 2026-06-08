# detection_engine/baseline/ema.py
"""
Exponential Moving Average updater for per-metric baselines.
Each metric (e.g. packets/sec per IP) maintains a running EMA and
a variance estimate (Welford online algorithm adapted for EMA).
"""

import threading
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class EMAState:
    mean: float = 0.0
    variance: float = 0.0
    count: int = 0


class EMATracker:
    """
    Thread-safe EMA tracker for arbitrary string keys.
    alpha: smoothing factor (0 < alpha < 1). Smaller = slower adaptation.
    """

    def __init__(self, alpha: float = 0.05):
        self._alpha = alpha
        self._states: Dict[str, EMAState] = {}
        self._lock = threading.Lock()

    def update(self, key: str, value: float) -> EMAState:
        with self._lock:
            if key not in self._states:
                self._states[key] = EMAState(mean=value, variance=0.0, count=1)
                return EMAState(mean=value, variance=0.0, count=1)

            s = self._states[key]
            diff = value - s.mean
            s.mean = s.mean + self._alpha * diff
            s.variance = (1 - self._alpha) * (s.variance + self._alpha * diff ** 2)
            s.count += 1
            return EMAState(mean=s.mean, variance=s.variance, count=s.count)

    def get(self, key: str) -> EMAState | None:
        with self._lock:
            return self._states.get(key)

    def deviation_score(self, key: str, value: float) -> float:
        """
        Returns how many standard deviations `value` is from the EMA mean.
        Returns 0.0 if insufficient data.
        """
        with self._lock:
            s = self._states.get(key)
        if s is None or s.count < 10 or s.variance < 1e-9:
            return 0.0
        import math
        std = math.sqrt(s.variance)
        return abs(value - s.mean) / std

    def all_keys(self) -> list:
        with self._lock:
            return list(self._states.keys())