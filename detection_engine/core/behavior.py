# detection_engine/core/behavior.py
"""
Behavior-based anomaly detection.
Compares current per-IP activity against the learned EMA baseline.
"""

import logging
from typing import List, Tuple

from ..baseline.ema import EMATracker
from ..baseline.profile import NetworkProfile
from ..state.cache import RecentPacketCache

logger = logging.getLogger("netsentinel.behavior")

# Deviation thresholds (standard deviations above EMA mean)
RATE_ANOMALY_THRESHOLD    = 4.0   # packet rate spike
PORT_DIVERSITY_THRESHOLD  = 3.0   # unusual spread of destination ports

# Score deltas for behavioral findings
SCORE_RATE_ANOMALY   = 20
SCORE_PORT_DIVERSITY = 15
SCORE_PROTO_MISMATCH = 10


class BehaviorEngine:
    def __init__(self, cache: RecentPacketCache, ema: EMATracker,
                 profile: NetworkProfile):
        self._cache   = cache
        self._ema     = ema
        self._profile = profile

    def evaluate(self, ip: str, dst_port: int, protocol: int,
                 pkt_rate: float) -> List[Tuple[str, int, str]]:
        """
        Returns a list of (finding_name, score_delta, detail).
        """
        hits = []

        # 1. Packet rate anomaly
        dev = self._ema.deviation_score(f"pkt_rate:{ip}", pkt_rate)
        if dev >= RATE_ANOMALY_THRESHOLD:
            detail = (f"Packet rate {pkt_rate:.1f} pkt/s is "
                      f"{dev:.1f}σ above baseline mean")
            hits.append(("Packet Rate Anomaly", SCORE_RATE_ANOMALY, detail))
            logger.debug("Rate anomaly for %s: %.1f pkt/s (%.1fσ)", ip, pkt_rate, dev)

        # 2. Port diversity anomaly
        recent_ports = len(self._cache.unique_ports(ip))
        historical   = self._profile.unique_port_count(ip) or 1
        if recent_ports > historical * 3 and recent_ports > 10:
            detail = (f"Accessing {recent_ports} unique ports; "
                      f"historical baseline is ~{historical}")
            hits.append(("Unusual Port Diversity", SCORE_PORT_DIVERSITY, detail))

        # 3. Protocol mismatch heuristic (TCP on UDP-typical ports)
        UDP_TYPICAL = {53, 123, 161, 500, 4500}
        TCP_PROTO   = 6
        if protocol == TCP_PROTO and dst_port in UDP_TYPICAL:
            detail = f"TCP packet to typically-UDP port {dst_port}"
            hits.append(("Protocol Mismatch", SCORE_PROTO_MISMATCH, detail))

        return hits
