# p2p/signature_sanitizer.py
"""
Strips all identifying information (source IPs, destination IPs) from a
threat signature before broadcasting it to peer nodes.
Only behavioural patterns and rule identifiers are shared.
"""

import hashlib
import json
import time


def sanitize(raw: dict) -> dict:
    """
    Input:  raw signature dict (may contain IP addresses, ports, etc.)
    Output: anonymized signature safe for P2P broadcast
    """
    safe = {
        "sig_id":       _derive_id(raw),
        "event_type":   raw.get("event_type", "unknown"),
        "rule_ids":     raw.get("rule_ids", []),
        "tcp_flags":    raw.get("tcp_flags"),
        "protocol":     raw.get("protocol"),
        "port_pattern": _port_pattern(raw.get("ports", [])),
        "score":        raw.get("score", 0),
        "timestamp":    time.time(),
        "version":      "1.0",
    }
    # Explicitly drop any IP fields
    for field in ("ip", "src_ip", "dst_ip", "source", "destination"):
        safe.pop(field, None)
    return safe


def _derive_id(raw: dict) -> str:
    """Deterministic signature ID from event type + rule IDs."""
    key = json.dumps({
        "event_type": raw.get("event_type", ""),
        "rule_ids":   sorted(raw.get("rule_ids", [])),
        "tcp_flags":  raw.get("tcp_flags"),
    }, sort_keys=True)
    return "sig_" + hashlib.sha256(key.encode()).hexdigest()[:16]


def _port_pattern(ports: list) -> str:
    """Encode a list of ports as a coarse pattern string."""
    if not ports:
        return ""
    if len(ports) > 20:
        return "multi_port_sweep"
    if all(p in {21, 22, 23, 3389, 5900} for p in ports):
        return "auth_ports"
    return f"{len(ports)}_ports"