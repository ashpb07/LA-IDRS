# api/services/state_service.py
"""
Shared in-memory service layer.
The orchestrator injects live references to the core engines here,
so all API routes read from the same running state.
"""

import time
from typing import Any

# These are injected by orchestrator/runner.py at startup
_ip_state_store     = None
_attack_graph_store = None
_xai_generator      = None
_ip_blocker         = None
_honeypot_manager   = None
_learner            = None
_honeypot_contacts: list = []


def inject(state_store=None, graph_store=None, xai=None,
           blocker=None, honeypots=None, learner=None):
    global _ip_state_store, _attack_graph_store, _xai_generator
    global _ip_blocker, _honeypot_manager, _learner
    _ip_state_store     = state_store
    _attack_graph_store = graph_store
    _xai_generator      = xai
    _ip_blocker         = blocker
    _honeypot_manager   = honeypots
    _learner            = learner


def record_honeypot_contact(ip: str, port: int) -> None:
    _honeypot_contacts.append({"ip": ip, "port": port, "timestamp": time.time()})


# ------------------------------------------------------------------ #
def get_system_status() -> dict:
    learning = _learner.is_learning if _learner else False
    pct      = _learner.elapsed_pct() if _learner else 100.0
    blocked  = len(_ip_blocker.all_banned()) if _ip_blocker else 0
    total_ips = len(_ip_state_store.all()) if _ip_state_store else 0
    return {
        "baseline_learning": learning,
        "baseline_pct":      round(pct, 1),
        "blocked_count":     blocked,
        "tracked_ips":       total_ips,
        "timestamp":         time.time(),
    }


def get_recent_alerts(limit: int = 100) -> list:
    if not _ip_state_store:
        return []
    results = []
    for state in _ip_state_store.all():
        if state.risk_score >= 31:
            results.append({
                "ip":         state.ip,
                "risk_score": state.risk_score,
                "is_blocked": state.is_blocked,
                "events":     [
                    {"type": e.event_type, "detail": e.detail,
                     "ts": e.timestamp, "delta": e.score_delta}
                    for e in state.events[-10:]
                ],
            })
    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results[:limit]


def get_alerts_for_ip(ip: str) -> dict:
    if not _ip_state_store:
        return {}
    state = _ip_state_store.get(ip)
    if not state:
        return {}
    return {
        "ip": state.ip,
        "risk_score": state.risk_score,
        "is_blocked": state.is_blocked,
        "events": [
            {"type": e.event_type, "detail": e.detail,
             "ts": e.timestamp, "delta": e.score_delta}
            for e in state.events
        ],
    }


def get_blocked_ips() -> list:
    if not _ip_blocker:
        return []
    return [{"ip": ip} for ip in _ip_blocker.all_banned()]


def unblock_ip(ip: str) -> bool:
    if not _ip_blocker:
        return False
    return _ip_blocker.unblock(ip)


def get_all_attack_graphs() -> list:
    if not _attack_graph_store:
        return []
    return _attack_graph_store.list_all()


def get_attack_graph(graph_id: str) -> Any:
    if not _attack_graph_store:
        return None
    return _attack_graph_store.load(graph_id)


def get_honeypot_status() -> dict:
    return {
        "contact_count": len(_honeypot_contacts),
    }


def get_honeypot_contacts() -> list:
    return list(reversed(_honeypot_contacts[-100:]))


def get_all_xai_reports() -> list:
    if not _xai_generator:
        return []
    return _xai_generator.list_reports()


def get_xai_report(ip: str) -> Any:
    if not _xai_generator:
        return None
    return _xai_generator.get_report(ip)
