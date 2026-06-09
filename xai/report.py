# xai/report.py
"""
Explainable AI (XAI) block report generator.
Produces structured JSON reports for every automated block action.
Optionally exports PDF via Jinja2 + weasyprint.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

from detection_engine.state.ip_state import IPState

logger = logging.getLogger("netsentinel.xai")

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "db", "reports")


class XAIReportGenerator:
    def __init__(self, reports_dir: str = REPORTS_DIR):
        self._dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)

    # ------------------------------------------------------------------ #
    def generate(self, state: IPState,
                 attack_graph_id: Optional[str] = None) -> dict:
        reasons = []
        for ev in state.events:
            reasons.append(f"{ev.event_type}: {ev.detail}" if ev.detail
                           else ev.event_type)

        report = {
            "ip":              state.ip,
            "blocked_at":      datetime.now(timezone.utc).isoformat(),
            "risk_score":      state.risk_score,
            "reasons":         reasons,
            "honeypot_contacts": state.honeypot_contacts,
            "attack_graph_id": attack_graph_id or "",
            "generated_at":    time.time(),
        }

        path = self._save_json(report, state.ip)
        logger.info("XAI report saved: %s", path)
        return report

    # ------------------------------------------------------------------ #
    def _save_json(self, report: dict, ip: str) -> str:
        fname = f"block_{ip.replace('.', '_')}_{int(time.time())}.json"
        path  = os.path.join(self._dir, fname)
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        return path

    def list_reports(self) -> list:
        results = []
        for fname in sorted(os.listdir(self._dir), reverse=True):
            if fname.endswith(".json"):
                try:
                    with open(os.path.join(self._dir, fname)) as f:
                        results.append(json.load(f))
                except Exception:
                    pass
        return results

    def get_report(self, ip: str) -> Optional[dict]:
        """Return the most recent report for an IP."""
        for report in self.list_reports():
            if report.get("ip") == ip:
                return report
        return None
