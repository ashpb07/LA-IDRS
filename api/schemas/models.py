# api/schemas/models.py
"""
Pydantic models for API request/response validation.
"""

from pydantic import BaseModel
from typing import List, Optional


class EventSchema(BaseModel):
    type: str
    detail: str = ""
    ts: float
    delta: int


class AlertSchema(BaseModel):
    ip: str
    risk_score: int
    is_blocked: bool
    events: List[EventSchema] = []


class BlockedIPSchema(BaseModel):
    ip: str


class AttackNodeSchema(BaseModel):
    node_id: str
    event_type: str
    detail: str
    timestamp: float


class AttackGraphSchema(BaseModel):
    graph_id: str
    ip: str
    created: float
    nodes: List[AttackNodeSchema] = []
    edges: List[list] = []
    narrative: Optional[str] = None


class XAIReportSchema(BaseModel):
    ip: str
    blocked_at: str
    risk_score: int
    reasons: List[str] = []
    honeypot_contacts: int = 0
    attack_graph_id: str = ""
    generated_at: float


class SystemStatusSchema(BaseModel):
    baseline_learning: bool
    baseline_pct: float
    blocked_count: int
    tracked_ips: int
    timestamp: float


class HoneypotContactSchema(BaseModel):
    ip: str
    port: int
    timestamp: float


class HoneypotStatusSchema(BaseModel):
    contact_count: int
