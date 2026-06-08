# api/routes/alerts.py
from fastapi import APIRouter
from ..services import state_service

router = APIRouter()


@router.get("/")
async def get_alerts():
    return state_service.get_recent_alerts()


@router.get("/{ip}")
async def get_alerts_for_ip(ip: str):
    return state_service.get_alerts_for_ip(ip)