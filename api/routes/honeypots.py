# api/routes/honeypots.py
from fastapi import APIRouter
from ..services import state_service

router = APIRouter()


@router.get("/")
async def get_honeypot_status():
    return state_service.get_honeypot_status()


@router.get("/contacts")
async def get_honeypot_contacts():
    return state_service.get_honeypot_contacts()
