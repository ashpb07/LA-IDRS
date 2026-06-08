# api/routes/status.py
from fastapi import APIRouter
from ..services import state_service

router = APIRouter()


@router.get("/")
async def get_status():
    return state_service.get_system_status()