# api/routes/blocks.py
from fastapi import APIRouter, HTTPException
from ..services import state_service

router = APIRouter()


@router.get("/")
async def get_blocked_ips():
    return state_service.get_blocked_ips()


@router.delete("/{ip}")
async def unblock_ip(ip: str):
    result = state_service.unblock_ip(ip)
    if not result:
        raise HTTPException(status_code=404, detail=f"IP {ip} not found in block list")
    return {"status": "unblocked", "ip": ip}
