# api/routes/reports.py
from fastapi import APIRouter, HTTPException
from ..services import state_service

router = APIRouter()


@router.get("/")
async def get_all_reports():
    return state_service.get_all_xai_reports()


@router.get("/{ip}")
async def get_report_for_ip(ip: str):
    r = state_service.get_xai_report(ip)
    if not r:
        raise HTTPException(status_code=404, detail=f"No report found for IP {ip}")
    return r
