# api/routes/graphs.py
from fastapi import APIRouter, HTTPException
from ..services import state_service

router = APIRouter()


@router.get("/")
async def get_all_graphs():
    return state_service.get_all_attack_graphs()


@router.get("/{graph_id}")
async def get_graph(graph_id: str):
    g = state_service.get_attack_graph(graph_id)
    if not g:
        raise HTTPException(status_code=404, detail=f"Graph {graph_id} not found")
    return g
