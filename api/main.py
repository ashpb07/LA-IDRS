# api/main.py
"""
FastAPI REST API layer for NetSentinel.
Exposes endpoints for the dashboard, external integrations, and P2P sharing.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import alerts, blocks, graphs, honeypots, status, reports

logger = logging.getLogger("netsentinel.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("NetSentinel API starting up")
    yield
    logger.info("NetSentinel API shutting down")


app = FastAPI(
    title="NetSentinel LA-IDRS API",
    description="Lightweight Autonomous Intrusion Detection and Response System",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(status.router,    prefix="/api/v1/status",    tags=["Status"])
app.include_router(alerts.router,    prefix="/api/v1/alerts",    tags=["Alerts"])
app.include_router(blocks.router,    prefix="/api/v1/blocks",    tags=["Blocks"])
app.include_router(graphs.router,    prefix="/api/v1/graphs",    tags=["Attack Graphs"])
app.include_router(honeypots.router, prefix="/api/v1/honeypots", tags=["Honeypots"])
app.include_router(reports.router,   prefix="/api/v1/reports",   tags=["XAI Reports"])


@app.get("/")
async def root():
    return {"service": "NetSentinel LA-IDRS", "version": "1.0.0", "status": "running"}