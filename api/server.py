"""
AI SOC Assistant - Central Ingestion FastAPI Service
Receives, authenticates, validates, and routes security events from local and remote agents.
Feeds events into the real-time sliding-window detection engine and persists to SQLite.
"""

from typing import List, Dict, Any, Optional, Union
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from fastapi import FastAPI, Header, HTTPException, status, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from config.settings import (
    SOC_API_HOST,
    SOC_API_PORT,
    SOC_AGENT_TOKEN,
    SOC_MAX_EVENT_BATCH
)
from modules.live_monitor.event_schema import (
    SecurityEvent,
    SecurityEventBatch,
    AgentHeartbeat
)
from modules.live_monitor.detection_rules import get_live_detection_engine
from modules.database import (
    register_or_update_agent,
    update_agent_heartbeat,
    save_security_events_batch,
    save_live_alert,
    get_monitored_agents,
    get_live_alerts,
    get_live_monitoring_metrics
)

app = FastAPI(
    title="AI SOC Assistant - Security Ingestion API",
    description="Central ingestion service for normalized Windows and Linux security event logs",
    version="2.0.0"
)

# Optional CORS middleware for web clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_agent_token(
    x_soc_agent_token: Optional[str] = Header(None, alias="X-SOC-Agent-Token"),
    authorization: Optional[str] = Header(None)
) -> bool:
    """
    Validates agent authentication token from either X-SOC-Agent-Token or Authorization header.
    Never prints or exposes secret tokens in console logs.
    """
    supplied_token = x_soc_agent_token
    if not supplied_token and authorization:
        parts = authorization.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() in ["bearer", "token"]:
            supplied_token = parts[1]
        else:
            supplied_token = authorization

    if not supplied_token or supplied_token.strip() != SOC_AGENT_TOKEN.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing agent authentication token. Configure SOC_AGENT_TOKEN."
        )
    return True

@app.get("/")
def root():
    """API Root diagnostic endpoint."""
    return {
        "service": "AI SOC Assistant - Ingestion Service",
        "version": "2.0.0",
        "status": "online",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "documentation": "/docs"
    }

@app.get("/health")
def health_check():
    """Service health and database diagnostic check."""
    metrics = get_live_monitoring_metrics()
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "live_metrics": metrics
    }

@app.post("/api/heartbeat")
def agent_heartbeat(
    heartbeat: AgentHeartbeat,
    authenticated: bool = Depends(verify_agent_token)
):
    """
    Registers an agent heartbeat, updating its last_seen timestamp and network metadata.
    """
    ok = register_or_update_agent(
        agent_id=heartbeat.agent_id,
        hostname=heartbeat.hostname,
        ip_address=heartbeat.ip_address,
        os_type=heartbeat.os_type,
        agent_version=heartbeat.agent_version
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to register agent heartbeat in database.")
    
    return {
        "status": "success",
        "message": f"Heartbeat recorded for agent '{heartbeat.agent_id}'.",
        "last_seen": datetime.now(timezone.utc).isoformat()
    }

class EventsIngestRequest(BaseModel):
    """Payload accepting either list of events or batch object."""
    events: List[SecurityEvent] = Field(..., max_length=SOC_MAX_EVENT_BATCH)

@app.post("/api/events")
def ingest_security_events(
    payload: Union[SecurityEventBatch, EventsIngestRequest, List[SecurityEvent], SecurityEvent],
    authenticated: bool = Depends(verify_agent_token)
):
    """
    Ingests normalized security events:
    1. Validates schema and token
    2. Deduplicates against database
    3. Feeds newly arriving events into the LiveDetectionEngine
    4. Persists any triggered threat alerts
    5. Returns ingestion summary
    """
    # Normalize input into list of SecurityEvent
    raw_events: List[SecurityEvent] = []
    if isinstance(payload, SecurityEventBatch) or isinstance(payload, EventsIngestRequest):
        raw_events = payload.events
    elif isinstance(payload, list):
        raw_events = payload
    elif isinstance(payload, SecurityEvent):
        raw_events = [payload]
    else:
        raise HTTPException(status_code=400, detail="Invalid event payload format.")

    if not raw_events:
        raise HTTPException(status_code=400, detail="Event list cannot be empty.")

    if len(raw_events) > SOC_MAX_EVENT_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"Batch size {len(raw_events)} exceeds maximum allowed ({SOC_MAX_EVENT_BATCH})."
        )

    # 1. Update Agent Registration / Last Seen for all distinct agents in batch
    distinct_agents = {ev.agent_id: ev.hostname for ev in raw_events}
    for aid, hname in distinct_agents.items():
        register_or_update_agent(agent_id=aid, hostname=hname)

    # 2. Convert to dicts for SQLite batch insertion (handles duplicate ignoring)
    event_dicts = [ev.model_dump() for ev in raw_events]
    inserted_count = save_security_events_batch(event_dicts)
    duplicates = len(raw_events) - inserted_count

    # 3. Process events through the LiveDetectionEngine
    engine = get_live_detection_engine()
    triggered_alerts = engine.process_batch(raw_events)

    # 4. Save any triggered alerts to SQLite
    alerts_saved = 0
    for alert in triggered_alerts:
        if save_live_alert(alert.to_dict()):
            alerts_saved += 1

    return {
        "success": True,
        "received": len(raw_events),
        "ingested": inserted_count,
        "duplicates_skipped": duplicates,
        "alerts_triggered": len(triggered_alerts),
        "alerts_saved": alerts_saved,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/agents")
def list_monitored_agents(authenticated: bool = Depends(verify_agent_token)):
    """Returns all registered agents."""
    return {"agents": get_monitored_agents()}

@app.get("/api/alerts")
def list_live_alerts(
    limit: int = 50,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    authenticated: bool = Depends(verify_agent_token)
):
    """Returns recent live alerts."""
    return {"alerts": get_live_alerts(limit=limit, status=status, severity=severity)}

@app.get("/api/metrics")
def get_metrics():
    """Telemetry metrics endpoint for dashboard polling."""
    return get_live_monitoring_metrics()

if __name__ == "__main__":
    import uvicorn
    print(f"[*] Starting AI SOC Ingestion API on http://{SOC_API_HOST}:{SOC_API_PORT}")
    uvicorn.run("api.server:app", host=SOC_API_HOST, port=SOC_API_PORT, reload=False)
