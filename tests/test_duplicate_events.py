"""
Tests for Duplicate Event Ingestion Protection (modules/database.py & api/server.py)
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from api.server import app
from modules.database import save_security_events_batch

def test_database_level_duplicate_rejection():
    unique_run_id = f"EVT-DUP-TEST-{uuid.uuid4().hex[:8].upper()}"
    ev = {
        "event_id": unique_run_id,
        "agent_id": "dup-agent",
        "hostname": "DUP-PC",
        "timestamp": "2026-10-28T12:00:00Z",
        "event_type": "FAILED_LOGIN",
        "windows_event_id": 4625,
        "username": "dup_user",
        "source_ip": "1.2.3.4",
        "description": "Duplicate test event"
    }
    
    # First insert: should succeed (1 inserted)
    ins1 = save_security_events_batch([ev])
    assert ins1 == 1

    # Second insert with identical event_id: should be ignored (0 inserted)
    ins2 = save_security_events_batch([ev])
    assert ins2 == 0

def test_api_level_duplicate_reporting():
    client = TestClient(app)
    headers = {"X-SOC-Agent-Token": "soc-secure-agent-token-2026"}
    unique_run_id = f"EVT-API-DUP-{uuid.uuid4().hex[:8].upper()}"
    
    ev_payload = {
        "event_id": unique_run_id,
        "agent_id": "api-dup-agent",
        "hostname": "API-DUP-PC",
        "event_type": "SUCCESSFUL_LOGIN",
        "windows_event_id": 4624,
        "username": "normal_user",
        "source_ip": "10.0.0.1",
        "description": "API duplicate test"
    }

    # First API post: should be ingested (1 ingested, 0 skipped)
    res1 = client.post("/api/events", json=[ev_payload], headers=headers)
    assert res1.status_code == 200
    assert res1.json()["ingested"] == 1
    assert res1.json()["duplicates_skipped"] == 0

    # Second API post with identical event: should be skipped (0 ingested, 1 skipped)
    res2 = client.post("/api/events", json=[ev_payload], headers=headers)
    assert res2.status_code == 200
    assert res2.json()["ingested"] == 0
    assert res2.json()["duplicates_skipped"] == 1
