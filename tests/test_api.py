"""
Tests for Central Ingestion FastAPI Service (api/server.py)
"""

import pytest
from fastapi.testclient import TestClient
from api.server import app

@pytest.fixture
def client():
    return TestClient(app)

def test_api_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "live_metrics" in data

def test_api_authentication_required(client):
    # Reject request without token
    res = client.post("/api/events", json=[])
    assert res.status_code == 401
    
    # Reject request with invalid token
    res_bad = client.post("/api/events", json=[], headers={"X-SOC-Agent-Token": "wrong-token"})
    assert res_bad.status_code == 401

def test_api_heartbeat_and_agents_list(client):
    headers = {"X-SOC-Agent-Token": "soc-secure-agent-token-2026"}
    hb_payload = {
        "agent_id": "api-test-agent",
        "hostname": "TEST-HOST-API",
        "ip_address": "192.168.10.50",
        "os_type": "Windows 11",
        "agent_version": "2.0.0"
    }
    res = client.post("/api/heartbeat", json=hb_payload, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # Query agents list
    res_agents = client.get("/api/agents", headers=headers)
    assert res_agents.status_code == 200
    agents = res_agents.json()["agents"]
    matching = [a for a in agents if a["agent_id"] == "api-test-agent"]
    assert len(matching) == 1
    assert matching[0]["hostname"] == "TEST-HOST-API"

def test_api_event_ingestion_and_alert_trigger(client):
    headers = {"X-SOC-Agent-Token": "soc-secure-agent-token-2026"}
    
    # Send 4 failed logins for same user to trigger targeted brute force
    batch = []
    for i in range(4):
        batch.append({
            "agent_id": "api-bf-agent",
            "hostname": "BF-HOST",
            "event_type": "FAILED_LOGIN",
            "windows_event_id": 4625,
            "username": "victim_account",
            "source_ip": "10.50.50.50",
            "description": f"Failed attempt {i}"
        })

    res = client.post("/api/events", json=batch, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["received"] == 4
    assert data["ingested"] == 4
    assert data["alerts_triggered"] >= 1
