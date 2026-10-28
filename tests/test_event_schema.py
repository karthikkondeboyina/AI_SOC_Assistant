"""
Tests for Normalized Security Event Schema (modules/live_monitor/event_schema.py)
"""

import pytest
from datetime import datetime, timezone
from modules.live_monitor.event_schema import (
    SecurityEvent,
    SecurityEventType,
    WINDOWS_EVENT_ID_MAP,
    generate_deterministic_event_id,
    normalize_security_event
)

def test_valid_security_event_creation():
    ev = SecurityEvent(
        agent_id="test-agent-01",
        hostname="WORKSTATION-1",
        event_type=SecurityEventType.FAILED_LOGIN,
        windows_event_id=4625,
        username="john.doe",
        source_ip="192.168.1.55",
        logon_type="2 - Interactive",
        description="Failed console authentication"
    )
    assert ev.agent_id == "test-agent-01"
    assert ev.hostname == "WORKSTATION-1"
    assert ev.event_type == SecurityEventType.FAILED_LOGIN
    assert ev.windows_event_id == 4625
    assert ev.username == "john.doe"
    assert ev.source_ip == "192.168.1.55"
    assert ev.event_id.startswith("EVT-")

def test_username_sanitization():
    # Domain prefix stripping
    ev1 = SecurityEvent(
        agent_id="a1", hostname="h1", event_type=SecurityEventType.FAILED_LOGIN,
        username="CORP\\admin"
    )
    assert ev1.username == "admin"

    # UPN suffix stripping
    ev2 = SecurityEvent(
        agent_id="a1", hostname="h1", event_type=SecurityEventType.FAILED_LOGIN,
        username="alice@corp.internal"
    )
    assert ev2.username == "alice"

    # Empty or null fallback
    ev3 = SecurityEvent(
        agent_id="a1", hostname="h1", event_type=SecurityEventType.FAILED_LOGIN,
        username="-"
    )
    assert ev3.username == "Unknown"

def test_source_ip_sanitization():
    # Loopback or dash normalized to None
    ev1 = SecurityEvent(
        agent_id="a1", hostname="h1", event_type=SecurityEventType.FAILED_LOGIN,
        source_ip="::1"
    )
    assert ev1.source_ip is None

    # Port stripping
    ev2 = SecurityEvent(
        agent_id="a1", hostname="h1", event_type=SecurityEventType.FAILED_LOGIN,
        source_ip="10.0.0.5:49152"
    )
    assert ev2.source_ip == "10.0.0.5"

def test_deterministic_event_id():
    id1 = generate_deterministic_event_id("agent-1", "2026-10-28T10:00:00Z", "4625", 1001)
    id2 = generate_deterministic_event_id("agent-1", "2026-10-28T10:00:00Z", "4625", 1001)
    id3 = generate_deterministic_event_id("agent-1", "2026-10-28T10:00:01Z", "4625", 1002)

    assert id1 == id2
    assert id1 != id3

def test_windows_event_id_mappings():
    assert WINDOWS_EVENT_ID_MAP[4624] == SecurityEventType.SUCCESSFUL_LOGIN
    assert WINDOWS_EVENT_ID_MAP[4625] == SecurityEventType.FAILED_LOGIN
    assert WINDOWS_EVENT_ID_MAP[4634] == SecurityEventType.LOGOFF
    assert WINDOWS_EVENT_ID_MAP[4740] == SecurityEventType.ACCOUNT_LOCKOUT
