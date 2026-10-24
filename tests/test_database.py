"""
Tests for SQLite Database Persistence (modules/database.py)
"""

import uuid
import pytest
from modules.database import (
    init_db,
    save_analysis_run,
    save_incidents,
    get_recent_incidents,
    get_incident_by_id,
    update_incident_status,
    save_investigation_report,
    get_investigation_report
)

def test_database_lifecycle():
    init_db()
    test_run_id = f"RUN-TEST-{uuid.uuid4().hex[:6]}"
    
    # 1. Save Run
    run_saved = save_analysis_run(
        run_id=test_run_id,
        filename="test_traffic.csv",
        total_records=100,
        suspicious_records=5,
        model_version="1.0.0",
        summary_dict={"test": True}
    )
    assert run_saved is True
    
    # 2. Save Incident
    test_inc_id = f"INC-TEST-{uuid.uuid4().hex[:6]}"
    inc_data = [{
        "incident_id": test_inc_id,
        "run_id": test_run_id,
        "threat_category": "DDoS",
        "event_count": 5,
        "max_risk_score": 85.0,
        "avg_confidence": 0.98,
        "severity": "Critical",
        "status": "New",
        "mitre_technique_id": "T1498",
        "mitre_technique_name": "Network Denial of Service",
        "evidence_summary": "High packet volume test"
    }]
    assert save_incidents(inc_data) is True
    
    # 3. Retrieve Incident
    inc = get_incident_by_id(test_inc_id)
    assert inc is not None
    assert inc["threat_category"] == "DDoS"
    assert inc["status"] == "New"
    
    # 4. Update Status
    updated = update_incident_status(test_inc_id, "Under Review")
    assert updated is True
    inc_after = get_incident_by_id(test_inc_id)
    assert inc_after["status"] == "Under Review"
    
    # 5. Save and Retrieve AI Report
    rep_saved = save_investigation_report(
        report_id=f"REP-{uuid.uuid4().hex[:4]}",
        incident_id=test_inc_id,
        ai_summary="Test Executive Summary",
        threat_implications="Availability loss",
        investigation_steps="Check ingress flow logs",
        defensive_actions="Rate limit IP subnet"
    )
    assert rep_saved is True
    rep = get_investigation_report(test_inc_id)
    assert rep is not None
    assert "Test Executive Summary" in rep["ai_summary"]
