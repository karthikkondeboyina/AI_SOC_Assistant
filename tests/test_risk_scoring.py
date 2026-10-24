"""
Tests for Risk Scoring Module (modules/risk_scoring.py)
"""

import pytest
from modules.risk_scoring import calculate_risk_score, get_severity_label

def test_benign_traffic_risk():
    res = calculate_risk_score(predicted_class="Benign", confidence=0.99)
    assert res["risk_score"] == 0.0
    assert res["severity"] == "Benign"

def test_high_severity_ddos_risk():
    res = calculate_risk_score(
        predicted_class="DDoS",
        confidence=0.95,
        flow_features={"Total Fwd Packets": 5000, "Flow Bytes/s": 2000000},
        asset_criticality="High"
    )
    assert res["risk_score"] >= 80.0
    assert res["severity"] in ["High", "Critical"]
    assert "explanation" in res

def test_boundary_clamping():
    # Verify that scores are strictly within [0, 100]
    res_max = calculate_risk_score(
        predicted_class="Infiltration",
        confidence=1.0,
        flow_features={"Total Fwd Packets": 100000},
        asset_criticality="Mission-Critical"
    )
    assert 0.0 <= res_max["risk_score"] <= 100.0

def test_severity_tiers():
    assert get_severity_label(95) == "Critical"
    assert get_severity_label(75) == "High"
    assert get_severity_label(55) == "Medium"
    assert get_severity_label(30) == "Low"
    assert get_severity_label(10) == "Informational"
