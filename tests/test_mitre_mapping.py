"""
Tests for MITRE ATT&CK Mapping (modules/mitre_mapping.py)
"""

import pytest
from modules.mitre_mapping import map_threat_to_mitre

def test_map_known_attacks():
    portscan = map_threat_to_mitre("Port Scan")
    assert portscan["mapped"] is True
    assert portscan["technique_id"] == "T1046"
    assert "https://attack.mitre.org/" in portscan["url"]

    ddos = map_threat_to_mitre("DDoS")
    assert ddos["mapped"] is True
    assert ddos["technique_id"] == "T1498"

    ssh_bf = map_threat_to_mitre("Brute Force (SSH)")
    assert ssh_bf["mapped"] is True
    assert ssh_bf["technique_id"] == "T1110"

def test_map_benign():
    benign = map_threat_to_mitre("Benign")
    assert benign["mapped"] is False
    assert benign["technique_id"] == "N/A"

def test_map_unclassified_fallback():
    unknown = map_threat_to_mitre("Random Unknown Attack")
    assert unknown["mapped"] is False
    assert "requires additional evidence" in unknown["technique_name"]
