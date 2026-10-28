"""
Tests for Live Detection Engine & Sliding Window Rules (modules/live_monitor/detection_rules.py)
"""

import pytest
from datetime import datetime, timezone, timedelta
from modules.live_monitor.detection_rules import LiveDetectionEngine
from modules.live_monitor.event_schema import SecurityEvent, SecurityEventType

def test_rule1_host_failed_logins():
    engine = LiveDetectionEngine(window_minutes=5, cooldown_minutes=5)
    alerts = []
    
    # Send 5 failed logins for different users on same host
    for i in range(5):
        ev = SecurityEvent(
            agent_id="host-1",
            hostname="PC-1",
            event_type=SecurityEventType.FAILED_LOGIN,
            windows_event_id=4625,
            username=f"user_{i}",
            source_ip=f"192.168.1.{i+10}"
        )
        alerts.extend(engine.process_event(ev))

    # At least Rule 1 should trigger
    rule_ids = [a.rule_id for a in alerts]
    assert "RULE-01-HOST-FAILED-LOGINS" in rule_ids

def test_rule2_targeted_user_bruteforce():
    engine = LiveDetectionEngine(window_minutes=5, cooldown_minutes=5)
    alerts = []
    
    # 3 failed logins for same user "target_user"
    for i in range(3):
        ev = SecurityEvent(
            agent_id="host-2",
            hostname="PC-2",
            event_type=SecurityEventType.FAILED_LOGIN,
            windows_event_id=4625,
            username="target_user",
            source_ip="10.1.1.5"
        )
        alerts.extend(engine.process_event(ev))

    rule_ids = [a.rule_id for a in alerts]
    assert "RULE-02-TARGETED-BRUTEFORCE" in rule_ids
    bf_alert = next(a for a in alerts if a.rule_id == "RULE-02-TARGETED-BRUTEFORCE")
    assert bf_alert.mitre_technique_id == "T1110.001"
    assert bf_alert.event_count >= 3
    assert bf_alert.risk_score >= 70

def test_rule3_password_spraying():
    engine = LiveDetectionEngine(window_minutes=5, cooldown_minutes=5)
    alerts = []
    
    # Single IP attacking 3 distinct usernames
    attack_ip = "198.51.100.99"
    for u in ["userA", "userB", "userC"]:
        ev = SecurityEvent(
            agent_id="host-3",
            hostname="PC-3",
            event_type=SecurityEventType.FAILED_LOGIN,
            windows_event_id=4625,
            username=u,
            source_ip=attack_ip
        )
        alerts.extend(engine.process_event(ev))

    rule_ids = [a.rule_id for a in alerts]
    assert "RULE-03-PASSWORD-SPRAYING" in rule_ids
    spray_alert = next(a for a in alerts if a.rule_id == "RULE-03-PASSWORD-SPRAYING")
    assert spray_alert.mitre_technique_id == "T1110.003"
    assert spray_alert.severity in ["High", "Critical"]

def test_rule4_account_lockout():
    engine = LiveDetectionEngine(window_minutes=5, cooldown_minutes=5)
    ev = SecurityEvent(
        agent_id="host-4",
        hostname="PC-4",
        event_type=SecurityEventType.ACCOUNT_LOCKOUT,
        windows_event_id=4740,
        username="locked_user"
    )
    alerts = engine.process_event(ev)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-04-LOCKOUT"
    assert alerts[0].mitre_technique_id == "T1110"
    assert alerts[0].risk_score >= 80

def test_rule5_suspicious_rdp():
    engine = LiveDetectionEngine(window_minutes=5, cooldown_minutes=5)
    ev = SecurityEvent(
        agent_id="host-5",
        hostname="PC-5",
        event_type=SecurityEventType.FAILED_LOGIN,
        windows_event_id=4625,
        username="administrator",
        source_ip="203.0.113.88",
        logon_type="10 - RemoteInteractive (RDP)"
    )
    alerts = engine.process_event(ev)
    rule_ids = [a.rule_id for a in alerts]
    assert "RULE-05-SUSPICIOUS-RDP-LOGON" in rule_ids

def test_alert_cooldown_deduplication():
    engine = LiveDetectionEngine(window_minutes=5, cooldown_minutes=10)
    alerts = []
    
    # 6 failed logins for same user in quick succession
    for i in range(6):
        ev = SecurityEvent(
            agent_id="host-6",
            hostname="PC-6",
            event_type=SecurityEventType.FAILED_LOGIN,
            windows_event_id=4625,
            username="admin_user",
            source_ip="10.2.2.2"
        )
        alerts.extend(engine.process_event(ev))

    # Targeted brute force rule should trigger only once despite 6 attempts due to cooldown
    rule2_alerts = [a for a in alerts if a.rule_id == "RULE-02-TARGETED-BRUTEFORCE"]
    assert len(rule2_alerts) == 1
