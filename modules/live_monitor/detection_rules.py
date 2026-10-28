"""
AI SOC Assistant - Live Threat Detection Engine
Stateful sliding-window rule-based detection engine for streaming security events.
Evaluates brute force patterns, password spraying, account lockouts, and privileged anomalies.
Includes alert cooldowns, state purging, and explainable risk scoring.
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import uuid

from config.settings import (
    LIVE_FAILED_LOGIN_HOST_THRESHOLD,
    LIVE_FAILED_LOGIN_USER_THRESHOLD,
    LIVE_PASSWORD_SPRAY_USER_THRESHOLD,
    LIVE_DETECTION_WINDOW_MINUTES,
    LIVE_ALERT_COOLDOWN_MINUTES
)
from modules.live_monitor.event_schema import SecurityEvent, SecurityEventType

PRIVILEGED_ACCOUNTS = {
    "administrator", "admin", "root", "system", "sa", "oracle", "postgres",
    "domain admin", "enterprise admin", "svc-", "service", "dbadmin"
}

class DetectionRuleAlert:
    """Represents a generated security alert from the live detection engine."""
    def __init__(
        self,
        alert_id: str,
        rule_id: str,
        rule_name: str,
        severity: str,
        risk_score: float,
        agent_id: str,
        hostname: str,
        username: Optional[str],
        source_ip: Optional[str],
        event_count: int,
        first_seen: str,
        last_seen: str,
        mitre_technique_id: str,
        mitre_technique_name: str,
        evidence_summary: str,
        risk_rationale: str
    ):
        self.alert_id = alert_id
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.risk_score = risk_score
        self.agent_id = agent_id
        self.hostname = hostname
        self.username = username
        self.source_ip = source_ip
        self.event_count = event_count
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.mitre_technique_id = mitre_technique_id
        self.mitre_technique_name = mitre_technique_name
        self.evidence_summary = evidence_summary
        self.risk_rationale = risk_rationale

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "username": self.username,
            "source_ip": self.source_ip,
            "event_count": self.event_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": "New",
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "evidence_summary": self.evidence_summary,
            "risk_rationale": self.risk_rationale,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

class LiveDetectionEngine:
    """
    Sliding-window stateful security detection engine.
    Maintains rolling queues of recent authentication failures per host, user, and source IP.
    """
    def __init__(
        self,
        window_minutes: int = LIVE_DETECTION_WINDOW_MINUTES,
        cooldown_minutes: int = LIVE_ALERT_COOLDOWN_MINUTES
    ):
        self.window = timedelta(minutes=window_minutes)
        self.cooldown = timedelta(minutes=cooldown_minutes)
        
        # In-memory sliding windows: key -> deque of (datetime, SecurityEvent)
        self.host_failures: Dict[str, deque] = defaultdict(deque)
        self.user_failures: Dict[Tuple[str, str], deque] = defaultdict(deque) # (agent_id, username)
        self.ip_user_attempts: Dict[Tuple[str, str], deque] = defaultdict(deque) # (agent_id, source_ip)
        
        # Alert cooldown tracking: deduplication_key -> (alert_id, last_alert_time, event_count)
        self.active_alerts: Dict[str, Dict[str, Any]] = {}

    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parses UTC ISO timestamp with timezone awareness."""
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.now(timezone.utc)

    def _purge_expired(self, current_time: datetime):
        """Removes entries older than the sliding window."""
        cutoff = current_time - self.window
        
        for k in list(self.host_failures.keys()):
            q = self.host_failures[k]
            while q and q[0][0] < cutoff:
                q.popleft()
            if not q:
                del self.host_failures[k]
                
        for k in list(self.user_failures.keys()):
            q = self.user_failures[k]
            while q and q[0][0] < cutoff:
                q.popleft()
            if not q:
                del self.user_failures[k]
                
        for k in list(self.ip_user_attempts.keys()):
            q = self.ip_user_attempts[k]
            while q and q[0][0] < cutoff:
                q.popleft()
            if not q:
                del self.ip_user_attempts[k]

    def _compute_risk_score(
        self,
        base_score: float,
        event_count: int,
        threshold: int,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        is_lockout: bool = False
    ) -> Tuple[float, str, str]:
        """
        Calculates an explainable risk score (1-100) and severity rating.
        Returns: (score, severity, rationale)
        """
        score = base_score
        reasons = [f"Base rule severity: {base_score:.0f} pts"]
        
        # Volume escalation
        excess = event_count - threshold
        if excess > 0:
            volume_bonus = min(15.0, (excess // 2) * 2.5)
            score += volume_bonus
            reasons.append(f"High failure density ({event_count} attempts): +{volume_bonus:.0f} pts")
            
        # Target criticality
        u_lower = (username or "").lower()
        if any(priv in u_lower for priv in PRIVILEGED_ACCOUNTS):
            score += 15.0
            reasons.append(f"Target is privileged/administrative account ('{username}'): +15 pts")
            
        # Account lockout escalation
        if is_lockout:
            score += 10.0
            reasons.append("Account lockout triggered: +10 pts")
            
        # External source IP presence
        if source_ip and not (source_ip.startswith("10.") or source_ip.startswith("192.168.") or source_ip.startswith("172.")):
            score += 10.0
            reasons.append(f"Source IP is non-private/external ('{source_ip}'): +10 pts")
            
        # Clamp strictly between 1 and 100
        final_score = min(100.0, max(1.0, round(score, 1)))
        
        if final_score >= 85:
            severity = "Critical"
        elif final_score >= 70:
            severity = "High"
        elif final_score >= 45:
            severity = "Medium"
        else:
            severity = "Low"
            
        rationale = " | ".join(reasons)
        return final_score, severity, rationale

    def process_event(self, event: SecurityEvent) -> List[DetectionRuleAlert]:
        """
        Ingests a single normalized event into the sliding window and evaluates detection rules.
        Returns a list of any newly triggered or updated alerts.
        """
        ev_dt = self._parse_timestamp(event.timestamp)
        self._purge_expired(ev_dt)
        alerts: List[DetectionRuleAlert] = []
        
        # ----------------------------------------------------------------------
        # RULE 4: Account Lockout (Immediate Event ID 4740 or ACCOUNT_LOCKOUT)
        # ----------------------------------------------------------------------
        if event.event_type == SecurityEventType.ACCOUNT_LOCKOUT or event.windows_event_id == 4740:
            dedup_key = f"RULE4:{event.agent_id}:{event.username or 'any'}"
            if not self._is_in_cooldown(dedup_key, ev_dt):
                risk_score, severity, rationale = self._compute_risk_score(
                    base_score=80.0,
                    event_count=1,
                    threshold=1,
                    username=event.username,
                    source_ip=event.source_ip,
                    is_lockout=True
                )
                alert = DetectionRuleAlert(
                    alert_id=f"ALT-LOCK-{uuid.uuid4().hex[:8].upper()}",
                    rule_id="RULE-04-LOCKOUT",
                    rule_name="Account Lockout Detected",
                    severity=severity,
                    risk_score=risk_score,
                    agent_id=event.agent_id,
                    hostname=event.hostname,
                    username=event.username,
                    source_ip=event.source_ip,
                    event_count=1,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    mitre_technique_id="T1110",
                    mitre_technique_name="Brute Force",
                    evidence_summary=f"Security Event 4740: User account '{event.username}' was locked out after repeated authorization failures on {event.hostname}.",
                    risk_rationale=rationale
                )
                self._record_alert(dedup_key, alert, ev_dt)
                alerts.append(alert)

        # Only evaluate authentication failure rules if event is FAILED_LOGIN or 4625
        if event.event_type == SecurityEventType.FAILED_LOGIN or event.windows_event_id == 4625:
            # Append to rolling windows
            self.host_failures[event.agent_id].append((ev_dt, event))
            
            user_key = (event.agent_id, event.username or "Unknown")
            self.user_failures[user_key].append((ev_dt, event))
            
            if event.source_ip:
                ip_key = (event.agent_id, event.source_ip)
                self.ip_user_attempts[ip_key].append((ev_dt, event))

            # ------------------------------------------------------------------
            # RULE 2: Multiple Failed Logins Targeting Single Account (Brute Force)
            # ------------------------------------------------------------------
            user_q = self.user_failures[user_key]
            if len(user_q) >= LIVE_FAILED_LOGIN_USER_THRESHOLD:
                dedup_key = f"RULE2:{event.agent_id}:{event.username}"
                if not self._is_in_cooldown(dedup_key, ev_dt):
                    cnt = len(user_q)
                    first_ts = user_q[0][1].timestamp
                    last_ts = user_q[-1][1].timestamp
                    risk_score, severity, rationale = self._compute_risk_score(
                        base_score=75.0,
                        event_count=cnt,
                        threshold=LIVE_FAILED_LOGIN_USER_THRESHOLD,
                        username=event.username,
                        source_ip=event.source_ip
                    )
                    alert = DetectionRuleAlert(
                        alert_id=f"ALT-BFUSER-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="RULE-02-TARGETED-BRUTEFORCE",
                        rule_name="Targeted Account Brute-Force",
                        severity=severity,
                        risk_score=risk_score,
                        agent_id=event.agent_id,
                        hostname=event.hostname,
                        username=event.username,
                        source_ip=event.source_ip,
                        event_count=cnt,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        mitre_technique_id="T1110.001",
                        mitre_technique_name="Brute Force: Password Guessing",
                        evidence_summary=f"Detected {cnt} consecutive failed logins targeting account '{event.username}' on {event.hostname} within {LIVE_DETECTION_WINDOW_MINUTES}m.",
                        risk_rationale=rationale
                    )
                    self._record_alert(dedup_key, alert, ev_dt)
                    alerts.append(alert)

            # ------------------------------------------------------------------
            # RULE 3: Password Spraying (Single IP targeting multiple accounts)
            # ------------------------------------------------------------------
            if event.source_ip:
                ip_q = self.ip_user_attempts[(event.agent_id, event.source_ip)]
                targeted_users = {e[1].username for e in ip_q if e[1].username and e[1].username != "Unknown"}
                if len(targeted_users) >= LIVE_PASSWORD_SPRAY_USER_THRESHOLD:
                    dedup_key = f"RULE3:{event.agent_id}:{event.source_ip}"
                    if not self._is_in_cooldown(dedup_key, ev_dt):
                        cnt = len(ip_q)
                        first_ts = ip_q[0][1].timestamp
                        last_ts = ip_q[-1][1].timestamp
                        risk_score, severity, rationale = self._compute_risk_score(
                            base_score=85.0,
                            event_count=cnt,
                            threshold=LIVE_PASSWORD_SPRAY_USER_THRESHOLD,
                            username="Multiple",
                            source_ip=event.source_ip
                        )
                        u_list = ", ".join(list(targeted_users)[:5])
                        alert = DetectionRuleAlert(
                            alert_id=f"ALT-SPRAY-{uuid.uuid4().hex[:8].upper()}",
                            rule_id="RULE-03-PASSWORD-SPRAYING",
                            rule_name="Password Spraying Attack",
                            severity=severity,
                            risk_score=risk_score,
                            agent_id=event.agent_id,
                            hostname=event.hostname,
                            username=f"{len(targeted_users)} accounts ({u_list})",
                            source_ip=event.source_ip,
                            event_count=cnt,
                            first_seen=first_ts,
                            last_seen=last_ts,
                            mitre_technique_id="T1110.003",
                            mitre_technique_name="Brute Force: Password Spraying",
                            evidence_summary=f"Source IP {event.source_ip} attempted authentication across {len(targeted_users)} distinct accounts ({u_list}) on {event.hostname}.",
                            risk_rationale=rationale
                        )
                        self._record_alert(dedup_key, alert, ev_dt)
                        alerts.append(alert)

            # ------------------------------------------------------------------
            # RULE 1: Repeated Failed Logins Across Host
            # ------------------------------------------------------------------
            host_q = self.host_failures[event.agent_id]
            if len(host_q) >= LIVE_FAILED_LOGIN_HOST_THRESHOLD:
                dedup_key = f"RULE1:{event.agent_id}:host"
                if not self._is_in_cooldown(dedup_key, ev_dt):
                    cnt = len(host_q)
                    first_ts = host_q[0][1].timestamp
                    last_ts = host_q[-1][1].timestamp
                    risk_score, severity, rationale = self._compute_risk_score(
                        base_score=65.0,
                        event_count=cnt,
                        threshold=LIVE_FAILED_LOGIN_HOST_THRESHOLD,
                        username=event.username,
                        source_ip=event.source_ip
                    )
                    alert = DetectionRuleAlert(
                        alert_id=f"ALT-HOSTFAIL-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="RULE-01-HOST-FAILED-LOGINS",
                        rule_name="Anomalous Host Failed Logins",
                        severity=severity,
                        risk_score=risk_score,
                        agent_id=event.agent_id,
                        hostname=event.hostname,
                        username=event.username,
                        source_ip=event.source_ip,
                        event_count=cnt,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        mitre_technique_id="T1110",
                        mitre_technique_name="Brute Force",
                        evidence_summary=f"Host {event.hostname} recorded {cnt} failed login attempts within {LIVE_DETECTION_WINDOW_MINUTES}m.",
                        risk_rationale=rationale
                    )
                    self._record_alert(dedup_key, alert, ev_dt)
                    alerts.append(alert)

            # ------------------------------------------------------------------
            # RULE 5: Suspicious Remote Interactive (RDP) Authentication Failure
            # ------------------------------------------------------------------
            logon_t = str(event.logon_type or "")
            if "10" in logon_t or "RemoteInteractive" in logon_t:
                dedup_key = f"RULE5:{event.agent_id}:{event.username or 'rdp'}"
                if not self._is_in_cooldown(dedup_key, ev_dt):
                    risk_score, severity, rationale = self._compute_risk_score(
                        base_score=70.0,
                        event_count=1,
                        threshold=1,
                        username=event.username,
                        source_ip=event.source_ip
                    )
                    alert = DetectionRuleAlert(
                        alert_id=f"ALT-RDP-{uuid.uuid4().hex[:8].upper()}",
                        rule_id="RULE-05-SUSPICIOUS-RDP-LOGON",
                        rule_name="Suspicious Remote Interactive (RDP) Failure",
                        severity=severity,
                        risk_score=risk_score,
                        agent_id=event.agent_id,
                        hostname=event.hostname,
                        username=event.username,
                        source_ip=event.source_ip,
                        event_count=1,
                        first_seen=event.timestamp,
                        last_seen=event.timestamp,
                        mitre_technique_id="T1078",
                        mitre_technique_name="Valid Accounts",
                        evidence_summary=f"Failed Remote Desktop (Logon Type 10) authentication for account '{event.username}' from source {event.source_ip or 'unknown'}.",
                        risk_rationale=rationale
                    )
                    self._record_alert(dedup_key, alert, ev_dt)
                    alerts.append(alert)

        return alerts

    def process_batch(self, events: List[SecurityEvent]) -> List[DetectionRuleAlert]:
        """Processes a list of normalized events chronologically."""
        # Sort by timestamp to ensure sliding window is ordered
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        all_alerts: List[DetectionRuleAlert] = []
        for ev in sorted_events:
            alerts = self.process_event(ev)
            all_alerts.extend(alerts)
        return all_alerts

    def _is_in_cooldown(self, key: str, current_time: datetime) -> bool:
        """Checks if an alert for this key was triggered within the cooldown interval."""
        if key not in self.active_alerts:
            return False
        last_dt = self.active_alerts[key]["time"]
        return (current_time - last_dt) < self.cooldown

    def _record_alert(self, key: str, alert: DetectionRuleAlert, current_time: datetime):
        """Records an alert to prevent flooding during ongoing attacks."""
        self.active_alerts[key] = {
            "alert_id": alert.alert_id,
            "time": current_time,
            "rule_id": alert.rule_id
        }

# Singleton instance of the live detection engine
_LIVE_ENGINE_INSTANCE: Optional[LiveDetectionEngine] = None

def get_live_detection_engine() -> LiveDetectionEngine:
    """Returns the global singleton LiveDetectionEngine instance."""
    global _LIVE_ENGINE_INSTANCE
    if _LIVE_ENGINE_INSTANCE is None:
        _LIVE_ENGINE_INSTANCE = LiveDetectionEngine()
    return _LIVE_ENGINE_INSTANCE
