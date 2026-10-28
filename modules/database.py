"""
AI SOC Assistant - SQLite Database Module
Manages analysis runs, individual events, grouped incidents, analyst status updates,
and AI investigation reports with parameterized, thread-safe queries.
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from config.settings import DATABASE_PATH

def get_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory enabled."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DATABASE_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes database tables if they do not exist."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_runs (
        run_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        filename TEXT NOT NULL,
        total_records INTEGER NOT NULL,
        suspicious_records INTEGER NOT NULL,
        model_version TEXT NOT NULL,
        summary_json TEXT
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        threat_category TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        max_risk_score REAL NOT NULL,
        avg_confidence REAL NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'New',
        mitre_technique_id TEXT,
        mitre_technique_name TEXT,
        evidence_summary TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(run_id) REFERENCES analysis_runs(run_id)
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detected_events (
        event_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        incident_id TEXT,
        predicted_class TEXT NOT NULL,
        confidence REAL NOT NULL,
        risk_score REAL NOT NULL,
        severity TEXT NOT NULL,
        evidence_summary TEXT,
        raw_features_json TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY(run_id) REFERENCES analysis_runs(run_id),
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigation_reports (
        report_id TEXT PRIMARY KEY,
        incident_id TEXT UNIQUE NOT NULL,
        ai_summary TEXT NOT NULL,
        threat_implications TEXT NOT NULL,
        investigation_steps TEXT NOT NULL,
        defensive_actions TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
    );
    """)
    
    # Near-Real-Time Log Monitoring: Monitored Agents
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS monitored_agents (
        agent_id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        ip_address TEXT,
        os_type TEXT,
        status TEXT DEFAULT 'active',
        registered_at TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        total_events INTEGER DEFAULT 0,
        agent_version TEXT DEFAULT '1.0.0'
    );
    """)

    # Near-Real-Time Log Monitoring: Security Events
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        event_id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        windows_event_id INTEGER,
        username TEXT,
        source_ip TEXT,
        logon_type TEXT,
        description TEXT,
        raw_json TEXT,
        ingested_at TEXT NOT NULL,
        FOREIGN KEY(agent_id) REFERENCES monitored_agents(agent_id)
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_agent ON security_events(agent_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_type ON security_events(event_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sec_events_time ON security_events(timestamp);")

    # Near-Real-Time Log Monitoring: Live Threat Alerts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS live_alerts (
        alert_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score REAL NOT NULL,
        agent_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        username TEXT,
        source_ip TEXT,
        event_count INTEGER NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        status TEXT DEFAULT 'New',
        mitre_technique_id TEXT,
        mitre_technique_name TEXT,
        evidence_summary TEXT,
        incident_id TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(agent_id) REFERENCES monitored_agents(agent_id),
        FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_live_alerts_agent ON live_alerts(agent_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_live_alerts_severity ON live_alerts(severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_live_alerts_status ON live_alerts(status);")

    conn.commit()
    conn.close()

def save_analysis_run(
    run_id: str,
    filename: str,
    total_records: int,
    suspicious_records: int,
    model_version: str,
    summary_dict: Dict[str, Any]
) -> bool:
    """Records a new analysis run in the database."""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    try:
        cursor.execute("""
        INSERT INTO analysis_runs (run_id, timestamp, filename, total_records, suspicious_records, model_version, summary_json)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (run_id, now, filename, total_records, suspicious_records, model_version, json.dumps(summary_dict)))
        conn.commit()
        return True
    except Exception as e:
        print(f"[-] DB Error saving analysis run: {e}")
        return False
    finally:
        conn.close()

def save_incidents(incidents_list: List[Dict[str, Any]]) -> bool:
    """Inserts a batch of grouped security incidents."""
    if not incidents_list:
        return True
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    try:
        for inc in incidents_list:
            cursor.execute("""
            INSERT OR REPLACE INTO incidents (
                incident_id, run_id, threat_category, event_count, max_risk_score,
                avg_confidence, severity, status, mitre_technique_id, mitre_technique_name,
                evidence_summary, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                inc["incident_id"],
                inc["run_id"],
                inc["threat_category"],
                inc["event_count"],
                inc["max_risk_score"],
                inc["avg_confidence"],
                inc["severity"],
                inc.get("status", "New"),
                inc.get("mitre_technique_id", "T1498"),
                inc.get("mitre_technique_name", "Network Denial of Service"),
                inc.get("evidence_summary", "Network flow pattern detected"),
                now,
                now
            ))
        conn.commit()
        return True
    except Exception as e:
        print(f"[-] DB Error saving incidents: {e}")
        return False
    finally:
        conn.close()

def get_recent_incidents(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetches the most recent incidents from the database."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?;
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"[-] DB Error fetching incidents: {e}")
        return []
    finally:
        conn.close()

def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single incident by its unique ID."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM incidents WHERE incident_id = ?;", (incident_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def update_incident_status(incident_id: str, new_status: str) -> bool:
    """Updates the triage status of an incident (New, Under Review, Resolved, False Positive)."""
    valid_statuses = ["New", "Under Review", "Resolved", "False Positive"]
    if new_status not in valid_statuses:
        raise ValueError(f"Invalid status: {new_status}. Must be one of {valid_statuses}")
        
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    try:
        cursor.execute("""
        UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?;
        """, (new_status, now, incident_id))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()

def save_investigation_report(
    report_id: str,
    incident_id: str,
    ai_summary: str,
    threat_implications: str,
    investigation_steps: str,
    defensive_actions: str
) -> bool:
    """Stores an AI-generated investigation advisory report."""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    try:
        cursor.execute("""
        INSERT OR REPLACE INTO investigation_reports (
            report_id, incident_id, ai_summary, threat_implications,
            investigation_steps, defensive_actions, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (report_id, incident_id, ai_summary, threat_implications, investigation_steps, defensive_actions, now))
        conn.commit()
        return True
    finally:
        conn.close()

def get_investigation_report(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves the AI investigation report for a given incident."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM investigation_reports WHERE incident_id = ?;", (incident_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def get_db_metrics() -> Dict[str, int]:
    """Returns aggregated high-level metrics for dashboard cards."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    metrics = {
        "total_runs": 0,
        "total_incidents": 0,
        "high_risk_incidents": 0,
        "active_incidents": 0,
        "resolved_incidents": 0
    }
    try:
        cursor.execute("SELECT COUNT(*) FROM analysis_runs;")
        metrics["total_runs"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents;")
        metrics["total_incidents"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE severity IN ('High', 'Critical');")
        metrics["high_risk_incidents"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status IN ('New', 'Under Review');")
        metrics["active_incidents"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'Resolved';")
        metrics["resolved_incidents"] = cursor.fetchone()[0]
    except Exception as e:
        print(f"[-] DB Metrics error: {e}")
    finally:
        conn.close()
    return metrics

# ==============================================================================
# NEAR-REAL-TIME SECURITY LOG MONITORING EXTENSIONS
# ==============================================================================

def register_or_update_agent(
    agent_id: str,
    hostname: str,
    ip_address: Optional[str] = None,
    os_type: Optional[str] = None,
    agent_version: str = "1.0.0"
) -> bool:
    """Registers a new monitoring agent or updates its metadata & heartbeat."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    try:
        cursor.execute("""
        INSERT INTO monitored_agents (agent_id, hostname, ip_address, os_type, status, registered_at, last_seen, agent_version)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
            hostname = excluded.hostname,
            ip_address = COALESCE(excluded.ip_address, monitored_agents.ip_address),
            os_type = COALESCE(excluded.os_type, monitored_agents.os_type),
            status = 'active',
            last_seen = excluded.last_seen,
            agent_version = excluded.agent_version;
        """, (agent_id, hostname, ip_address, os_type, now, now, agent_version))
        conn.commit()
        return True
    except Exception as e:
        print(f"[-] DB Error registering agent: {e}")
        return False
    finally:
        conn.close()

def update_agent_heartbeat(agent_id: str) -> bool:
    """Updates the last_seen timestamp for an authenticated agent heartbeat."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    try:
        cursor.execute("""
        UPDATE monitored_agents SET last_seen = ?, status = 'active' WHERE agent_id = ?;
        """, (now, agent_id))
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"[-] DB Error updating heartbeat: {e}")
        return False
    finally:
        conn.close()

def get_monitored_agents() -> List[Dict[str, Any]]:
    """Retrieves all registered monitoring agents with status determination."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        SELECT * FROM monitored_agents ORDER BY last_seen DESC;
        """)
        rows = cursor.fetchall()
        agents = []
        now = datetime.now()
        for r in rows:
            d = dict(r)
            # Evaluate active vs inactive (inactive if no heartbeat in 10 minutes)
            try:
                last_dt = datetime.fromisoformat(d["last_seen"])
                diff_sec = (now - last_dt).total_seconds()
                d["is_online"] = diff_sec < 600
                d["status"] = "Active" if diff_sec < 600 else "Inactive"
            except Exception:
                d["is_online"] = False
                d["status"] = "Unknown"
            agents.append(d)
        return agents
    except Exception as e:
        print(f"[-] DB Error fetching agents: {e}")
        return []
    finally:
        conn.close()

def get_agent_by_id(agent_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single agent by ID."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM monitored_agents WHERE agent_id = ?;", (agent_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def save_security_events_batch(events_list: List[Dict[str, Any]]) -> int:
    """
    Inserts a batch of normalized security events into the database.
    Silently ignores duplicates based on event_id.
    Returns the number of newly inserted events.
    """
    if not events_list:
        return 0
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    inserted_count = 0
    agent_counts: Dict[str, int] = {}
    
    try:
        for evt in events_list:
            raw_meta = evt.get("metadata", {})
            raw_json = json.dumps(raw_meta) if isinstance(raw_meta, (dict, list)) else str(raw_meta)
            
            cursor.execute("""
            INSERT OR IGNORE INTO security_events (
                event_id, agent_id, hostname, timestamp, event_type,
                windows_event_id, username, source_ip, logon_type,
                description, raw_json, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                evt["event_id"],
                evt["agent_id"],
                evt["hostname"],
                evt["timestamp"],
                evt["event_type"],
                evt.get("windows_event_id"),
                evt.get("username"),
                evt.get("source_ip"),
                evt.get("logon_type"),
                evt.get("description", ""),
                raw_json,
                now
            ))
            if cursor.rowcount > 0:
                inserted_count += 1
                aid = evt["agent_id"]
                agent_counts[aid] = agent_counts.get(aid, 0) + 1

        # Increment total_events for affected agents
        for aid, cnt in agent_counts.items():
            cursor.execute("""
            UPDATE monitored_agents 
            SET total_events = total_events + ?, last_seen = ?
            WHERE agent_id = ?;
            """, (cnt, now, aid))
            
        conn.commit()
        return inserted_count
    except Exception as e:
        print(f"[-] DB Error saving security events batch: {e}")
        return 0
    finally:
        conn.close()

def save_live_alert(alert: Dict[str, Any]) -> bool:
    """Inserts or updates a live threat alert."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    try:
        cursor.execute("""
        INSERT INTO live_alerts (
            alert_id, rule_id, rule_name, severity, risk_score,
            agent_id, hostname, username, source_ip, event_count,
            first_seen, last_seen, status, mitre_technique_id,
            mitre_technique_name, evidence_summary, incident_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(alert_id) DO UPDATE SET
            event_count = excluded.event_count,
            last_seen = excluded.last_seen,
            risk_score = excluded.risk_score,
            severity = excluded.severity,
            evidence_summary = excluded.evidence_summary;
        """, (
            alert["alert_id"],
            alert["rule_id"],
            alert["rule_name"],
            alert["severity"],
            alert["risk_score"],
            alert["agent_id"],
            alert["hostname"],
            alert.get("username"),
            alert.get("source_ip"),
            alert.get("event_count", 1),
            alert.get("first_seen", now),
            alert.get("last_seen", now),
            alert.get("status", "New"),
            alert.get("mitre_technique_id", "T1110"),
            alert.get("mitre_technique_name", "Brute Force"),
            alert.get("evidence_summary", ""),
            alert.get("incident_id"),
            alert.get("created_at", now)
        ))
        conn.commit()
        return True
    except Exception as e:
        print(f"[-] DB Error saving live alert: {e}")
        return False
    finally:
        conn.close()

def get_live_alerts(
    limit: int = 50,
    status: Optional[str] = None,
    severity: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieves live threat alerts ordered by recency."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT * FROM live_alerts WHERE 1=1"
        params: List[Any] = []
        if status and status != "All":
            query += " AND status = ?"
            params.append(status)
        if severity and severity != "All":
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[-] DB Error fetching live alerts: {e}")
        return []
    finally:
        conn.close()

def get_live_alert_by_id(alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single live alert by ID."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM live_alerts WHERE alert_id = ?;", (alert_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def update_live_alert_status(alert_id: str, new_status: str) -> bool:
    """Updates status for a live alert (New, Investigating, Resolved, False Positive)."""
    valid = ["New", "Investigating", "Resolved", "False Positive"]
    if new_status not in valid:
        raise ValueError(f"Invalid alert status: {new_status}")
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE live_alerts SET status = ? WHERE alert_id = ?;", (new_status, alert_id))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()

def get_recent_security_events(
    limit: int = 100,
    event_type: Optional[str] = None,
    agent_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Fetches the latest ingested security events."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    try:
        query = "SELECT * FROM security_events WHERE 1=1"
        params: List[Any] = []
        if event_type and event_type != "All":
            query += " AND event_type = ?"
            params.append(event_type)
        if agent_id and agent_id != "All":
            query += " AND agent_id = ?"
            params.append(agent_id)
        query += " ORDER BY timestamp DESC LIMIT ?;"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[-] DB Error fetching security events: {e}")
        return []
    finally:
        conn.close()

def get_live_monitoring_metrics() -> Dict[str, Any]:
    """Returns aggregated live monitoring telemetry for dashboards."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    metrics = {
        "total_agents": 0,
        "active_agents": 0,
        "total_events": 0,
        "failed_logins": 0,
        "active_alerts": 0,
        "critical_alerts": 0,
        "last_event_time": None
    }
    try:
        cursor.execute("SELECT COUNT(*) FROM monitored_agents;")
        metrics["total_agents"] = cursor.fetchone()[0]
        
        # Agents seen in last 10 minutes
        ten_mins_ago = (datetime.now().timestamp() - 600)
        # SQLite string comparison for ISO timestamps works well if formatted identically
        cursor.execute("SELECT COUNT(*) FROM monitored_agents WHERE status = 'active';")
        metrics["active_agents"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM security_events;")
        metrics["total_events"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM security_events WHERE event_type = 'FAILED_LOGIN';")
        metrics["failed_logins"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM live_alerts WHERE status IN ('New', 'Investigating');")
        metrics["active_alerts"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM live_alerts WHERE severity IN ('High', 'Critical');")
        metrics["critical_alerts"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT timestamp FROM security_events ORDER BY timestamp DESC LIMIT 1;")
        row = cursor.fetchone()
        if row:
            metrics["last_event_time"] = row[0]
    except Exception as e:
        print(f"[-] Live Metrics error: {e}")
    finally:
        conn.close()
    return metrics

def convert_alert_to_incident(alert_id: str) -> Optional[str]:
    """
    Promotes a live threat alert to a central security incident record,
    enabling full Gemini AI investigation and RAG knowledge retrieval.
    Returns the created incident_id.
    """
    alert = get_live_alert_by_id(alert_id)
    if not alert:
        return None
        
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    incident_id = f"INC-LIVE-{alert['alert_id'][:8]}"
    
    try:
        # Create a synthetic analysis run if not exists for live monitor
        live_run_id = f"RUN-LIVE-MONITOR"
        cursor.execute("""
        INSERT OR IGNORE INTO analysis_runs (run_id, timestamp, filename, total_records, suspicious_records, model_version, summary_json)
        VALUES (?, ?, 'Live_Host_Security_Events', 1, 1, 'Live-Rule-Engine-1.0', '{}');
        """, (live_run_id, now))
        
        # Insert into incidents
        cursor.execute("""
        INSERT OR REPLACE INTO incidents (
            incident_id, run_id, threat_category, event_count, max_risk_score,
            avg_confidence, severity, status, mitre_technique_id, mitre_technique_name,
            evidence_summary, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            incident_id,
            live_run_id,
            alert["rule_name"],
            alert["event_count"],
            alert["risk_score"],
            0.95, # High rule confidence
            alert["severity"],
            "New",
            alert.get("mitre_technique_id", "T1110"),
            alert.get("mitre_technique_name", "Brute Force"),
            alert["evidence_summary"],
            now,
            now
        ))
        
        # Link back to live alert
        cursor.execute("UPDATE live_alerts SET incident_id = ? WHERE alert_id = ?;", (incident_id, alert_id))
        conn.commit()
        return incident_id
    except Exception as e:
        print(f"[-] Error converting alert to incident: {e}")
        return None
    finally:
        conn.close()

# Initialize on module load
init_db()
