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

# Initialize on module load
init_db()
