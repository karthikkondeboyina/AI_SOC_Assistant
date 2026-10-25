"""
AI SOC Assistant - Incident Management Module
Aggregates and correlates individual suspicious network flow alerts into coherent
security incidents. Avoids false inflation where every packet flow is labeled an independent breach.
"""

from typing import List, Dict, Any
import uuid
import numpy as np
import pandas as pd
from utils.helpers import summarize_flow_evidence

def group_suspicious_flows_into_incidents(
    results_df: pd.DataFrame,
    run_id: str
) -> List[Dict[str, Any]]:
    """
    Groups individual suspicious flow records into security incidents.
    Grouping strategy:
    - Flows sharing the same attack category (e.g. 'DDoS', 'Port Scan', 'Brute Force (SSH)')
      belong to the same operational security incident for that capture run.
    - Aggregates event counts, determines maximum risk score, average confidence,
      and extracts representative flow evidence.
    """
    if "is_suspicious" not in results_df.columns:
        return []
        
    suspicious_df = results_df[results_df["is_suspicious"] == True]
    if suspicious_df.empty:
        return []
        
    incidents = []
    
    # Group by predicted attack category
    for category, group in suspicious_df.groupby("predicted_class"):
        incident_id = f"INC-{category.replace(' ', '-').replace('(', '').replace(')', '').upper()[:8]}-{uuid.uuid4().hex[:6].upper()}"
        
        event_count = len(group)
        max_risk = float(group["risk_score"].max()) if "risk_score" in group.columns else 70.0
        avg_conf = float(group["confidence"].mean()) if "confidence" in group.columns else 0.85
        
        # Max severity
        if max_risk >= 85:
            sev = "Critical"
        elif max_risk >= 70:
            sev = "High"
        elif max_risk >= 45:
            sev = "Medium"
        else:
            sev = "Low"
            
        # Extract sample evidence from the top risk flow in this group (O(N) instead of O(N log N) sort)
        top_idx = group["risk_score"].idxmax() if "risk_score" in group.columns else group.index[0]
        top_row = group.loc[top_idx].to_dict()
        evidence_summary = summarize_flow_evidence(top_row)
        
        incidents.append({
            "incident_id": incident_id,
            "run_id": run_id,
            "threat_category": category,
            "event_count": event_count,
            "max_risk_score": max_risk,
            "avg_confidence": round(avg_conf, 4),
            "severity": sev,
            "status": "New",
            "evidence_summary": f"Detected {event_count} correlated flow events. Representative: {evidence_summary}",
            "sample_row": top_row
        })
        
    return incidents
