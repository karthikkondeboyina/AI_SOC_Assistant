"""
AI SOC Assistant - Utility & Helper Functions
Provides formatting, badge renderers, text sanitization, and data export helpers.
"""

import re
import html
from typing import Any, Dict

def format_number(val: Any) -> str:
    """Format integer or float into readable human string."""
    try:
        num = float(val)
        if num.is_integer():
            return f"{int(num):,}"
        return f"{num:,.2f}"
    except (ValueError, TypeError):
        return str(val)

def format_bytes(size_bytes: int) -> str:
    """Format bytes into KB, MB, GB."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    else:
        return f"{size_bytes / (1024 ** 3):.2f} GB"

def get_severity_badge_html(severity: str) -> str:
    """Return colored HTML badge corresponding to severity tier."""
    sev = str(severity).lower()
    if sev == "critical":
        css_class = "badge-critical"
    elif sev == "high":
        css_class = "badge-high"
    elif sev == "medium":
        css_class = "badge-medium"
    elif sev == "low":
        css_class = "badge-low"
    else:
        css_class = "badge-benign"
    
    clean_text = html.escape(str(severity).upper())
    return f'<span class="{css_class}">{clean_text}</span>'

def sanitize_for_llm(data: Any, max_len: int = 500) -> str:
    """
    Sanitize text input to protect LLM from prompt injection embedded in network logs.
    Replaces control characters, backticks, and limits string length.
    """
    if data is None:
        return "N/A"
    text = str(data)
    # Strip dangerous characters and excessive whitespace
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    text = text.replace("```", "'''")
    # Truncate to reasonable length
    if len(text) > max_len:
        text = text[:max_len] + "... [truncated]"
    return text.strip()

def summarize_flow_evidence(row: Dict[str, Any]) -> str:
    """Extract key network-flow evidence into a concise, readable summary string."""
    evidence_parts = []
    
    proto = row.get("Protocol") or row.get("protocol")
    if proto is not None:
        evidence_parts.append(f"Protocol: {proto}")
        
    duration = row.get("Flow Duration") or row.get("flow_duration")
    if duration is not None:
        evidence_parts.append(f"Duration: {format_number(duration)} us")
        
    fwd_pkts = row.get("Total Fwd Packets") or row.get("total_fwd_packets")
    bwd_pkts = row.get("Total Backward Packets") or row.get("total_backward_packets")
    if fwd_pkts is not None or bwd_pkts is not None:
        evidence_parts.append(f"Packets (Fwd/Bwd): {fwd_pkts or 0}/{bwd_pkts or 0}")
        
    flow_bytes_s = row.get("Flow Bytes/s") or row.get("flow_bytes/s")
    if flow_bytes_s is not None:
        evidence_parts.append(f"Flow Rate: {format_number(flow_bytes_s)} B/s")
        
    return "; ".join(evidence_parts) if evidence_parts else "Network flow metrics recorded"
