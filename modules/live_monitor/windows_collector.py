"""
AI SOC Assistant - Windows Security Event Log Collector
Monitors local Windows Security Event Logs using pywin32 Windows Event Log APIs.
Collects and parses Event IDs 4624, 4625, 4634, and 4740 into normalized SecurityEvent objects.
Uses bookmarking to prevent duplicate ingestion across collector restarts.
Safely catches permission limitations and missing dependencies.
"""

from typing import List, Dict, Any, Optional, Tuple
import os
import sys
import platform
import json
from pathlib import Path
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

from config.settings import DATA_DIR
from modules.live_monitor.event_schema import (
    SecurityEvent,
    SecurityEventType,
    WINDOWS_EVENT_ID_MAP,
    LOGON_TYPES,
    generate_deterministic_event_id
)

BOOKMARK_FILE = DATA_DIR / "windows_collector_bookmark.json"

# Check pywin32 availability
HAS_WIN32 = False
try:
    if platform.system() == "Windows":
        import win32evtlog
        import win32con
        import win32api
        HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

class WindowsSecurityLogCollector:
    """
    Local Windows Security Log Collector.
    Extracts authentication and account management telemetry from Windows Event Logs.
    """
    def __init__(
        self,
        agent_id: Optional[str] = None,
        hostname: Optional[str] = None,
        bookmark_file: Path = BOOKMARK_FILE
    ):
        self.hostname = hostname or platform.node() or "LOCALHOST"
        self.agent_id = agent_id or f"win-local-{self.hostname.lower()}"
        self.bookmark_file = bookmark_file
        self.last_record_id: int = self._load_bookmark()
        self.target_event_ids = [4624, 4625, 4634, 4740]

    def _load_bookmark(self) -> int:
        """Loads last processed EventRecordID from disk."""
        if self.bookmark_file.exists():
            try:
                with open(self.bookmark_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return int(data.get("last_record_id", 0))
            except Exception:
                return 0
        return 0

    def _save_bookmark(self, record_id: int):
        """Saves last processed EventRecordID to disk."""
        try:
            self.bookmark_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.bookmark_file, "w", encoding="utf-8") as f:
                json.dump({"last_record_id": record_id, "updated_at": datetime.now(timezone.utc).isoformat()}, f)
            self.last_record_id = record_id
        except Exception as e:
            print(f"[-] Warning: Failed to save event bookmark: {e}")

    def check_environment(self) -> Dict[str, Any]:
        """
        Validates if Windows Security logs can be accessed.
        Returns capability report and troubleshooting guidance.
        """
        if platform.system() != "Windows":
            return {
                "capable": False,
                "os": platform.system(),
                "reason": "Windows Event Log collector requires a Microsoft Windows operating system.",
                "solution": "Use remote agent, synthetic log simulator (simulate_logs.py), or Linux collector."
            }

        if not HAS_WIN32:
            return {
                "capable": False,
                "os": "Windows",
                "reason": "pywin32 library is not installed in the active Python environment.",
                "solution": "Run 'python -m pip install pywin32' to enable Windows Event Log collection."
            }

        # Attempt opening Security log channel
        try:
            # Modern Windows EvtQuery test
            query = "*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"
            handle = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryChannelPath, query)
            return {
                "capable": True,
                "os": "Windows",
                "api": "EvtQuery (Modern Vista+ XML API)",
                "reason": "Security Event Log is accessible with active permissions.",
                "solution": "Ready for live collection."
            }
        except Exception as e:
            err_msg = str(e)
            if "Access is denied" in err_msg or "5" in err_msg:
                return {
                    "capable": False,
                    "os": "Windows",
                    "reason": "Permission Denied: Windows Security logs require Administrator elevation or 'Event Log Readers' group membership.",
                    "solution": "Run terminal/Streamlit as Administrator, or use the built-in synthetic event simulator."
                }
            return {
                "capable": False,
                "os": "Windows",
                "reason": f"Windows Event Log channel error: {err_msg}",
                "solution": "Verify Windows Event Log service ('EventLog') is running."
            }

    def _parse_event_xml(self, xml_text: str) -> Optional[SecurityEvent]:
        """Parses modern Windows Event XML into a normalized SecurityEvent."""
        try:
            root = ET.fromstring(xml_text)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            # System Section
            system = root.find("ns:System", ns)
            if system is None:
                return None
                
            event_id_elem = system.find("ns:EventID", ns)
            if event_id_elem is None or not event_id_elem.text:
                return None
            event_id = int(event_id_elem.text.strip())
            
            record_id_elem = system.find("ns:EventRecordID", ns)
            record_id = int(record_id_elem.text.strip()) if record_id_elem is not None and record_id_elem.text else 0
            
            time_elem = system.find("ns:TimeCreated", ns)
            ts_str = time_elem.get("SystemTime") if time_elem is not None else datetime.now(timezone.utc).isoformat()
            
            computer_elem = system.find("ns:Computer", ns)
            hostname = computer_elem.text.strip() if computer_elem is not None and computer_elem.text else self.hostname

            # EventData Section
            event_data_dict: Dict[str, str] = {}
            event_data = root.find("ns:EventData", ns)
            if event_data is not None:
                for data_item in event_data.findall("ns:Data", ns):
                    name = data_item.get("Name")
                    val = data_item.text or ""
                    if name:
                        event_data_dict[name] = val.strip()

            # Target User Resolution
            username = (
                event_data_dict.get("TargetUserName") or
                event_data_dict.get("SubjectUserName") or
                "Unknown"
            )
            # Filter out system computer accounts ending in $ (e.g. WORKSTATION$)
            if username.endswith("$"):
                return None

            source_ip = event_data_dict.get("IpAddress")
            logon_type_code = event_data_dict.get("LogonType")
            logon_desc = LOGON_TYPES.get(logon_type_code, f"Logon Type {logon_type_code}" if logon_type_code else None)
            
            event_type = WINDOWS_EVENT_ID_MAP.get(event_id, SecurityEventType.GENERIC_SECURITY)
            
            if event_id == 4625:
                desc = f"Failed logon for '{username}' from IP {source_ip or 'Local'}"
            elif event_id == 4624:
                desc = f"Successful logon for '{username}' ({logon_desc or 'Standard'})"
            elif event_id == 4740:
                desc = f"Account lockout triggered for '{username}'"
            elif event_id == 4634:
                desc = f"Logoff event for '{username}'"
            else:
                desc = f"Windows Security Event {event_id}"

            unique_evt_id = generate_deterministic_event_id(self.agent_id, ts_str, str(event_id), record_id)

            return SecurityEvent(
                event_id=unique_evt_id,
                agent_id=self.agent_id,
                hostname=hostname,
                timestamp=ts_str,
                event_type=event_type,
                windows_event_id=event_id,
                username=username,
                source_ip=source_ip,
                logon_type=logon_desc,
                description=desc,
                metadata={
                    "record_id": record_id,
                    "sub_status": event_data_dict.get("SubStatus"),
                    "failure_reason": event_data_dict.get("FailureReason"),
                    "workstation_name": event_data_dict.get("WorkstationName"),
                    "process_name": event_data_dict.get("ProcessName")
                }
            )
        except Exception as e:
            print(f"[-] Error parsing Windows XML event: {e}")
            return None

    def collect_new_events(self, max_events: int = 100) -> Tuple[List[SecurityEvent], Dict[str, Any]]:
        """
        Queries and returns newly generated Windows Security events since last bookmark.
        Returns: (events_list, diagnostic_summary)
        """
        env_check = self.check_environment()
        if not env_check["capable"]:
            return [], env_check

        events: List[SecurityEvent] = []
        max_seen_record = self.last_record_id
        
        try:
            # Query Security channel for specific authentication event IDs
            evt_filter = " or ".join([f"EventID={eid}" for eid in self.target_event_ids])
            if self.last_record_id > 0:
                query_xpath = f"*[System[({evt_filter}) and EventRecordID > {self.last_record_id}]]"
            else:
                # First run: take events from past 24 hours
                query_xpath = f"*[System[({evt_filter}) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"

            query_handle = win32evtlog.EvtQuery(
                "Security",
                win32evtlog.EvtQueryChannelPath,
                query_xpath
            )
            
            raw_events = win32evtlog.EvtNext(query_handle, max_events)
            for raw_ev in raw_events:
                xml_content = win32evtlog.EvtRender(raw_ev, win32evtlog.EvtRenderEventXml)
                parsed = self._parse_event_xml(xml_content)
                if parsed:
                    events.append(parsed)
                    rec_id = parsed.metadata.get("record_id", 0) if parsed.metadata else 0
                    if rec_id > max_seen_record:
                        max_seen_record = rec_id

            if max_seen_record > self.last_record_id:
                self._save_bookmark(max_seen_record)

            return events, {
                "success": True,
                "collected_count": len(events),
                "last_record_id": self.last_record_id,
                "agent_id": self.agent_id
            }
        except Exception as exc:
            return [], {
                "success": False,
                "error": str(exc),
                "advice": "Check administrator permissions for Security Event Log access."
            }
