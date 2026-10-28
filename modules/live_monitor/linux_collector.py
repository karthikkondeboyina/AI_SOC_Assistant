"""
AI SOC Assistant - Linux Security Log Collector
Parses standard Linux authentication logs (/var/log/auth.log, /var/log/secure, or journalctl)
into normalized SecurityEvent instances.
Includes permission checks and cross-platform fallback for testing on non-Linux hosts.
"""

from typing import List, Dict, Any, Tuple, Optional
import os
import re
import platform
from datetime import datetime, timezone

from modules.live_monitor.event_schema import (
    SecurityEvent,
    SecurityEventType,
    generate_deterministic_event_id
)

AUTH_LOG_PATHS = [
    "/var/log/auth.log",       # Debian, Ubuntu
    "/var/log/secure",         # RHEL, CentOS, Fedora
    "/var/log/messages"
]

class LinuxAuthLogCollector:
    """Collector for Linux sshd / sudo authentication events."""
    def __init__(self, agent_id: Optional[str] = None, hostname: Optional[str] = None):
        self.hostname = hostname or platform.node() or "LINUX-HOST"
        self.agent_id = agent_id or f"linux-local-{self.hostname.lower()}"
        self.log_path: Optional[str] = self._locate_auth_log()
        self.last_byte_offset: int = 0

    def _locate_auth_log(self) -> Optional[str]:
        for path in AUTH_LOG_PATHS:
            if os.path.exists(path) and os.path.isfile(path):
                return path
        return None

    def check_environment(self) -> Dict[str, Any]:
        if platform.system() != "Linux":
            return {
                "capable": False,
                "os": platform.system(),
                "reason": "Linux log collector requires a Linux operating system.",
                "solution": "Use Windows collector or synthetic log simulator (simulate_logs.py)."
            }
        if not self.log_path:
            return {
                "capable": False,
                "os": "Linux",
                "reason": "Standard authentication log files (/var/log/auth.log, /var/log/secure) not found.",
                "solution": "Ensure rsyslog or systemd-journald is running."
            }
        if not os.access(self.log_path, os.R_OK):
            return {
                "capable": False,
                "os": "Linux",
                "reason": f"Permission denied reading {self.log_path}.",
                "solution": "Run collector with sudo or add the user to the 'adm' group."
            }
        return {
            "capable": True,
            "os": "Linux",
            "log_path": self.log_path,
            "reason": f"Active read access to {self.log_path}.",
            "solution": "Ready for live collection."
        }

    def parse_line(self, line: str) -> Optional[SecurityEvent]:
        """Parses a single syslog line into a SecurityEvent."""
        # Example sshd failed login:
        # Oct 28 10:15:30 myhost sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2
        # Oct 28 10:15:35 myhost sshd[1234]: Accepted password for ubuntu from 192.168.1.50 port 54322 ssh2
        line = line.strip()
        if not line or "sshd" not in line:
            return None

        now_utc = datetime.now(timezone.utc).isoformat()
        
        # Failed password
        fail_match = re.search(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)", line)
        if fail_match:
            user = fail_match.group(1)
            src_ip = fail_match.group(2)
            evt_id = generate_deterministic_event_id(self.agent_id, now_utc, "SSH_FAIL", hash(line) % 100000)
            return SecurityEvent(
                event_id=evt_id,
                agent_id=self.agent_id,
                hostname=self.hostname,
                timestamp=now_utc,
                event_type=SecurityEventType.FAILED_LOGIN,
                username=user,
                source_ip=src_ip,
                logon_type="SSH (Port 22)",
                description=f"Linux SSH failed password attempt for '{user}' from {src_ip}",
                metadata={"raw_line": line[:256]}
            )

        # Accepted password
        accept_match = re.search(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)", line)
        if accept_match:
            user = accept_match.group(1)
            src_ip = accept_match.group(2)
            evt_id = generate_deterministic_event_id(self.agent_id, now_utc, "SSH_OK", hash(line) % 100000)
            return SecurityEvent(
                event_id=evt_id,
                agent_id=self.agent_id,
                hostname=self.hostname,
                timestamp=now_utc,
                event_type=SecurityEventType.SUCCESSFUL_LOGIN,
                username=user,
                source_ip=src_ip,
                logon_type="SSH (Port 22)",
                description=f"Linux SSH successful logon for '{user}' from {src_ip}",
                metadata={"raw_line": line[:256]}
            )

        return None
