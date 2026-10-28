"""
AI SOC Assistant - Normalized Security Event Schema
Defines Pydantic models for validating, serializing, and sanitizing
real-time security event telemetry received from local and remote collectors.
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import hashlib
import uuid
from pydantic import BaseModel, Field, field_validator, ConfigDict

class SecurityEventType(str, Enum):
    FAILED_LOGIN = "FAILED_LOGIN"
    SUCCESSFUL_LOGIN = "SUCCESSFUL_LOGIN"
    LOGOFF = "LOGOFF"
    ACCOUNT_LOCKOUT = "ACCOUNT_LOCKOUT"
    PRIVILEGE_USE = "PRIVILEGE_USE"
    PROCESS_CREATION = "PROCESS_CREATION"
    SYSTEM_STARTUP = "SYSTEM_STARTUP"
    SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN"
    GENERIC_SECURITY = "GENERIC_SECURITY"

# Standard Windows Security Event ID mapping
WINDOWS_EVENT_ID_MAP: Dict[int, SecurityEventType] = {
    4624: SecurityEventType.SUCCESSFUL_LOGIN,
    4625: SecurityEventType.FAILED_LOGIN,
    4634: SecurityEventType.LOGOFF,
    4647: SecurityEventType.LOGOFF,
    4648: SecurityEventType.SUCCESSFUL_LOGIN, # Logon with explicit credentials
    4672: SecurityEventType.PRIVILEGE_USE,    # Special privileges assigned
    4720: SecurityEventType.GENERIC_SECURITY, # User account created
    4740: SecurityEventType.ACCOUNT_LOCKOUT,  # Account locked out
    4688: SecurityEventType.PROCESS_CREATION, # Process created
    6005: SecurityEventType.SYSTEM_STARTUP,
    6006: SecurityEventType.SYSTEM_SHUTDOWN,
}

# Windows Logon Type Reference
LOGON_TYPES: Dict[str, str] = {
    "2": "Interactive (Console / Local Keyboard)",
    "3": "Network (SMB, RPC, IIS)",
    "4": "Batch (Scheduled Task)",
    "5": "Service (Service Startup)",
    "7": "Unlock (Workstation Unlock)",
    "8": "NetworkCleartext (Cleartext Network Logon)",
    "9": "NewCredentials (RunAs with /netonly)",
    "10": "RemoteInteractive (Remote Desktop / RDP / Terminal Services)",
    "11": "CachedInteractive (Cached Domain Credentials)"
}

class SecurityEvent(BaseModel):
    """
    Normalized Security Event model.
    Enforces standard field structure across all operating systems and collection methods.
    """
    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(
        default_factory=lambda: f"EVT-{uuid.uuid4().hex[:12].upper()}",
        description="Unique event identifier (UUID or deterministic hash)"
    )
    agent_id: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Unique identifier of the sending agent (e.g. 'win-host-01')"
    )
    hostname: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Hostname or machine name where event occurred"
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC timestamp of the event in ISO 8601 format"
    )
    event_type: SecurityEventType = Field(
        ...,
        description="Standardized security event category"
    )
    windows_event_id: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535,
        description="Windows Security Event Log Event ID if applicable"
    )
    username: Optional[str] = Field(
        default="Unknown",
        max_length=128,
        description="Target or Subject user account associated with event"
    )
    source_ip: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Source IP address of authentication request or remote host"
    )
    logon_type: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Logon Type code or descriptive label"
    )
    description: Optional[str] = Field(
        default="",
        max_length=512,
        description="Human-readable summary of the security event"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Additional key-value pairs (e.g. process name, workstation name)"
    )

    @field_validator("timestamp")
    @classmethod
    def validate_utc_timestamp(cls, v: str) -> str:
        """Ensures timestamp is ISO formatted string with timezone awareness."""
        if not v:
            return datetime.now(timezone.utc).isoformat()
        try:
            # Parse to verify validity
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, v: Optional[str]) -> str:
        """Cleans and sanitizes username string."""
        if not v or v.strip() in ["-", "", "None", "null"]:
            return "Unknown"
        # Strip domain prefixes like WORKGROUP\\ or DOMAIN\\
        clean = v.strip()
        if "\\" in clean:
            clean = clean.split("\\")[-1]
        elif "@" in clean:
            clean = clean.split("@")[0]
        return clean[:128]

    @field_validator("source_ip")
    @classmethod
    def sanitize_source_ip(cls, v: Optional[str]) -> Optional[str]:
        """Normalizes IP address, handles loopbacks and missing indicators."""
        if not v or v.strip() in ["-", "", "::1", "127.0.0.1", "None", "null"]:
            return None
        clean = v.strip()
        # Some Windows logs append port e.g. '192.168.1.100:54321'
        if ":" in clean and "." in clean:
            clean = clean.split(":")[0]
        return clean[:64]

class SecurityEventBatch(BaseModel):
    """Container for batch submissions from log agents."""
    agent_id: str
    events: List[SecurityEvent] = Field(..., max_length=500)
    sent_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class AgentHeartbeat(BaseModel):
    """Agent heartbeat payload to indicate liveness."""
    agent_id: str
    hostname: str
    ip_address: Optional[str] = None
    os_type: Optional[str] = "Windows"
    agent_version: str = "1.0.0"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

def generate_deterministic_event_id(
    agent_id: str,
    timestamp: str,
    event_id_or_type: str,
    record_id: Optional[int] = None
) -> str:
    """
    Generates a deterministic unique event identifier to prevent duplicate submissions
    during agent retries or collector restarts.
    """
    raw_key = f"{agent_id}:{timestamp}:{event_id_or_type}:{record_id or ''}"
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16].upper()
    return f"EVT-{digest}"

def normalize_security_event(raw_dict: Dict[str, Any]) -> SecurityEvent:
    """Convenience helper to coerce dictionary into validated SecurityEvent."""
    return SecurityEvent(**raw_dict)
