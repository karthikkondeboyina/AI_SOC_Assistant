"""
AI SOC Assistant - Agent Configuration
Loads configuration for local and remote security log agents from environment variables
or command-line overrides.
"""

from typing import Optional
import os
import platform
from pydantic import BaseModel, Field

class AgentConfig(BaseModel):
    server_url: str = Field(
        default=os.getenv("SOC_SERVER_URL", "http://127.0.0.1:8000"),
        description="Base URL of the central SOC Ingestion FastAPI service"
    )
    agent_id: str = Field(
        default=os.getenv("SOC_AGENT_ID", f"agent-{platform.node().lower()[:16]}"),
        description="Unique identifier for this monitored host"
    )
    agent_token: str = Field(
        default=os.getenv("SOC_AGENT_TOKEN", "soc-secure-agent-token-2026"),
        description="Shared secret authentication token for API communication"
    )
    hostname: str = Field(
        default=platform.node() or "UNKNOWN-HOST",
        description="Machine name reported to SOC server"
    )
    poll_interval: int = Field(
        default=int(os.getenv("SOC_POLL_INTERVAL", "5")),
        description="Seconds to sleep between collection cycles"
    )
    heartbeat_interval: int = Field(
        default=int(os.getenv("SOC_HEARTBEAT_INTERVAL", "30")),
        description="Seconds between agent heartbeat pings"
    )
    batch_size: int = Field(
        default=50,
        description="Maximum events sent per HTTP request"
    )
    queue_maxsize: int = Field(
        default=1000,
        description="Maximum events held in offline buffer during network interruption"
    )
