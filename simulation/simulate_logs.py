"""
AI SOC Assistant - Safe Security Event Simulator
Generates synthetic, labeled security event streams for college demonstration,
system verification, and automated testing without touching real production logs or attacking systems.
"""

import sys
import time
import argparse
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
import httpx

# Ensure project root is available
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from modules.live_monitor.event_schema import (
    SecurityEvent,
    SecurityEventType,
    generate_deterministic_event_id
)

def create_synthetic_event(
    agent_id: str,
    hostname: str,
    event_type: SecurityEventType,
    windows_event_id: int,
    username: str,
    source_ip: str,
    logon_type: str,
    description: str,
    index: int
) -> SecurityEvent:
    """Constructs a validated synthetic security event."""
    ts = datetime.now(timezone.utc).isoformat()
    evt_id = f"SIM-{generate_deterministic_event_id(agent_id, ts, str(windows_event_id), index)[4:]}"
    
    return SecurityEvent(
        event_id=evt_id,
        agent_id=agent_id,
        hostname=hostname,
        timestamp=ts,
        event_type=event_type,
        windows_event_id=windows_event_id,
        username=username,
        source_ip=source_ip,
        logon_type=logon_type,
        description=f"[SYNTHETIC DEMO] {description}",
        metadata={"simulation_source": "simulate_logs.py", "scenario_index": index}
    )

def generate_scenario_events(
    scenario: str,
    agent_id: str,
    hostname: str,
    count: int = 10
) -> List[SecurityEvent]:
    """Generates synthetic events based on the requested security scenario."""
    events: List[SecurityEvent] = []
    
    if scenario == "normal":
        users = ["alice", "bob", "developer", "carol"]
        for i in range(count):
            u = random.choice(users)
            # Pair of logon and logoff
            events.append(create_synthetic_event(
                agent_id=agent_id,
                hostname=hostname,
                event_type=SecurityEventType.SUCCESSFUL_LOGIN,
                windows_event_id=4624,
                username=u,
                source_ip="192.168.1.45",
                logon_type="2 - Interactive",
                description=f"Authorized successful user logon for '{u}'",
                index=i*2
            ))
            events.append(create_synthetic_event(
                agent_id=agent_id,
                hostname=hostname,
                event_type=SecurityEventType.LOGOFF,
                windows_event_id=4634,
                username=u,
                source_ip="192.168.1.45",
                logon_type="2 - Interactive",
                description=f"Standard user logoff for '{u}'",
                index=i*2 + 1
            ))

    elif scenario == "failed-logins":
        # Repeated failed logins targeting Administrator (Rule 1 & Rule 2)
        for i in range(count):
            events.append(create_synthetic_event(
                agent_id=agent_id,
                hostname=hostname,
                event_type=SecurityEventType.FAILED_LOGIN,
                windows_event_id=4625,
                username="administrator",
                source_ip="10.0.4.88",
                logon_type="3 - Network",
                description=f"Failed authentication attempt #{i+1} against local administrator",
                index=i
            ))

    elif scenario == "password-spray":
        # Single external source IP attempting authentication across multiple usernames (Rule 3)
        targets = ["admin", "root", "oracle", "finance_user", "sql_service", "backup_operator", "helpdesk"]
        for i, u in enumerate(targets[:count]):
            events.append(create_synthetic_event(
                agent_id=agent_id,
                hostname=hostname,
                event_type=SecurityEventType.FAILED_LOGIN,
                windows_event_id=4625,
                username=u,
                source_ip="198.51.100.24", # Public IP
                logon_type="3 - Network",
                description=f"Password spray probe against account '{u}' from external IP 198.51.100.24",
                index=i
            ))

    elif scenario == "lockout":
        # 5 failed logins followed by an Account Lockout (Rule 4)
        target_account = "finance_director"
        for i in range(5):
            events.append(create_synthetic_event(
                agent_id=agent_id,
                hostname=hostname,
                event_type=SecurityEventType.FAILED_LOGIN,
                windows_event_id=4625,
                username=target_account,
                source_ip="192.168.1.189",
                logon_type="2 - Interactive",
                description=f"Failed console authentication attempt for '{target_account}'",
                index=i
            ))
        events.append(create_synthetic_event(
            agent_id=agent_id,
            hostname=hostname,
            event_type=SecurityEventType.ACCOUNT_LOCKOUT,
            windows_event_id=4740,
            username=target_account,
            source_ip="192.168.1.189",
            logon_type="Local Lockout",
            description=f"Account '{target_account}' has been locked out after exceeding failure threshold",
            index=5
        ))

    elif scenario == "rdp-brute":
        # RDP Remote Interactive failure (Rule 5)
        for i in range(count):
            events.append(create_synthetic_event(
                agent_id=agent_id,
                hostname=hostname,
                event_type=SecurityEventType.FAILED_LOGIN,
                windows_event_id=4625,
                username="administrator",
                source_ip="203.0.113.15", # Public external IP
                logon_type="10 - RemoteInteractive (RDP)",
                description=f"Unauthorized RDP connection attempt from internet source 203.0.113.15",
                index=i
            ))

    elif scenario == "mixed":
        # Comprehensive realistic mixture
        events.extend(generate_scenario_events("normal", agent_id, hostname, count=4))
        events.extend(generate_scenario_events("failed-logins", agent_id, hostname, count=6))
        events.extend(generate_scenario_events("lockout", agent_id, hostname, count=3))

    return events

def run_simulation(
    server_url: str,
    token: str,
    scenario: str,
    agent_id: str,
    hostname: str,
    count: int,
    delay: float
):
    print("=" * 65)
    print(f"[*] AI SOC Assistant - Synthetic Event Simulator")
    print(f"[*] Target Server: {server_url}")
    print(f"[*] Selected Scenario: {scenario.upper()}")
    print(f"[*] Monitored Agent ID: {agent_id} ({hostname})")
    print("=" * 65)

    headers = {"X-SOC-Agent-Token": token}
    
    # 1. Send Heartbeat first
    try:
        hb_payload = {
            "agent_id": agent_id,
            "hostname": hostname,
            "ip_address": "192.168.1.155",
            "os_type": "Windows (Simulated)",
            "agent_version": "2.0.0"
        }
        with httpx.Client(timeout=5.0) as client:
            res = client.post(f"{server_url.rstrip('/')}/api/heartbeat", json=hb_payload, headers=headers)
            if res.status_code == 200:
                print(f"[+] Registered simulated agent heartbeat with SOC server.")
            else:
                print(f"[-] Heartbeat failed (Status {res.status_code}): {res.text}")
    except Exception as e:
        print(f"[-] Cannot connect to SOC API server at {server_url}: {e}")
        print("    Please ensure FastAPI server is running: python -m api.server")
        return

    # 2. Generate and transmit events
    events = generate_scenario_events(scenario, agent_id, hostname, count)
    print(f"[*] Streaming {len(events)} synthetic security events (delay: {delay}s per event)...")

    success_count = 0
    alerts_triggered_total = 0

    with httpx.Client(timeout=8.0) as client:
        for idx, ev in enumerate(events, 1):
            try:
                res = client.post(
                    f"{server_url.rstrip('/')}/api/events",
                    json=[ev.model_dump()],
                    headers=headers
                )
                if res.status_code == 200:
                    data = res.json()
                    success_count += 1
                    alerts_count = data.get("alerts_triggered", 0)
                    alerts_triggered_total += alerts_count
                    alert_tag = f" -> 🚨 ALERT TRIGGERED!" if alerts_count > 0 else ""
                    print(f"[{idx}/{len(events)}] Sent {ev.event_type.value} for '{ev.username}' ({ev.windows_event_id or 'N/A'}){alert_tag}")
                else:
                    print(f"[{idx}/{len(events)}] Transmission failed: HTTP {res.status_code} - {res.text}")
            except Exception as exc:
                print(f"[{idx}/{len(events)}] Network exception: {exc}")

            if delay > 0 and idx < len(events):
                time.sleep(delay)

    print("=" * 65)
    print(f"[+] Simulation Complete!")
    print(f"    Total Events Sent: {len(events)}")
    print(f"    Successfully Ingested: {success_count}")
    print(f"    Threat Alerts Triggered: {alerts_triggered_total}")
    print(f"[*] Check the Streamlit '📡 Live Security Monitor' dashboard to view real-time alerts!")
    print("=" * 65)

def main():
    parser = argparse.ArgumentParser(description="Synthetic Security Event Simulator for AI SOC Assistant")
    parser.add_argument(
        "--scenario",
        type=str,
        default="failed-logins",
        choices=["normal", "failed-logins", "password-spray", "lockout", "rdp-brute", "mixed"],
        help="Demonstration scenario to execute"
    )
    parser.add_argument("--server", type=str, default="http://127.0.0.1:8000", help="Central SOC API URL")
    parser.add_argument("--token", type=str, default="soc-secure-agent-token-2026", help="Agent authentication token")
    parser.add_argument("--agent-id", type=str, default="sim-agent-01", help="Simulated agent ID")
    parser.add_argument("--hostname", type=str, default="FINANCE-SRV-01", help="Simulated hostname")
    parser.add_argument("--count", type=int, default=10, help="Number of events in scenario")
    parser.add_argument("--delay", type=float, default=0.15, help="Delay between events in seconds")
    
    args = parser.parse_args()
    run_simulation(
        server_url=args.server,
        token=args.token,
        scenario=args.scenario,
        agent_id=args.agent_id,
        hostname=args.hostname,
        count=args.count,
        delay=args.delay
    )

if __name__ == "__main__":
    main()
