"""
AI SOC Assistant - Autonomous Security Log Agent
Lightweight, defensive Python agent designed to run on monitored Windows or Linux computers.
Collects authorized security event logs, buffers in bounded queue during network outages,
and securely transmits normalized events to the central FastAPI ingestion server.
"""

import sys
import time
import signal
import platform
import argparse
from typing import List, Dict, Any, Optional
from collections import deque
from pathlib import Path
import httpx

# Ensure project root is available if running directly
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from agent.config import AgentConfig
from modules.live_monitor.event_schema import SecurityEvent, SecurityEventType
from modules.live_monitor.windows_collector import WindowsSecurityLogCollector
from modules.live_monitor.linux_collector import LinuxAuthLogCollector

class SOCLogAgent:
    """Defensive log forwarding agent."""
    def __init__(self, config: AgentConfig):
        self.config = config
        self.running = False
        self.queue: deque = deque(maxlen=config.queue_maxsize)
        self.last_heartbeat = 0.0
        
        # Select OS-specific collector
        self.collector = None
        if platform.system() == "Windows":
            self.collector = WindowsSecurityLogCollector(
                agent_id=self.config.agent_id,
                hostname=self.config.hostname
            )
        elif platform.system() == "Linux":
            self.collector = LinuxAuthLogCollector(
                agent_id=self.config.agent_id,
                hostname=self.config.hostname
            )

        # Setup HTTP client
        self.headers = {
            "X-SOC-Agent-Token": self.config.agent_token,
            "User-Agent": f"SOC-Agent-2.0/{self.config.agent_id}"
        }

    def send_heartbeat(self) -> bool:
        """Sends periodic heartbeat to the central SOC server."""
        url = f"{self.config.server_url.rstrip('/')}/api/heartbeat"
        payload = {
            "agent_id": self.config.agent_id,
            "hostname": self.config.hostname,
            "ip_address": None, # Discovered by server or agent
            "os_type": platform.system(),
            "agent_version": "2.0.0"
        }
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.post(url, json=payload, headers=self.headers)
                if res.status_code == 200:
                    self.last_heartbeat = time.time()
                    return True
                else:
                    print(f"[-] Heartbeat rejected by SOC server (Status {res.status_code}): {res.text}")
                    return False
        except Exception as e:
            print(f"[-] Heartbeat network error: {e}")
            return False

    def transmit_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Transmits a batch of events with retry and exponential backoff."""
        if not events:
            return True
            
        url = f"{self.config.server_url.rstrip('/')}/api/events"
        payload = {
            "agent_id": self.config.agent_id,
            "events": events
        }
        
        max_retries = 3
        backoff = 1.0
        for attempt in range(1, max_retries + 1):
            try:
                with httpx.Client(timeout=10.0) as client:
                    res = client.post(url, json=payload, headers=self.headers)
                    if res.status_code == 200:
                        data = res.json()
                        print(f"[+] Transmitted {len(events)} events (Ingested: {data.get('ingested')}, Alerts: {data.get('alerts_triggered')})")
                        return True
                    elif res.status_code == 401:
                        print("[-] Authentication Failed: Invalid agent token. Check SOC_AGENT_TOKEN.")
                        return False
                    else:
                        print(f"[-] Server returned status {res.status_code}: {res.text}")
            except Exception as e:
                print(f"[-] Transmission error (attempt {attempt}/{max_retries}): {e}")
                
            time.sleep(backoff)
            backoff *= 2.0
            
        return False

    def run(self):
        """Main agent loop."""
        self.running = True
        print("=" * 60)
        print(f"[*] AI SOC Security Agent Starting")
        print(f"[*] Agent ID: {self.config.agent_id}")
        print(f"[*] Hostname: {self.config.hostname}")
        print(f"[*] OS Platform: {platform.system()} ({platform.release()})")
        print(f"[*] Target Central Server: {self.config.server_url}")
        print("=" * 60)

        # Environment check for collectors
        if self.collector:
            env_status = self.collector.check_environment()
            if not env_status.get("capable", False):
                print(f"[!] Warning: Local log collector reports limited capabilities:")
                print(f"    Reason: {env_status.get('reason')}")
                print(f"    Solution: {env_status.get('solution')}")
            else:
                print(f"[+] Local collector verified: {env_status.get('reason')}")

        # Initial heartbeat
        self.send_heartbeat()

        try:
            while self.running:
                # 1. Periodic Heartbeat
                if time.time() - self.last_heartbeat >= self.config.heartbeat_interval:
                    self.send_heartbeat()

                # 2. Collect from local OS log
                if self.collector and hasattr(self.collector, "collect_new_events"):
                    new_events, _ = self.collector.collect_new_events(max_events=self.config.batch_size)
                    for ev in new_events:
                        self.queue.append(ev.model_dump())

                # 3. Drain and Transmit buffered queue
                if self.queue:
                    batch: List[Dict[str, Any]] = []
                    while self.queue and len(batch) < self.config.batch_size:
                        batch.append(self.queue.popleft())
                        
                    success = self.transmit_batch(batch)
                    if not success:
                        # Re-enqueue in front of queue
                        for item in reversed(batch):
                            self.queue.appendleft(item)
                        print(f"[!] Buffered {len(self.queue)} events in offline queue awaiting server recovery.")

                time.sleep(self.config.poll_interval)
        except KeyboardInterrupt:
            print("\n[*] Agent shutdown requested by user.")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        print("[*] Agent stopped gracefully.")

def main():
    parser = argparse.ArgumentParser(description="AI SOC Autonomous Security Log Agent")
    parser.add_argument("--server", type=str, default=None, help="Central SOC API URL (e.g. http://127.0.0.1:8000)")
    parser.add_argument("--token", type=str, default=None, help="Agent authentication token")
    parser.add_argument("--agent-id", type=str, default=None, help="Custom Agent Identifier")
    parser.add_argument("--interval", type=int, default=5, help="Poll interval in seconds")
    args = parser.parse_args()

    cfg = AgentConfig()
    if args.server:
        cfg.server_url = args.server
    if args.token:
        cfg.agent_token = args.token
    if args.agent_id:
        cfg.agent_id = args.agent_id
    if args.interval:
        cfg.poll_interval = args.interval

    agent = SOCLogAgent(cfg)
    agent.run()

if __name__ == "__main__":
    main()
