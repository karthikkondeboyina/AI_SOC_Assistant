"""
AI SOC Assistant - MITRE ATT&CK Mapping Module
Maps validated cybersecurity threat classifications to official MITRE ATT&CK Enterprise techniques,
providing technique IDs, names, tactic phases, official URLs, and evidence rationales.
"""

from typing import Dict, Any, Optional

# Verified MITRE ATT&CK Enterprise Matrix mappings
OFFICIAL_MITRE_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "Port Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery (TA0007)",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable entry points and listening ports.",
        "rationale": "High volume of short-duration SYN/FIN packets directed across sequential or distributed destination ports indicating systematic scanning."
    },
    "DDoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact (TA0040)",
        "url": "https://attack.mitre.org/techniques/T1498/",
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or disrupt the availability of targeted networks, systems, or services.",
        "rationale": "Severe packet flooding and volumetric bandwidth consumption overwhelming network flow capacity from distributed sources."
    },
    "DoS (Hulk)": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact (TA0040)",
        "url": "https://attack.mitre.org/techniques/T1499/",
        "description": "Adversaries may target web servers with application-level request flooding designed to exhaust web server threads and memory pools.",
        "rationale": "High-concurrency obfuscated HTTP GET requests with randomized headers generated to bypass caching and exhaust web service sockets."
    },
    "DoS (GoldenEye)": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact (TA0040)",
        "url": "https://attack.mitre.org/techniques/T1499/",
        "description": "Application-layer denial-of-service attack leveraging Keep-Alive HTTP headers to consume server worker threads.",
        "rationale": "Sustained persistent HTTP connections utilizing cache-control headers designed to monopolize pool resources."
    },
    "DoS (Slowloris)": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact (TA0040)",
        "url": "https://attack.mitre.org/techniques/T1499/",
        "description": "Adversaries send partial HTTP requests at periodic intervals to keep web server connections open indefinitely without completing them.",
        "rationale": "Prolonged flow duration with low packet transfer rates and incomplete HTTP header terminations."
    },
    "DoS (SlowHTTPTest)": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact (TA0040)",
        "url": "https://attack.mitre.org/techniques/T1499/",
        "description": "Vulnerability testing tool simulating slow HTTP read/post DoS conditions against web server concurrency limits.",
        "rationale": "High connection count exhibiting minimal payload transmission rates stalling server application threads."
    },
    "Brute Force (SSH)": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access (TA0006)",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Adversaries may use brute force techniques to attempt credential guessing against SSH remote administration services.",
        "rationale": "Repeated bidirectional handshakes against port 22 with consistent flow lengths representing iterative login authentication attempts."
    },
    "Brute Force (FTP)": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access (TA0006)",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Adversaries may automate credential guessing against FTP services (Patator toolkit) to acquire unauthorized file transfer access.",
        "rationale": "Rapid recurring TCP sessions against FTP service ports with characteristic authentication failure flow profiles."
    },
    "Web Attack (Brute Force)": {
        "technique_id": "T1110",
        "technique_name": "Brute Force: Password Spraying / Web Authentication",
        "tactic": "Credential Access (TA0006)",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Automated attempts to guess credentials on web-based authentication forms or API endpoints.",
        "rationale": "Cyclic HTTP POST request patterns toward web application authentication endpoints."
    },
    "Web Attack (XSS)": {
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise / Cross-Site Scripting",
        "tactic": "Initial Access (TA0001)",
        "url": "https://attack.mitre.org/techniques/T1189/",
        "description": "Adversaries may deliver malicious client-side scripts via web application parameters to target other users and hijack sessions.",
        "rationale": "Injected script payload characters and URI parameters detected in inbound HTTP flows."
    },
    "Web Attack (SQL Injection)": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access (TA0001)",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries exploit weaknesses in web application database input parsing to execute unauthorized SQL queries and extract data.",
        "rationale": "Inbound HTTP request structures bearing SQL syntax keywords (UNION, SELECT, OR 1=1) targeting backend datastores."
    },
    "Botnet": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol: Command and Control",
        "tactic": "Command and Control (TA0011)",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "description": "Adversaries communicate with malware-infected endpoints using standard application protocols to coordinate actions and beacon.",
        "rationale": "Periodic beaconing and synchronized command-and-control connection cycles matching known bot communication signatures (e.g. Ares botnet)."
    },
    "Vulnerability Exploit (Heartbleed)": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access (TA0001)",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries exploit OpenSSL TLS heartbeat extension buffer over-read (CVE-2014-0160) to dump server memory contents.",
        "rationale": "Anomalous TLS Heartbeat extension requests with payload length discrepancies triggering server heap memory disclosure."
    },
    "Infiltration": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts / Lateral Movement",
        "tactic": "Defense Evasion (TA0005) & Lateral Movement (TA0008)",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "description": "Adversaries establish foothold inside the perimeter and pivot across internal network segments to compromise assets.",
        "rationale": "Multi-stage internal host communication following perimeter breach, exhibiting atypical internal port interaction."
    },
    # Live Host Log Monitoring Mappings (Windows Event Logs & Syslog)
    "Targeted Account Brute-Force": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access (TA0006)",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "description": "Adversaries systematically guess passwords for a specific user account on a system to gain unauthorized access.",
        "rationale": "Cluster of Event 4625 failed authentication records targeting a specific account within a short sliding time window."
    },
    "Password Spraying Attack": {
        "technique_id": "T1110.003",
        "technique_name": "Brute Force: Password Spraying",
        "tactic": "Credential Access (TA0006)",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
        "description": "Adversaries use a single or small set of common passwords across many accounts to evade account lockout thresholds.",
        "rationale": "Authentication attempts originating from a single source address distributed across multiple distinct usernames."
    },
    "Anomalous Host Failed Logins": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access (TA0006)",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "Repeated failed authentication attempts against a host indicating automated scanning or credential brute-forcing.",
        "rationale": "High density of Windows Security Event 4625 occurrences exceeding host-wide baseline thresholds."
    },
    "Account Lockout Detected": {
        "technique_id": "T1110",
        "technique_name": "Brute Force / Account Lockout Triggered",
        "tactic": "Credential Access (TA0006) & Impact (TA0040)",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "description": "User account lockout triggered by repeated invalid authentication attempts, preventing legitimate access.",
        "rationale": "Windows Security Event 4740 explicitly generated indicating active lockout policy enforcement following brute force attempts."
    },
    "Suspicious Remote Interactive (RDP) Failure": {
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement (TA0008) & Initial Access (TA0001)",
        "url": "https://attack.mitre.org/techniques/T1021/001/",
        "description": "Adversaries may attempt to log into systems using Remote Desktop Protocol (RDP) using compromised or guessed credentials.",
        "rationale": "Windows Security Event 4625 with Logon Type 10 (RemoteInteractive) originating from external or unapproved network source."
    }
}

def map_threat_to_mitre(threat_category: str) -> Dict[str, Any]:
    """
    Retrieves the verified MITRE ATT&CK mapping for a given threat category.
    If the category is Benign or lacks sufficient evidence, returns an explicit advisory notice.
    """
    category_clean = str(threat_category).strip()
    
    if category_clean.lower() == "benign":
        return {
            "mapped": False,
            "technique_id": "N/A",
            "technique_name": "Benign Traffic",
            "tactic": "Normal Operations",
            "url": "https://attack.mitre.org/",
            "description": "No malicious tactics or techniques detected.",
            "rationale": "Observed flow indicators conform to legitimate baseline network behavior."
        }
        
    mapping = OFFICIAL_MITRE_MAPPINGS.get(category_clean)
    if mapping:
        res = dict(mapping)
        res["mapped"] = True
        return res
        
    # Check if partial match exists
    for key, val in OFFICIAL_MITRE_MAPPINGS.items():
        if key.lower() in category_clean.lower() or category_clean.lower() in key.lower():
            res = dict(val)
            res["mapped"] = True
            return res
            
    # Insufficient evidence
    return {
        "mapped": False,
        "technique_id": "N/A",
        "technique_name": "MITRE mapping requires additional evidence",
        "tactic": "Unclassified",
        "url": "https://attack.mitre.org/",
        "description": "Generic detection label does not provide sufficient behavioral context to definitively isolate a single MITRE ATT&CK technique.",
        "rationale": "Additional packet telemetry (payload inspection, endpoint process tree, or DNS queries) is necessary for high-confidence mapping."
    }
