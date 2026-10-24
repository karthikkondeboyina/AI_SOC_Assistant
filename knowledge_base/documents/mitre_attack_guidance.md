# MITRE ATT&CK Framework Guidance for Security Operations Centers

## T1046: Network Service Discovery
- **Tactic**: Discovery (TA0007)
- **Description**: Adversaries attempt to enumerate active services running on remote hosts to identify open listening ports and potentially vulnerable applications.
- **Network Flow Indicators**: Proliferation of brief SYN packets without subsequent application payloads across multiple sequential or random ports within a short time window.
- **SOC Detection & Mitigation**: Configure stateful firewall rate-limiting on port scanning behaviors. Restrict ingress access to management ports (e.g. 22, 3389, 445) through Zero Trust Network Access (ZTNA) or VPN gateways with MFA.

## T1110: Brute Force
- **Tactic**: Credential Access (TA0006)
- **Description**: Automated guessing of authentication credentials across protocols including SSH, FTP, RDP, and HTTP login forms.
- **Network Flow Indicators**: Repetitive bidirectional connection attempts of uniform length against authentication service ports, frequently interspersed with rapid TCP teardowns.
- **SOC Detection & Mitigation**: Enforce account lockout thresholds, exponential backoff delays on consecutive failed logins, robust password policies, and multi-factor authentication (MFA).

## T1498: Network Denial of Service (DDoS)
- **Tactic**: Impact (TA0040)
- **Description**: Adversaries perform network-layer denial of service to degrade or disrupt target network availability via volumetric packet flooding (e.g., SYN flood, UDP flood, ICMP flood).
- **Network Flow Indicators**: Extraordinary packet arrival frequency, asymmetric forward/backward packet counts, bandwidth saturation exceeding network interface baselines.
- **SOC Detection & Mitigation**: Upstream ISP traffic scrubbing, BGP Anycast routing, Anycast DNS, hardware DDoS mitigation appliances, and SYN cookie implementation.

## T1499: Endpoint Denial of Service
- **Tactic**: Impact (TA0040)
- **Description**: Application-layer DoS (e.g., HTTP Hulk, Slowloris, SlowHTTPTest, GoldenEye) targeting application thread concurrency and socket pools.
- **Network Flow Indicators**: Sustained connection duration with low transmission rates, partial HTTP request headers, randomized user-agent strings.
- **SOC Detection & Mitigation**: Reverse proxy connection timeouts, aggressive HTTP keep-alive limits, Web Application Firewall (WAF) rate limiting per client IP, and thread pool monitoring.

## T1190: Exploit Public-Facing Application
- **Tactic**: Initial Access (TA0001)
- **Description**: Exploitation of software weaknesses in internet-exposed services, such as SQL Injection or OpenSSL Heartbleed vulnerabilities.
- **Network Flow Indicators**: Unusual URI parameters bearing database syntax, anomalous TLS heartbeat lengths, unexpected HTTP error code spikes (500, 502).
- **SOC Detection & Mitigation**: Parameterized database queries, rigorous input validation, timely software patching, TLS termination with intrusion prevention system (IPS) inspection.

## T1071: Standard Application Layer Protocol for Command & Control
- **Tactic**: Command and Control (TA0011)
- **Description**: Adversaries communicate with malware-infected endpoints using standard application protocols (HTTP/HTTPS/DNS) to blend with legitimate administrative traffic.
- **Network Flow Indicators**: Periodic interval beaconing (jittered), uniform outbound request sizes, connections to unclassified external IP domains.
- **SOC Detection & Mitigation**: Deep packet inspection, outbound proxy SSL inspection, domain reputation filtering, and host-based endpoint detection and response (EDR).
