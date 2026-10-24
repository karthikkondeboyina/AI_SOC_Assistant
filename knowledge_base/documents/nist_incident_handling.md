# NIST Special Publication 800-61 Revision 2: Incident Handling Guide

## 1. Preparation
- Establish incident response policies, designated roles, and validated playbooks.
- Deploy host-based and network-based telemetry sensors.
- Maintain out-of-band communication channels for the security team during major incidents.

## 2. Detection & Analysis
- **Identify Incident Precursors & Indicators**: Differentiate between false positives and authentic operational anomalies.
- **Triage & Priority Classification**: Rate incidents by functional impact on systems, information impact (data breach vs. availability loss), and recovery effort.
- **Evidence Preservation**: Document timestamps, source/destination flow tuples, hash values, and preserve volatile system memory following chain-of-custody protocols.

## 3. Containment, Eradication & Recovery
- **Short-Term Containment**: Isolate affected network VLANs or route suspicious traffic to blackhole/sinkhole filters. Never prematurely destroy adversarial command channels before documenting telemetry.
- **Eradication**: Identify all affected hosts, remove unauthorized persistence mechanisms, and close exploited vulnerabilities or patch affected software versions.
- **Recovery**: Restore verified clean backups, validate system security baseline, re-enable production traffic, and institute heightened monitoring.

## 4. Post-Incident Activity
- Conduct a formal lessons-learned meeting within two weeks of incident closure.
- Document total downtime, financial impact, root cause, and remediation efficacy.
- Update firewall rules, intrusion detection signatures, and automated SOC playbooks.
