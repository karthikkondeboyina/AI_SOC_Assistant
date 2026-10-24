# OWASP Top 10 Defensive Engineering & Mitigation Strategies

## A03: Injection (SQL Injection, Command Injection)
- **Threat Vector**: Untrusted input concatenated directly into dynamic SQL queries or system commands.
- **Defensive Measures**:
  1. Mandate parameterized queries or prepared statements across all database abstraction layers.
  2. Implement strict object-relational mapping (ORM) parameter binding.
  3. Restrict database user account permissions following the principle of least privilege.
  4. Deploy Web Application Firewalls (WAF) with signature and behavioral rules blocking malicious SQL statements.

## A07: Identification and Authentication Failures
- **Threat Vector**: Credential stuffing, automated brute force, weak session timeouts.
- **Defensive Measures**:
  1. Require multi-factor authentication (MFA) on all internet-facing portals.
  2. Implement CAPTCHA or progressive rate limiting after consecutive invalid login attempts.
  3. Disallow default credentials and enforce strong passphrase complexity.
  4. Invalidate session identifiers upon logout and session inactivity.

## Denial of Service and Resource Depletion
- **Threat Vector**: HTTP request floods, connection exhaustion, slow client reading.
- **Defensive Measures**:
  1. Enforce per-IP request throttling and adaptive concurrency caps.
  2. Configure reverse proxies (Nginx, Cloudflare, HAProxy) to drop invalid HTTP request methods.
  3. Tune timeout thresholds: client_header_timeout, client_body_timeout, and keepalive_timeout.
