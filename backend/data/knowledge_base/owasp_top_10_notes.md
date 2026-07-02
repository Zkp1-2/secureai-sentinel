# OWASP A01 Broken Access Control
Broken access control occurs when users can act outside intended permissions. Examples include insecure direct object references, missing function-level authorization, privilege escalation, and bypassing access control checks. Recommended controls include server-side authorization, deny-by-default policies, centralized access control, and regression tests for horizontal and vertical privilege escalation.

# OWASP A02 Cryptographic Failures
Cryptographic failures include exposure of secrets, credentials, tokens, personal data, or weak protection of sensitive data in transit or at rest. Recommended controls include secret management, TLS, encryption at rest, key rotation, and avoiding sensitive data in logs or client-side responses.

# OWASP A03 Injection
Injection occurs when untrusted input is interpreted as a command, query, script, or expression. SQL injection, command injection, template injection, and some forms of XSS are common examples. Recommended controls include parameterized queries, allowlist validation, contextual output encoding, escaping, and avoiding unsafe interpreters.

# OWASP A05 Security Misconfiguration
Security misconfiguration includes default passwords, debug mode, overly permissive cloud storage, exposed admin dashboards, missing security headers, and unnecessary open ports. Recommended controls include hardened baselines, automated configuration scanning, secure defaults, and continuous monitoring.

# OWASP A06 Vulnerable and Outdated Components
Applications using vulnerable dependencies or unsupported components may inherit known CVEs. Recommended controls include software composition analysis, patch management, dependency pinning, advisories monitoring, and compensating controls when immediate upgrade is not possible.

# OWASP A07 Identification and Authentication Failures
Authentication failures include weak passwords, missing MFA, no lockout or throttling, poor credential recovery, and insecure session management. Recommended controls include MFA, lockout/throttling, secure password policies, breached password checks, and session protection.

# OWASP A10 Server-Side Request Forgery
SSRF occurs when a server-side component fetches attacker-controlled URLs, potentially reaching internal services or cloud metadata endpoints. Recommended controls include allowlisting destinations, network egress restrictions, blocking metadata endpoints, and redirect validation.

---
OWASP Practical Triage Workflow
Security findings should be validated against evidence, affected asset, exploitability, and business impact. Practical triage often uses scanner severity, CWE/OWASP mapping, exposed asset context, and remediation ownership. Findings should be marked as Confirmed, False Positive, Accepted Risk, Fixed, or Needs Review.

---
Scanner Report Validation
Scanner outputs from tools such as OWASP ZAP, Trivy, Semgrep, Nmap, Burp Suite, OpenVAS, and SCA platforms should be normalized before triage. Duplicate findings should be grouped by asset, weakness category, CWE, endpoint, and package. High-confidence reports include evidence, affected location, scanner name, severity, and remediation guidance.
