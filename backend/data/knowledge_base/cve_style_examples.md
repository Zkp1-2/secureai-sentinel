# CVE-Style Example: SQL Injection in Login Endpoint
A login endpoint concatenates user input into SQL queries. Attackers may alter query logic to bypass authentication or extract database rows. Fixes include parameterized queries, database least privilege, query monitoring, and security tests.

# CVE-Style Example: Stored XSS in Profile Page
User profile fields are rendered without contextual output encoding. Attackers may inject JavaScript that runs in another user's browser and steals session cookies. Fixes include output encoding, sanitization, HttpOnly cookies, SameSite cookies, and Content Security Policy.

# CVE-Style Example: Missing MFA on Admin Portal
An admin portal has weak passwords and no MFA or account lockout. Attackers may brute-force administrator accounts. Fixes include MFA, lockout, throttling, breached-password checks, and login anomaly detection.

# CVE-Style Example: SSRF in URL Preview Feature
A URL preview feature fetches user-supplied URLs from the server. Attackers may request internal services or cloud metadata endpoints. Fixes include destination allowlists, network egress rules, and metadata endpoint blocking.

# CVE-Style Example: Path Traversal in File Download
A file download endpoint accepts a user-controlled path. Attackers may use traversal sequences to read files outside the intended directory. Fixes include path normalization, allowlisted file identifiers, and least-privilege file access.

# CVE-Style Example: Remote Code Execution Through Unsafe Deserialization
A service deserializes untrusted data and reaches code execution. Attackers may execute commands on the server. Fixes include removing unsafe deserialization, type allowlists, sandboxing, and segmentation.

---
CVE-Style Example: Trivy Vulnerable Dependency
A container scan reports a dependency with a known CVE, severity, package name, installed version, and fixed version. Triage should confirm runtime exposure, patch availability, exploit maturity, and compensating controls. Fixes include upgrading the package, rebuilding the image, and rescanning.

---
CVE-Style Example: Nmap Exposed Service
A network scan identifies an open TCP service on a public host. Triage should confirm whether the service is intentionally exposed, patched, authenticated, and monitored. Fixes include restricting ingress, disabling unused services, enforcing TLS/authentication, and patching the service.

---
CVE-Style Example: Semgrep Static Finding
A static analysis finding identifies insecure code patterns in source files. Triage should confirm reachability, data flow, sanitization, and whether the finding is exploitable in production. Fixes include secure coding changes, tests, and code review.
