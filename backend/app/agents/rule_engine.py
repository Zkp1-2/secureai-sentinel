from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

from app.schemas.analysis import EvidenceReference, VulnerabilityFinding
from app.utils.text import keyword_hits, safe_excerpt


@dataclass(frozen=True)
class Rule:
    category: str
    patterns: List[str]
    explanation: str
    severity_hint: str
    cwe: str | None = None
    owasp: str | None = None
    base_confidence: float = 0.78


RULES: List[Rule] = [
    Rule(
        category="SQL Injection",
        patterns=["sql injection", "parameterized", "prepared statement", "database query", "bypass authentication", "union select", "or 1=1", "cwe-89"],
        explanation="The input suggests unsafe database query construction that may allow authentication bypass, data extraction, or data manipulation.",
        severity_hint="Critical",
        cwe="CWE-89",
        owasp="A03:2021 Injection",
        base_confidence=0.9,
    ),
    Rule(
        category="Cross-Site Scripting",
        patterns=["cross-site scripting", "xss", "javascript", "script", "session cookie", "output encoding", "content security policy", "browser", "cwe-79"],
        explanation="The input suggests untrusted content may be rendered in a browser without safe output encoding or sanitization.",
        severity_hint="High",
        cwe="CWE-79",
        owasp="A03:2021 Injection",
        base_confidence=0.86,
    ),
    Rule(
        category="Weak Authentication",
        patterns=["multi-factor", "mfa", "weak password", "brute-force", "brute force", "account lockout", "login attempts", "password policy", "admin portal", "cwe-287"],
        explanation="The input suggests authentication controls are insufficient, which may allow account takeover or administrative compromise.",
        severity_hint="Critical",
        cwe="CWE-287",
        owasp="A07:2021 Identification and Authentication Failures",
        base_confidence=0.88,
    ),
    Rule(
        category="Broken Access Control",
        patterns=["access control", "permission", "authorization", "admin", "privilege", "restricted", "idor", "role", "sensitive configuration", "overly broad", "broad privilege", "broad privileges", "cwe-284"],
        explanation="The input suggests users may access data or functions beyond their intended permissions.",
        severity_hint="High",
        cwe="CWE-284",
        owasp="A01:2021 Broken Access Control",
        base_confidence=0.82,
    ),
    Rule(
        category="Credential Exposure",
        patterns=["credential", "password", "secret", "secrets", "api key", "token", "private key", "hardcoded", "environment variable", "log file", "configuration file", "configuration files", "cwe-798"],
        explanation="The input suggests sensitive credentials may be exposed, reused, logged, or stored insecurely.",
        severity_hint="Critical",
        cwe="CWE-798",
        owasp="A02:2021 Cryptographic Failures",
        base_confidence=0.83,
    ),
    Rule(
        category="Remote Code Execution",
        patterns=["remote code execution", "command injection", "arbitrary code", "execute commands", "shell", "deserialization", "unsafe deserialization", "rce vulnerability", "cwe-94"],
        explanation="The input suggests attackers may execute commands or arbitrary code on the target system.",
        severity_hint="Critical",
        cwe="CWE-94",
        owasp="A03:2021 Injection",
        base_confidence=0.87,
    ),
    Rule(
        category="Server-Side Request Forgery",
        patterns=["ssrf", "server-side request forgery", "metadata service", "169.254.169.254", "internal endpoint", "fetch url", "webhook url", "url preview", "cwe-918"],
        explanation="The input suggests the server may be tricked into making requests to internal or cloud metadata endpoints.",
        severity_hint="High",
        cwe="CWE-918",
        owasp="A10:2021 Server-Side Request Forgery",
        base_confidence=0.86,
    ),
    Rule(
        category="Path Traversal",
        patterns=["path traversal", "directory traversal", "../", "..\\", "file path", "download file", "arbitrary file", "cwe-22"],
        explanation="The input suggests attackers may manipulate file paths to access files outside the intended directory.",
        severity_hint="High",
        cwe="CWE-22",
        owasp="A01:2021 Broken Access Control",
        base_confidence=0.8,
    ),
    Rule(
        category="Insecure Configuration",
        patterns=["misconfiguration", "default password", "debug mode", "public bucket", "open port", "exposed dashboard", "no tls", "insecure configuration", "security misconfiguration", "cwe-16"],
        explanation="The input suggests insecure defaults or exposed services may increase the attack surface.",
        severity_hint="Medium",
        cwe="CWE-16",
        owasp="A05:2021 Security Misconfiguration",
        base_confidence=0.77,
    ),
    Rule(
        category="Vulnerable Dependency",
        patterns=["cve-", "outdated", "vulnerable dependency", "dependency", "library", "patch", "version", "known vulnerability", "fixedversion", "package"],
        explanation="The input suggests a third-party package or component may contain a known vulnerability requiring patching or compensating controls.",
        severity_hint="High",
        cwe="CWE-1104",
        owasp="A06:2021 Vulnerable and Outdated Components",
        base_confidence=0.78,
    ),
    Rule(
        category="Network Exposure",
        patterns=["open port", "listening", "nmap", "service", "exposed service", "publicly reachable", "0.0.0.0", "tcp open"],
        explanation="The input suggests exposed network services that should be reviewed for reachability, patching, and authentication requirements.",
        severity_hint="Medium",
        cwe="CWE-200",
        owasp="A05:2021 Security Misconfiguration",
        base_confidence=0.74,
    ),
]


SEVERITY_ORDER: Dict[str, int] = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _find_reference(text: str, hit: str) -> EvidenceReference:
    lower = text.lower()
    needle = hit.lower().replace("re:", "")
    idx = lower.find(needle) if not needle.startswith("\\") else -1
    if idx < 0:
        # fallback: find first token-sized piece
        tokens = re.findall(r"[a-zA-Z0-9_.:-]{4,}", hit)
        for token in tokens:
            idx = lower.find(token.lower())
            if idx >= 0:
                break
    if idx < 0:
        return EvidenceReference(source="input", locator="matched keyword", excerpt=hit[:180])
    line_no = text[:idx].count("\n") + 1
    return EvidenceReference(source="input", locator=f"line {line_no}", excerpt=safe_excerpt(text, idx, window=110))


def detect_findings(text: str) -> List[VulnerabilityFinding]:
    findings: List[VulnerabilityFinding] = []
    for rule in RULES:
        hits = keyword_hits(text, rule.patterns)
        if not hits:
            continue
        weak_generic = {"Cross-Site Scripting", "Insecure Configuration", "Vulnerable Dependency", "Network Exposure"}
        if rule.category in weak_generic and len(hits) < 2:
            continue
        if rule.category == "Broken Access Control" and len(hits) < 2 and not any(h in {"admin", "overly broad", "broad privilege", "broad privileges", "cwe-284"} for h in hits):
            continue
        if rule.category == "Credential Exposure" and len(hits) < 2 and not any(h in {"secret", "secrets", "api key", "private key", "hardcoded", "token"} for h in hits):
            continue
        evidence_refs = [_find_reference(text, hit) for hit in hits[:5]]
        confidence = min(0.98, rule.base_confidence + 0.03 * max(0, len(hits) - 1))
        findings.append(
            VulnerabilityFinding(
                category=rule.category,
                severity_hint=rule.severity_hint,
                evidence=hits[:8],
                evidence_refs=evidence_refs,
                explanation=rule.explanation,
                cwe=rule.cwe,
                owasp=rule.owasp,
                confidence=round(confidence, 2),
            )
        )

    if not findings:
        findings.append(
            VulnerabilityFinding(
                category="Security Review Required",
                severity_hint="Medium",
                evidence=[],
                evidence_refs=[EvidenceReference(source="input", locator="document", excerpt=text[:220].replace("\n", " "))] if text.strip() else [],
                explanation="The input does not match a high-confidence built-in rule. A manual security review or LLM-assisted analysis is recommended.",
                confidence=0.45,
            )
        )
    return findings
