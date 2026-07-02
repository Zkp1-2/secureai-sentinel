from __future__ import annotations

from typing import Dict, List
from app.schemas.analysis import VulnerabilityFinding, RiskScore


DEFENSES: Dict[str, List[str]] = {
    "SQL Injection": [
        "Use parameterized queries or prepared statements for all database access.",
        "Validate and normalize input before it reaches query construction logic.",
        "Apply least-privilege database accounts and monitor suspicious query patterns.",
    ],
    "Cross-Site Scripting": [
        "Apply contextual output encoding for HTML, JavaScript, URL, and attribute contexts.",
        "Sanitize rich text using an allowlist-based sanitizer.",
        "Deploy Content Security Policy to reduce script execution impact.",
    ],
    "Weak Authentication": [
        "Enforce MFA for all administrator and high-risk accounts.",
        "Add account lockout or throttling for repeated failed login attempts.",
        "Use strong password policy, breached-password checks, and login anomaly monitoring.",
    ],
    "Broken Access Control": [
        "Enforce server-side authorization checks on every sensitive endpoint.",
        "Use deny-by-default access control and centralized policy enforcement.",
        "Add tests for horizontal and vertical privilege escalation cases.",
    ],
    "Credential Exposure": [
        "Remove secrets from source code, logs, and client-side responses.",
        "Rotate exposed credentials immediately and use a secret manager.",
        "Add secret scanning to CI/CD and repository protection workflows.",
    ],
    "Remote Code Execution": [
        "Remove unsafe command execution, template evaluation, or deserialization paths.",
        "Use strict allowlists for commands, file paths, and data formats.",
        "Isolate services using containers, least privilege, and network restrictions.",
    ],
    "Server-Side Request Forgery": [
        "Validate outbound URL destinations with strict allowlists.",
        "Block access to metadata services and internal networks from application fetchers.",
        "Disable redirects or re-validate each redirect destination.",
    ],
    "Path Traversal": [
        "Normalize and validate paths before file access.",
        "Use allowlisted file identifiers instead of user-controlled paths.",
        "Run file-serving components with least privilege and constrained directories.",
    ],
    "Insecure Configuration": [
        "Disable debug mode and remove default credentials before deployment.",
        "Harden network exposure, storage permissions, TLS, and admin dashboards.",
        "Continuously scan infrastructure for drift and misconfiguration.",
    ],
    "Vulnerable Dependency": [
        "Upgrade vulnerable components to patched versions.",
        "Use SCA scanning in CI/CD and monitor advisories for critical dependencies.",
        "Apply compensating controls when patching cannot happen immediately.",
    ],
}


class DefenseAgent:
    name = "Defense Recommendation Agent"

    def recommend(self, findings: List[VulnerabilityFinding], risk: RiskScore | None = None) -> List[str]:
        recommendations: List[str] = []
        for finding in findings:
            for item in DEFENSES.get(finding.category, []):
                if item not in recommendations:
                    recommendations.append(item)
        if risk and risk.severity in {"High", "Critical"}:
            recommendations.append("Create a remediation ticket with owner, due date, validation steps, retest evidence, and final analyst status.")
        if not recommendations:
            recommendations = [
                "Perform manual validation to confirm exploitability and affected assets.",
                "Document business impact, likelihood, and remediation owner.",
                "Add security tests to prevent recurrence after remediation.",
            ]
        return recommendations[:12]

    def executive_actions(self, findings: List[VulnerabilityFinding], risk: RiskScore) -> List[str]:
        actions = [
            f"Prioritize this case as {risk.severity} based on the current automated analysis.",
            "Validate exploitability in a controlled test environment before production remediation.",
        ]
        if risk.severity in {"Critical", "High"}:
            actions.append("Assign immediate remediation ownership and schedule a retest after fixes are deployed.")
        if any(f.category in {"Credential Exposure", "Weak Authentication"} for f in findings):
            actions.append("Review account activity and rotate any potentially exposed credentials or sessions.")
        return actions
