from __future__ import annotations

from typing import Dict, List
from app.schemas.analysis import VulnerabilityFinding


ATTACK_STEPS: Dict[str, List[str]] = {
    "SQL Injection": [
        "Attacker identifies an input that reaches backend SQL query construction.",
        "Attacker submits crafted SQL payloads that alter query logic.",
        "Successful exploitation may bypass authentication, extract records, or modify data.",
    ],
    "Cross-Site Scripting": [
        "Attacker places malicious script in content rendered by the application.",
        "Victim browser executes the script inside the trusted application context.",
        "Attacker may steal session cookies, alter page content, or perform actions as the user.",
    ],
    "Weak Authentication": [
        "Attacker targets login or administrative authentication controls.",
        "Weak password policy, missing MFA, or missing lockout enables repeated guessing or credential reuse.",
        "Successful compromise may lead to account takeover and privileged access.",
    ],
    "Broken Access Control": [
        "Attacker discovers predictable identifiers, weak role checks, or exposed admin functions.",
        "Attacker accesses restricted resources by manipulating requests, roles, or session state.",
        "Successful exploitation may expose sensitive records or enable unauthorized actions.",
    ],
    "Credential Exposure": [
        "Attacker discovers exposed credentials in logs, repositories, configuration files, or responses.",
        "Attacker reuses the credential against internal services, cloud resources, or user accounts.",
        "Successful exploitation may lead to account takeover, lateral movement, or data access.",
    ],
    "Remote Code Execution": [
        "Attacker identifies an input path that reaches command execution, unsafe deserialization, or code loading.",
        "Attacker delivers a payload that executes on the target server.",
        "Successful exploitation may result in full system compromise.",
    ],
    "Server-Side Request Forgery": [
        "Attacker finds a server-side URL fetch, webhook, or preview feature.",
        "Attacker supplies internal or cloud metadata URLs as input.",
        "Successful exploitation may disclose internal data or cloud credentials.",
    ],
    "Path Traversal": [
        "Attacker identifies a file path input used by download or read functions.",
        "Attacker uses traversal sequences to escape the intended directory.",
        "Successful exploitation may disclose source code, credentials, or system files.",
    ],
    "Insecure Configuration": [
        "Attacker scans exposed services, dashboards, or debug endpoints.",
        "Attacker abuses default settings, missing TLS, weak permissions, or open storage.",
        "Successful exploitation may expose data or provide a foothold for deeper compromise.",
    ],
    "Vulnerable Dependency": [
        "Attacker maps exposed software versions or known vulnerable components.",
        "Attacker applies a known exploit path for the vulnerable dependency.",
        "Successful exploitation depends on exploitability, exposure, and available compensating controls.",
    ],
}


class AttackPathAgent:
    name = "Attack Path Agent"

    def build_attack_path(self, findings: List[VulnerabilityFinding]) -> List[str]:
        steps: List[str] = []
        for finding in findings:
            for step in ATTACK_STEPS.get(finding.category, []):
                if step not in steps:
                    steps.append(step)
        if not steps:
            steps = [
                "Analyst reviews the security case and identifies exposed assets, trust boundaries, and possible entry points.",
                "Analyst validates whether the issue is externally reachable, requires authentication, or affects sensitive data.",
                "Analyst prioritizes remediation based on exploitability and business impact.",
            ]
        return steps[:12]
