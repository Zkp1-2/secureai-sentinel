from __future__ import annotations

from typing import List

from app.agents.rule_engine import SEVERITY_ORDER
from app.schemas.analysis import CvssLikeVector, RiskScore, VulnerabilityFinding


class RiskScoringAgent:
    name = "Risk Scoring Agent"

    def score(self, findings: List[VulnerabilityFinding], text: str) -> RiskScore:
        lower = text.lower()
        # Avoid high scores for generic/manual review results unless impact indicators exist.
        is_review_only = len(findings) == 1 and findings[0].category == "Security Review Required"
        max_hint = max((SEVERITY_ORDER.get(f.severity_hint, 2) for f in findings), default=2)
        score = 24 + max_hint * 12
        drivers: List[str] = []

        if len(findings) >= 2 and not is_review_only:
            score += 8
            drivers.append("multiple security weaknesses appear in the same case")
        if any(term in lower for term in ["admin", "root", "privilege", "administrator", "broad privileges"]):
            score += 8
            drivers.append("administrative or privileged functionality is affected")
        if any(term in lower for term in ["sensitive", "customer", "user records", "database", "personal", "pii", "token", "session cookie", "secret", "credential", "metadata service"]):
            score += 10
            drivers.append("sensitive data or secrets may be exposed")
        if any(term in lower for term in ["remote", "internet", "unauthenticated", "public", "external", "bypass authentication", "internal endpoint", "metadata service", "cloud metadata", "webhook", "url preview"]):
            score += 9
            drivers.append("remote or unauthenticated exploitation indicators are present")
        if any(term in lower for term in ["rce", "remote code execution", "arbitrary code", "command injection", "execute commands", "deserialization"]):
            score += 12
            drivers.append("potential code execution impact")
        if any(term in lower for term in ["no logging", "no monitoring", "not monitored", "no alert"]):
            score += 4
            drivers.append("weak monitoring may delay detection")
        if any(term in lower for term in ["scanner report type", "zap", "trivy", "nmap", "semgrep", "openvas", "burp"]):
            score += 3
            drivers.append("finding came from a structured security scanner source")

        if is_review_only and not drivers:
            score = min(score, 42)
            drivers.append("manual review is required because no high-confidence vulnerability pattern was detected")

        score = max(1, min(100, score))
        if score >= 90:
            severity = "Critical"
            priority = "P0"
            sla = "Fix or formally accept risk within 24-72 hours"
        elif score >= 68:
            severity = "High"
            priority = "P1"
            sla = "Fix within 7 days"
        elif score >= 45:
            severity = "Medium"
            priority = "P2"
            sla = "Fix or validate within 14-30 days"
        else:
            severity = "Low"
            priority = "P3"
            sla = "Track and review in the next normal hardening cycle"

        if not drivers:
            drivers = ["detected weakness category and available impact indicators"]

        vector = self._build_vector(findings, lower)
        rationale = "Risk score is based on " + ", ".join(drivers) + "."
        return RiskScore(score=score, severity=severity, rationale=rationale, drivers=drivers, vector=vector, priority=priority, remediation_sla=sla)

    def _build_vector(self, findings: List[VulnerabilityFinding], lower: str) -> CvssLikeVector:
        categories = {f.category for f in findings}
        attack_vector = "Network" if any(term in lower for term in ["web", "internet", "public", "remote", "url", "endpoint", "tcp", "http", "api"]) else "Unknown"
        attack_complexity = "Low" if any(cat in categories for cat in ["SQL Injection", "Weak Authentication", "Server-Side Request Forgery", "Remote Code Execution"]) else "Medium"
        privileges_required = "None" if any(term in lower for term in ["unauthenticated", "public", "login form", "webhook", "url preview"]) else ("Low" if "user" in lower else "Unknown")
        user_interaction = "Required" if "browser" in lower or "user" in lower and "click" in lower else "None" if any(cat in categories for cat in ["SQL Injection", "Server-Side Request Forgery", "Remote Code Execution", "Weak Authentication"]) else "Unknown"
        confidentiality = "High" if any(term in lower for term in ["sensitive", "records", "database", "token", "cookie", "credential", "secret", "metadata"]) else "Low"
        integrity = "High" if any(cat in categories for cat in ["SQL Injection", "Remote Code Execution", "Broken Access Control"]) else "Medium"
        availability = "High" if any(cat in categories for cat in ["Remote Code Execution"]) or "denial" in lower else "Low"
        exploitability = "High" if any(term in lower for term in ["unauthenticated", "public", "remote", "brute", "metadata", "bypass"]) else "Medium"
        business_impact = "High" if confidentiality == "High" or any(cat in categories for cat in ["Remote Code Execution", "Credential Exposure", "Weak Authentication"]) else "Medium"
        return CvssLikeVector(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            confidentiality=confidentiality,
            integrity=integrity,
            availability=availability,
            exploitability=exploitability,
            business_impact=business_impact,
        )
