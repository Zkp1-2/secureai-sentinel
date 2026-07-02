from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.agents.attack_path import AttackPathAgent
from app.agents.defense import DefenseAgent
from app.agents.report_writer import ReportWriterAgent
from app.agents.risk_scoring import RiskScoringAgent
from app.agents.vulnerability_analyst import VulnerabilityAnalystAgent
from app.rag.knowledge_base import LocalRAGKnowledgeBase
from app.schemas.analysis import (
    AgentTrace,
    AnalysisResponse,
    EvaluationSignals,
    RetrievedKnowledge,
    RiskScore,
    VulnerabilityFinding,
)
from app.services.llm_client import LLMClient
from app.utils.text import clean_text


class SecurityAnalysisOrchestrator:
    """Coordinates RAG retrieval, multi-agent analysis, optional LLM augmentation, and report generation."""

    def __init__(self) -> None:
        self.vulnerability_agent = VulnerabilityAnalystAgent()
        self.risk_agent = RiskScoringAgent()
        self.attack_agent = AttackPathAgent()
        self.defense_agent = DefenseAgent()
        self.report_agent = ReportWriterAgent()
        self.knowledge_base = LocalRAGKnowledgeBase()
        self.llm = LLMClient()

    def analyze(self, title: str, text: str, use_llm: bool | None = None, source_metadata: Dict[str, Any] | None = None) -> AnalysisResponse:
        cleaned = clean_text(text)
        retrieved = [RetrievedKnowledge(**item) for item in self.knowledge_base.search(cleaned, top_k=5)]

        findings = self.vulnerability_agent.analyze(cleaned)
        risk = self.risk_agent.score(findings, cleaned)
        attack_path = self.attack_agent.build_attack_path(findings)
        defenses = self.defense_agent.recommend(findings, risk)
        executive_actions = self.defense_agent.executive_actions(findings, risk)
        traces: List[AgentTrace] = [
            AgentTrace(agent=self.vulnerability_agent.name, mode="rule+rAG", output_summary=f"Detected {len(findings)} finding(s)."),
            AgentTrace(agent=self.risk_agent.name, mode="cvss-style-rule", output_summary=f"Risk {risk.severity} {risk.score}/100, {risk.priority}."),
            AgentTrace(agent=self.attack_agent.name, mode="template", output_summary=f"Generated {len(attack_path)} attack-path step(s)."),
            AgentTrace(agent=self.defense_agent.name, mode="template", output_summary=f"Generated {len(defenses)} defense recommendation(s)."),
        ]

        llm_result = self._run_llm(cleaned, findings, risk, retrieved, use_llm)
        llm_mode = "disabled"
        llm_error = None
        if llm_result.enabled and llm_result.parsed_json:
            llm_mode = f"{llm_result.provider}:{llm_result.model}"
            findings, risk, attack_path, defenses, executive_actions = self._merge_llm_output(
                llm_result.parsed_json, findings, risk, attack_path, defenses, executive_actions
            )
            traces.append(AgentTrace(agent="LLM Augmentation Agent", mode=llm_mode, output_summary="LLM JSON output merged into analysis."))
        elif llm_result.error:
            llm_error = llm_result.error
            llm_mode = f"fallback_after_{llm_result.provider}_error"
            traces.append(AgentTrace(agent="LLM Augmentation Agent", mode=llm_mode, output_summary=llm_result.error[:180]))

        categories = ", ".join(sorted({finding.category for finding in findings}))
        summary = (
            f"The submitted case appears to involve {categories}. "
            f"SecureAI Sentinel assessed the case as {risk.severity} risk with a score of {risk.score}/100 ({risk.priority}). "
            f"The analysis combines local RAG context, evidence references, CVSS-style scoring, and "
            f"{'LLM augmentation' if llm_result.enabled and llm_result.parsed_json else 'deterministic multi-agent rules'} for a reproducible security review."
        )
        evaluation = self._evaluate(findings, retrieved, llm_result.enabled and llm_result.parsed_json)
        final_report = self.report_agent.write(
            title=title,
            summary=summary,
            findings=findings,
            risk=risk,
            attack_path=attack_path,
            defenses=defenses,
            executive_actions=executive_actions,
            retrieved_knowledge=retrieved,
            evaluation=evaluation,
        )
        traces.append(AgentTrace(agent=self.report_agent.name, mode="structured-markdown", output_summary="Generated final Markdown report."))

        return AnalysisResponse(
            title=title,
            summary=summary,
            findings=findings,
            risk=risk,
            attack_path=attack_path,
            defenses=defenses,
            executive_actions=executive_actions,
            final_report=final_report,
            retrieved_knowledge=retrieved,
            evaluation=evaluation,
            traces=traces,
            metadata={
                "version": "v3.2.5-ui-stable",
                "analysis_time_utc": datetime.now(timezone.utc).isoformat(),
                "pipeline": [trace.agent for trace in traces],
                "llm_mode": llm_mode,
                "llm_error": llm_error,
                "input_chars": len(cleaned),
                "input_preview": cleaned[:800],
                "source": source_metadata or {"parser": "manual-text"},
            },
        )

    def _run_llm(self, text: str, findings: List[VulnerabilityFinding], risk: RiskScore, retrieved: List[RetrievedKnowledge], use_llm: bool | None):
        context = "\n\n".join([f"[{item.source} / {item.section}] {item.content}" for item in retrieved])
        preliminary = {
            "findings": [f.model_dump() for f in findings],
            "risk": risk.model_dump(),
        }
        system_prompt = (
            "You are SecureAI Sentinel, a defensive AI security analyst. "
            "Analyze only for risk assessment, mitigation, and reporting. Do not provide exploit payloads, malware code, or step-by-step offensive instructions. "
            "Return strict JSON only. Preserve evidence references when possible."
        )
        user_prompt = f"""
Security case excerpt:
{text[:5000]}

Retrieved cybersecurity knowledge:
{context[:5000]}

Preliminary deterministic analysis:
{json.dumps(preliminary, indent=2)}

Return JSON with this schema:
{{
  "findings": [{{"category": "...", "severity_hint": "Low|Medium|High|Critical", "evidence": ["..."], "explanation": "...", "cwe": "...", "owasp": "...", "confidence": 0.0}}],
  "risk": {{"score": 1-100, "severity": "Low|Medium|High|Critical", "rationale": "...", "drivers": ["..."], "priority": "P0|P1|P2|P3", "remediation_sla": "..."}},
  "attack_path": ["high-level defensive attack path step, no payloads"],
  "defenses": ["specific defensive remediation"],
  "executive_actions": ["manager-friendly action"]
}}
"""
        return self.llm.analyze_json(system_prompt, user_prompt, request_override=use_llm)

    def _merge_llm_output(
        self,
        payload: Dict[str, Any],
        findings: List[VulnerabilityFinding],
        risk: RiskScore,
        attack_path: List[str],
        defenses: List[str],
        executive_actions: List[str],
    ):
        try:
            llm_findings = [VulnerabilityFinding(**item) for item in payload.get("findings", []) if isinstance(item, dict)]
            if llm_findings:
                # Keep deterministic evidence_refs if LLM did not provide them.
                for idx, lf in enumerate(llm_findings):
                    if idx < len(findings) and not lf.evidence_refs:
                        lf.evidence_refs = findings[idx].evidence_refs
                findings = llm_findings[:8]
        except Exception:
            pass
        try:
            if isinstance(payload.get("risk"), dict):
                risk_payload = {**risk.model_dump(), **payload["risk"]}
                risk = RiskScore(**risk_payload)
        except Exception:
            pass
        for field_name, current in [
            ("attack_path", attack_path),
            ("defenses", defenses),
            ("executive_actions", executive_actions),
        ]:
            values = payload.get(field_name)
            if isinstance(values, list) and values and all(isinstance(v, str) for v in values):
                if field_name == "attack_path":
                    attack_path = values[:12]
                elif field_name == "defenses":
                    defenses = values[:12]
                elif field_name == "executive_actions":
                    executive_actions = values[:8]
        return findings, risk, attack_path, defenses, executive_actions

    def _evaluate(self, findings: List[VulnerabilityFinding], retrieved: List[RetrievedKnowledge], used_llm: bool) -> EvaluationSignals:
        category_aliases = {
            "Cross-Site Scripting": ["xss", "cross-site", "scripting", "javascript", "stored xss"],
            "SQL Injection": ["sql", "injection", "database", "query"],
            "Server-Side Request Forgery": ["ssrf", "server-side", "request", "forgery", "metadata"],
            "Weak Authentication": ["authentication", "mfa", "password", "login"],
            "Remote Code Execution": ["remote code", "execution", "deserialization", "command"],
            "Broken Access Control": ["access control", "authorization", "privilege"],
            "Credential Exposure": ["credential", "secret", "token", "password"],
            "Path Traversal": ["path", "traversal", "file"],
            "Vulnerable Dependency": ["dependency", "cve", "package", "component"],
            "Insecure Configuration": ["configuration", "misconfiguration", "debug", "open port"],
            "Network Exposure": ["network", "open port", "service"],
        }
        tokens: List[str] = []
        for finding in findings:
            tokens.extend(category_aliases.get(finding.category, finding.category.lower().split()))
            tokens.extend([e.lower() for e in finding.evidence[:4]])
        retrieved_text = " ".join((item.section + " " + item.content).lower() for item in retrieved)
        if tokens:
            overlap = sum(1 for token in set(tokens) if token and token in retrieved_text)
            coverage = min(1.0, overlap / max(1, min(len(set(tokens)), 5)))
        else:
            coverage = 0.0
        avg_conf = sum(f.confidence for f in findings) / max(1, len(findings))
        if retrieved and coverage > 0:
            guardrail = "Report is grounded with retrieved local knowledge snippets and evidence references. Manual validation is still required."
        elif retrieved:
            guardrail = "Knowledge was retrieved, but semantic overlap is weak; treat output as preliminary and validate manually."
        else:
            guardrail = "No knowledge context retrieved; treat output as preliminary and validate manually."
        consistency_note = "Deterministic rule mode provides repeatable output." if not used_llm else "LLM mode may vary slightly; benchmark multiple runs for consistency."
        return EvaluationSignals(
            retrieval_coverage=round(coverage, 2),
            hallucination_guardrail=guardrail,
            consistency_note=consistency_note,
            confidence=round(avg_conf, 2),
        )
