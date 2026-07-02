from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.schemas.analysis import AnalysisResponse, RemediationTicketResponse


def build_remediation_ticket(analysis: AnalysisResponse, finding_index: int = 0, owner: str = "Security Team", due_days: int = 7) -> RemediationTicketResponse:
    if not analysis.findings:
        raise ValueError("Analysis has no findings")
    finding_index = max(0, min(finding_index, len(analysis.findings) - 1))
    finding = analysis.findings[finding_index]
    due = (datetime.now(timezone.utc) + timedelta(days=due_days)).date().isoformat()
    title = f"[{analysis.risk.severity}] Fix {finding.category}: {analysis.title}"
    evidence_lines = "\n".join([f"- {ref.locator}: {ref.excerpt}" for ref in finding.evidence_refs]) or "- Manual validation required."
    body = f"""## Summary
SecureAI Sentinel detected **{finding.category}** in **{analysis.title}**.

## Risk
- Severity: **{analysis.risk.severity}**
- Score: **{analysis.risk.score}/100**
- Priority: **{analysis.risk.priority}**
- SLA: **{analysis.risk.remediation_sla}**
- Due date target: **{due}**

## Finding Details
- CWE: {finding.cwe or 'N/A'}
- OWASP: {finding.owasp or 'N/A'}
- Confidence: {finding.confidence:.2f}
- Explanation: {finding.explanation}

## Evidence
{evidence_lines}

## Recommended Fixes
"""
    for item in analysis.defenses[:8]:
        body += f"- [ ] {item}\n"
    body += "\n## Validation Checklist\n- [ ] Confirm exploitability in a controlled test environment.\n- [ ] Deploy remediation.\n- [ ] Retest the affected asset.\n- [ ] Mark finding as Fixed or Accepted Risk.\n"
    labels = ["security", f"severity:{analysis.risk.severity.lower()}", f"priority:{analysis.risk.priority.lower()}", finding.category.lower().replace(" ", "-")]
    return RemediationTicketResponse(title=title, body_markdown=body, labels=labels, assignee=owner)
