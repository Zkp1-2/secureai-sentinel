from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    title: Optional[str] = Field(default="Untitled Security Case")
    text: str = Field(..., min_length=20)
    use_llm: Optional[bool] = Field(default=None, description="Override USE_LLM from environment for this request")


class RetrievedKnowledge(BaseModel):
    source: str
    section: str = "General"
    score: float
    content: str


class EvidenceReference(BaseModel):
    source: str = "input"
    locator: str = "text"
    excerpt: str


class VulnerabilityFinding(BaseModel):
    category: str
    severity_hint: str = "Medium"
    evidence: List[str] = Field(default_factory=list)
    evidence_refs: List[EvidenceReference] = Field(default_factory=list)
    explanation: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: float = 0.75
    status: str = "Needs Review"
    remediation_owner: Optional[str] = None


class CvssLikeVector(BaseModel):
    attack_vector: str = "Unknown"
    attack_complexity: str = "Unknown"
    privileges_required: str = "Unknown"
    user_interaction: str = "Unknown"
    confidentiality: str = "Unknown"
    integrity: str = "Unknown"
    availability: str = "Unknown"
    exploitability: str = "Unknown"
    business_impact: str = "Unknown"


class RiskScore(BaseModel):
    score: int
    severity: str
    rationale: str
    drivers: List[str] = Field(default_factory=list)
    vector: CvssLikeVector = Field(default_factory=CvssLikeVector)
    priority: str = "P3"
    remediation_sla: str = "Review in 14 days"


class AgentTrace(BaseModel):
    agent: str
    mode: str
    output_summary: str


class EvaluationSignals(BaseModel):
    retrieval_coverage: float
    hallucination_guardrail: str
    consistency_note: str
    confidence: float


class ScannerFinding(BaseModel):
    scanner: str
    name: str
    severity: str = "Unknown"
    description: str = ""
    evidence: str = ""
    location: str = ""
    recommendation: str = ""


class AnalysisResponse(BaseModel):
    title: str
    summary: str
    findings: List[VulnerabilityFinding]
    risk: RiskScore
    attack_path: List[str]
    defenses: List[str]
    executive_actions: List[str]
    final_report: str
    retrieved_knowledge: List[RetrievedKnowledge]
    evaluation: EvaluationSignals
    traces: List[AgentTrace]
    metadata: Dict[str, Any]


class BenchmarkCase(BaseModel):
    id: str
    title: str
    text: str
    expected_categories: List[str]
    expected_min_severity: str


class BenchmarkResult(BaseModel):
    case_id: str
    title: str
    expected_categories: List[str]
    detected_categories: List[str]
    category_recall: float
    expected_min_severity: str
    predicted_severity: str
    severity_pass: bool
    risk_score: int


class BenchmarkResponse(BaseModel):
    total_cases: int
    average_category_recall: float
    severity_pass_rate: float
    results: List[BenchmarkResult]


class ProjectCreateRequest(BaseModel):
    name: str = Field(..., min_length=2)
    description: str = ""


class ProjectResponse(BaseModel):
    id: int
    name: str
    description: str = ""
    created_at: str


class SaveAnalysisRequest(BaseModel):
    project_id: int
    analysis: AnalysisResponse


class SavedAnalysisResponse(BaseModel):
    id: int
    project_id: int
    title: str
    severity: str
    score: int
    created_at: str


class FindingStatusRequest(BaseModel):
    analysis_id: int
    finding_index: int
    status: str = Field(..., description="Confirmed, False Positive, Accepted Risk, Fixed, Needs Review")
    owner: Optional[str] = None


class RemediationTicketRequest(BaseModel):
    analysis: AnalysisResponse
    finding_index: int = 0
    owner: str = "Security Team"
    due_days: int = 7


class RemediationTicketResponse(BaseModel):
    title: str
    body_markdown: str
    labels: List[str]
    assignee: str
