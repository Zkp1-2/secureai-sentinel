from __future__ import annotations

import json
from pathlib import Path
from typing import List

from app.schemas.analysis import BenchmarkCase, BenchmarkResponse, BenchmarkResult
from app.services.orchestrator import SecurityAnalysisOrchestrator

SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
DEFAULT_CASES_PATH = Path(__file__).resolve().parents[3] / "experiments" / "evaluation_cases.json"


def load_cases(path: Path = DEFAULT_CASES_PATH) -> List[BenchmarkCase]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [BenchmarkCase(**item) for item in payload]


def run_benchmark(orchestrator: SecurityAnalysisOrchestrator | None = None, use_llm: bool | None = False) -> BenchmarkResponse:
    orchestrator = orchestrator or SecurityAnalysisOrchestrator()
    cases = load_cases()
    results: List[BenchmarkResult] = []
    for case in cases:
        response = orchestrator.analyze(case.title, case.text, use_llm=use_llm)
        detected = sorted({finding.category for finding in response.findings})
        expected = set(case.expected_categories)
        recall = len(expected.intersection(detected)) / max(1, len(expected))
        severity_pass = SEVERITY_ORDER.get(response.risk.severity, 0) >= SEVERITY_ORDER.get(case.expected_min_severity, 0)
        results.append(
            BenchmarkResult(
                case_id=case.id,
                title=case.title,
                expected_categories=case.expected_categories,
                detected_categories=detected,
                category_recall=round(recall, 2),
                expected_min_severity=case.expected_min_severity,
                predicted_severity=response.risk.severity,
                severity_pass=severity_pass,
                risk_score=response.risk.score,
            )
        )
    avg_recall = sum(r.category_recall for r in results) / max(1, len(results))
    severity_pass_rate = sum(1 for r in results if r.severity_pass) / max(1, len(results))
    return BenchmarkResponse(
        total_cases=len(results),
        average_category_recall=round(avg_recall, 2),
        severity_pass_rate=round(severity_pass_rate, 2),
        results=results,
    )
