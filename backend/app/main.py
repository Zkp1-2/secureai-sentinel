from __future__ import annotations

from typing import List
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.evaluation.benchmark import run_benchmark
from app.rag.knowledge_base import LocalRAGKnowledgeBase
from app.schemas.analysis import (
    AnalysisRequest,
    AnalysisResponse,
    BenchmarkResponse,
    FindingStatusRequest,
    ProjectCreateRequest,
    ProjectResponse,
    RemediationTicketRequest,
    RemediationTicketResponse,
    SaveAnalysisRequest,
    SavedAnalysisResponse,
)
from app.services.orchestrator import SecurityAnalysisOrchestrator
from app.services.storage import StorageService
from app.services.tickets import build_remediation_ticket
from app.utils.file_parser import parse_uploaded_file

app = FastAPI(
    title="SecureAI Sentinel API",
    description="Practical Multi-Agent AI Vulnerability Triage Platform with local RAG, scanner parsing, CVSS-style scoring, ticket export, and workspace storage.",
    version="3.2.5",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = SecurityAnalysisOrchestrator()
storage = StorageService()


@app.get("/")
def root():
    return {
        "project": "SecureAI Sentinel",
        "status": "running",
        "version": "v3.2.5-ui-stable",
        "features": [
            "multi-agent",
            "local-rag",
            "optional-llm",
            "scanner-report-parsing",
            "cvss-style-risk-scoring",
            "finding-workspace",
            "remediation-ticket-export",
            "benchmark",
        ],
    }


@app.get("/health")
def health():
    return {"status": "ok", "version": "3.2.5"}


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze(request: AnalysisRequest):
    return orchestrator.analyze(
        title=request.title or "Untitled Security Case",
        text=request.text,
        use_llm=request.use_llm,
        source_metadata={"parser": "manual-text"},
    )


@app.post("/api/analyze-file", response_model=AnalysisResponse)
async def analyze_file(file: UploadFile = File(...), use_llm: bool | None = None):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    raw = await file.read()
    try:
        parsed = parse_uploaded_file(file.filename, raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if len(parsed.text.strip()) < 20:
        raise HTTPException(status_code=400, detail="File content is too short for analysis")
    return orchestrator.analyze(title=parsed.title, text=parsed.text, use_llm=use_llm, source_metadata=parsed.metadata)


@app.post("/api/knowledge/reload")
def reload_knowledge_base():
    orchestrator.knowledge_base = LocalRAGKnowledgeBase()
    return {"status": "reloaded", "documents": len(orchestrator.knowledge_base.documents)}


@app.get("/api/benchmark", response_model=BenchmarkResponse)
def benchmark(use_llm: bool = False):
    return run_benchmark(orchestrator=orchestrator, use_llm=use_llm)


@app.post("/api/projects", response_model=ProjectResponse)
def create_project(request: ProjectCreateRequest):
    return storage.create_project(request.name, request.description)


@app.get("/api/projects", response_model=List[ProjectResponse])
def list_projects():
    return storage.list_projects()


@app.post("/api/analyses", response_model=SavedAnalysisResponse)
def save_analysis(request: SaveAnalysisRequest):
    try:
        return storage.save_analysis(request.project_id, request.analysis)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/analyses")
def list_analyses(project_id: int | None = None):
    return storage.list_analyses(project_id=project_id)


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: int):
    try:
        return storage.get_analysis_payload(analysis_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/findings/status")
def update_finding_status(request: FindingStatusRequest):
    try:
        return storage.update_finding_status(request.analysis_id, request.finding_index, request.status, request.owner)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/tickets/remediation", response_model=RemediationTicketResponse)
def remediation_ticket(request: RemediationTicketRequest):
    try:
        return build_remediation_ticket(request.analysis, request.finding_index, request.owner, request.due_days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
