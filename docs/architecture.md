# SecureAI Sentinel Architecture

SecureAI Sentinel is a practical AI-assisted vulnerability triage platform. The system is designed around a hybrid architecture: deterministic security rules provide repeatable evidence-based detection, local RAG retrieves cybersecurity context, and optional LLM augmentation can improve narrative explanations without replacing the rule-based risk engine.

## High-level architecture

```text
React Dashboard
    │
    │ HTTP / JSON
    ▼
FastAPI Backend
    │
    ├── File Parser and Scanner Normalizer
    │       ├── Text / Markdown / Log
    │       ├── PDF
    │       ├── OWASP ZAP JSON
    │       ├── Trivy JSON
    │       ├── Semgrep JSON
    │       ├── Nmap XML
    │       └── Generic CSV / JSON / XML
    │
    ├── Local RAG Knowledge Retrieval
    │       ├── OWASP-style notes
    │       ├── MITRE ATT&CK notes
    │       └── CVE-style examples
    │
    ├── Multi-Agent Orchestrator
    │       ├── Vulnerability Analyst Agent
    │       ├── Risk Scoring Agent
    │       ├── Attack Path Agent
    │       ├── Defense Recommendation Agent
    │       └── Report Writer Agent
    │
    ├── SQLite Workspace Storage
    │       ├── Projects
    │       ├── Saved analyses
    │       └── Finding status updates
    │
    └── Outputs
            ├── UI dashboard response
            ├── Markdown report
            ├── JSON result
            └── Remediation ticket
```

## Frontend

The frontend is a React/Vite dashboard. It provides manual text analysis, sample case loading, scanner file upload, workspace management, finding status updates, remediation ticket creation, benchmark execution, and report downloads.

## Backend

The backend is built with FastAPI and Pydantic. It exposes endpoints for analysis, file analysis, benchmark execution, project creation, saved analysis loading, finding status updates, and ticket generation.

## File ingestion

The parser layer converts scanner-specific formats into a normalized text representation. This allows the rest of the pipeline to operate on a consistent input shape while still preserving evidence snippets and source metadata.

## RAG layer

The local RAG layer uses TF-IDF retrieval over a compact cybersecurity knowledge base. It retrieves relevant OWASP, MITRE ATT&CK, and CVE-style notes. The goal is not to replace a production vector database, but to demonstrate grounded retrieval and avoid pure free-form generation.

## Multi-agent pipeline

1. **Vulnerability Analyst Agent** identifies vulnerability categories and supporting evidence.
2. **Risk Scoring Agent** assigns severity, score, priority, SLA, and CVSS-style vector.
3. **Attack Path Agent** builds an analyst-friendly exploitation sequence.
4. **Defense Recommendation Agent** generates mitigation and validation actions.
5. **Report Writer Agent** compiles the result into a Markdown report.

## Storage

SQLite stores project workspaces and saved analyses. This turns the system from a stateless AI demo into a lightweight vulnerability management workflow.

## Design principle

The core safety design is to keep high-impact decisions deterministic and evidence-driven. The optional LLM is used for explanation quality, while the parser, rule engine, risk scoring, and evidence references remain the guardrails.
