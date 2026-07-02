# SecureAI Sentinel

**AI-assisted vulnerability triage and remediation platform** built with FastAPI, React, local RAG, scanner parsers, CVSS-style risk scoring, workspace storage, and remediation ticket export.

SecureAI Sentinel is designed for AI Security, LLM-for-Cybersecurity, and secure software engineering portfolios. It converts raw vulnerability descriptions or scanner outputs into structured security findings, risk scores, attack paths, mitigation plans, and analyst-ready reports.

> Status: Stable practical portfolio version. This is an AI-assisted prototype, not a replacement for qualified security review.

---

## Demo workflow

```text
Security text / PDF / scanner report
        ↓
Parser and scanner normalizer
        ↓
Evidence extraction
        ↓
Local RAG cybersecurity knowledge retrieval
        ↓
Multi-agent analysis pipeline
        ↓
Risk score + CVSS-style vector + priority/SLA
        ↓
Attack path + defense recommendations
        ↓
Markdown/JSON report + remediation ticket
        ↓
SQLite workspace history and finding status tracking
```

---

## Key features

### AI security analysis

- Multi-agent workflow:
  - Vulnerability Analyst Agent
  - Risk Scoring Agent
  - Attack Path Agent
  - Defense Recommendation Agent
  - Report Writer Agent
- Local RAG retrieval over cybersecurity notes.
- Optional LLM mode through OpenAI-compatible or Ollama-compatible endpoints.
- Hallucination guardrails through deterministic evidence extraction and local knowledge context.

### Practical scanner ingestion

Supported input types:

- Plain text, Markdown, logs
- PDF reports
- JSON reports
- XML reports
- CSV reports

Built-in parser support:

- OWASP ZAP JSON
- Trivy JSON
- Semgrep JSON
- Nmap XML
- Generic vulnerability CSV
- Generic JSON/XML fallback

Sample reports are included in `samples/`.

### Risk triage and analyst workflow

- CVSS-style risk vector:
  - Attack Vector
  - Attack Complexity
  - Privileges Required
  - User Interaction
  - Confidentiality, Integrity, Availability impact
  - Exploitability
  - Business Impact
- Priority mapping: P0, P1, P2, P3
- Recommended remediation SLA
- Finding status workflow:
  - Needs Review
  - Confirmed
  - False Positive
  - Accepted Risk
  - Fixed
- Remediation ticket export as Markdown.
- SQLite workspace with saved analysis history.

### Reporting and evaluation

- Markdown report export.
- JSON result export.
- Internal benchmark for regression testing.
- Evaluation signals:
  - retrieval coverage
  - confidence
  - input parser type
  - agent trace summaries

> Benchmark note: the included benchmark is a small curated regression suite for project validation. It is not a claim of real-world scanner accuracy.

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python, FastAPI, Pydantic |
| Frontend | React, Vite, CSS |
| Retrieval | Local TF-IDF RAG with scikit-learn |
| Storage | SQLite |
| Parsing | JSON, CSV, XML, PDF parser |
| Optional LLM | OpenAI-compatible API or Ollama-compatible API |
| Deployment | Docker Compose |

---

## Project structure

```text
secureai-sentinel/
├── backend/
│   ├── app/
│   │   ├── agents/          # analysis agents and rule engine
│   │   ├── evaluation/      # benchmark logic
│   │   ├── rag/             # local knowledge retrieval
│   │   ├── schemas/         # Pydantic models
│   │   ├── services/        # orchestrator, storage, tickets, LLM client
│   │   └── utils/           # file parser and text utilities
│   ├── data/knowledge_base/ # OWASP/MITRE/CVE-style local notes
│   ├── requirements.txt
│   └── run_benchmark.py
├── frontend/
│   ├── src/
│   │   ├── main.jsx
│   │   └── style.css
│   ├── package.json
│   └── index.html
├── samples/                 # sample scanner files
├── experiments/             # benchmark cases and results
├── docs/                    # architecture, report, demo, CV/SOP material
├── docker-compose.yml
└── README.md
```

---

## Quick start on Windows PowerShell

### Backend

```powershell
cd "D:\SecureAI Sentinel\secureai-sentinel-github-ready\backend"
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

If activation fails, run directly through the virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Backend URL:

```text
http://127.0.0.1:8000
```

### Frontend

Open a second terminal:

```powershell
cd "D:\SecureAI Sentinel\secureai-sentinel-github-ready\frontend"
npm install
npm run dev
```

Frontend URL:

```text
http://127.0.0.1:5173
```

---

## Docker Compose

```bash
docker compose up --build
```

Backend: `http://127.0.0.1:8000`  
Frontend: `http://127.0.0.1:5173`

---

## How to test

1. Run the backend and frontend.
2. Use built-in sample buttons:
   - SQL Injection
   - XSS
   - Weak Auth
   - SSRF
   - RCE
   - Trivy JSON
3. Upload files from `samples/`:
   - `zap_sample.json`
   - `trivy_sample.json`
   - `semgrep_sample.json`
   - `nmap_sample.xml`
   - `generic_vulns.csv`
4. Create a workspace project.
5. Save the current analysis.
6. Create a remediation ticket.
7. Download Markdown and JSON reports.
8. Run the benchmark.

---

## Example CV bullet points

- Built a full-stack AI-assisted vulnerability triage platform using FastAPI, React, local RAG, scanner parsers, and CVSS-style risk scoring.
- Implemented automated ingestion for OWASP ZAP, Trivy, Semgrep, Nmap, CSV, PDF, JSON, XML, and text-based vulnerability reports.
- Developed a multi-agent workflow for vulnerability classification, attack path reasoning, mitigation planning, remediation ticket generation, and analyst status tracking.
- Added SQLite-based project workspaces, saved analysis history, Markdown/JSON report export, and an internal benchmark suite for regression testing.

---

## Limitations

- This system is an AI-assisted security triage prototype.
- Findings should be validated by a qualified analyst before production remediation decisions.
- The local RAG knowledge base is intentionally small and should be expanded for real-world use.
- The included benchmark is for regression testing, not broad accuracy claims.

---

## Future work

- Add richer CVSS 3.1/4.0 scoring.
- Add Jira/GitHub Issues API integration.
- Expand the cybersecurity knowledge base.
- Add authentication and multi-user roles.
- Add containerized vector database support.
- Add a larger real-world evaluation dataset.
