# GitHub Release Checklist

## Before upload

- [ ] Use the cleaned GitHub-ready folder, not a folder containing `node_modules`.
- [ ] Confirm `.gitignore` excludes `.venv`, `node_modules`, `__pycache__`, `.db`, and local environment files.
- [ ] Add 4–6 screenshots to `assets/screenshots/`.
- [ ] Update screenshot links in README if needed.
- [ ] Run backend and frontend locally.
- [ ] Test one manual case and one scanner sample.
- [ ] Run benchmark.
- [ ] Confirm Markdown and JSON export work.

## Recommended screenshots

1. Dashboard home with SQL Injection analysis.
2. Detected findings and CVSS-style risk vector.
3. Scanner CSV or Trivy report upload result.
4. Workspace saved analysis history.
5. Remediation ticket export.
6. Benchmark results.

## Suggested repository description

AI-assisted vulnerability triage and remediation platform with FastAPI, React, local RAG, scanner parsers, CVSS-style risk scoring, SQLite workspaces, and ticket export.

## Suggested GitHub topics

```text
ai-security
cybersecurity
vulnerability-management
rag
multi-agent
fastapi
react
owasp
mitre-attack
cvss
security-automation
```
