# SecureAI Sentinel Demo Script

## 2-minute version

Hi, this is SecureAI Sentinel, an AI-assisted vulnerability triage and remediation platform.

The goal of this project is to automate the first stage of security review. A user can paste a vulnerability description or upload scanner outputs from tools like OWASP ZAP, Trivy, Semgrep, Nmap, or a generic CSV vulnerability tracker.

The system parses the input, extracts evidence, retrieves relevant cybersecurity knowledge using local RAG, and runs a multi-agent pipeline. The agents classify vulnerabilities, score risk, reason about potential attack paths, generate defensive recommendations, and produce an analyst-ready report.

Here I am uploading a sample scanner report. The platform identifies multiple findings, assigns a critical risk score, generates a CVSS-style vector, and provides remediation actions. It also lets the analyst mark findings as Confirmed, False Positive, Accepted Risk, Fixed, or Needs Review.

This project is not just a chatbot. It is a structured AI security workflow with scanner parsing, evidence references, risk scoring, workspace storage, remediation ticket export, and benchmark testing.

It demonstrates my interest in AI Security, LLM for Cybersecurity, secure software engineering, and automated vulnerability analysis.

## Demo checklist

1. Open dashboard.
2. Run SQL Injection sample.
3. Show findings, risk score, CVSS-style vector, attack path, and defense recommendations.
4. Create a remediation ticket.
5. Save analysis to workspace.
6. Upload `generic_vulns.csv` or `trivy_sample.json`.
7. Show scanner parser label and extracted findings.
8. Download Markdown and JSON report.
9. Run benchmark.
