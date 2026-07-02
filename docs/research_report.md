# SecureAI Sentinel Research-Style Project Report

## Abstract

SecureAI Sentinel is an AI-assisted vulnerability triage and remediation platform that combines scanner report parsing, local retrieval-augmented generation, deterministic multi-agent analysis, CVSS-style risk scoring, workspace storage, and remediation ticket generation. The system is designed to support the early stages of security review by transforming raw vulnerability reports into structured findings, risk summaries, attack paths, mitigation plans, and analyst-ready reports.

## Motivation

Security teams often receive large volumes of vulnerability data from tools such as OWASP ZAP, Trivy, Semgrep, Nmap, and CSV-based internal trackers. These outputs can be noisy, duplicated, and difficult to prioritize. SecureAI Sentinel explores how AI-assisted workflows can help reduce triage time while keeping human analysts in control.

## System Design

The project uses a hybrid architecture. Scanner reports are parsed into normalized text and evidence snippets. A local RAG module retrieves relevant cybersecurity knowledge from OWASP-style notes, MITRE ATT&CK notes, and CVE-style examples. A multi-agent pipeline performs vulnerability classification, risk scoring, attack path reasoning, defense recommendation, and report generation.

The risk engine produces a CVSS-style vector and business priority. The UI supports finding status updates such as Confirmed, False Positive, Accepted Risk, Fixed, and Needs Review. SQLite workspaces allow users to save and reload analyses.

## Evaluation

The project includes a small curated benchmark of eight vulnerability cases covering SQL Injection, Cross-Site Scripting, Weak Authentication, Server-Side Request Forgery, Path Traversal, Remote Code Execution, Insecure Configuration, and Vulnerable Dependency scenarios. This benchmark is used as a regression test to verify that category detection and severity classification remain stable during development.

The benchmark is intentionally limited and should not be interpreted as a real-world accuracy claim. Future evaluation should include larger datasets, manually labeled scanner reports, and expert review of false positives and false negatives.

## Results

In local testing, the system successfully processed manual vulnerability descriptions and sample scanner reports, including ZAP JSON, Trivy JSON, Semgrep JSON, Nmap XML, and generic CSV. It generated structured findings, risk scores, evidence references, CVSS-style vectors, remediation actions, tickets, and Markdown/JSON reports.

## Limitations

The current knowledge base is compact and should be expanded before real operational use. The risk scoring engine is CVSS-style rather than a full CVSS implementation. The benchmark is small and curated. Findings require manual analyst validation before production decisions.

## Future Work

Future improvements include full CVSS 3.1/4.0 scoring, Jira/GitHub Issues integration, authentication, multi-user roles, a larger cybersecurity knowledge base, vector database support, and evaluation on larger real-world scanner datasets.
