from __future__ import annotations

import csv
import io
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from app.utils.text import clean_text

SUPPORTED_EXTENSIONS = {".txt", ".md", ".log", ".json", ".csv", ".pdf", ".xml"}


@dataclass
class ParsedUpload:
    title: str
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)


def parse_uploaded_file(filename: str, raw: bytes) -> ParsedUpload:
    suffix = Path(filename).suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{suffix}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}")
    if suffix == ".pdf":
        text = _parse_pdf(raw)
        return ParsedUpload(filename, text, {"parser": "pdf-text", "source_filename": filename})

    text = raw.decode("utf-8", errors="ignore")
    if suffix == ".json":
        return _parse_json_report(filename, text)
    if suffix == ".xml":
        return _parse_xml_report(filename, text)
    if suffix == ".csv":
        return _parse_csv_report(filename, text)
    return ParsedUpload(filename, clean_text(text), {"parser": "plain-text", "source_filename": filename})


def _parse_json_report(filename: str, text: str) -> ParsedUpload:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return ParsedUpload(filename, clean_text(text), {"parser": "json-raw", "source_filename": filename})

    scanner = _detect_json_scanner(obj)
    if scanner == "OWASP ZAP":
        lines, count = _normalize_zap(obj)
    elif scanner == "Trivy":
        lines, count = _normalize_trivy(obj)
    elif scanner == "Semgrep":
        lines, count = _normalize_semgrep(obj)
    else:
        pretty = json.dumps(obj, indent=2, ensure_ascii=False)
        return ParsedUpload(filename, clean_text(pretty), {"parser": "json-generic", "scanner": scanner or "generic-json", "source_filename": filename})
    normalized = "\n".join(lines)
    title = f"{scanner} Scanner Report: {filename}"
    return ParsedUpload(title, clean_text(normalized), {"parser": "scanner-json", "scanner": scanner, "finding_count": count, "source_filename": filename})


def _detect_json_scanner(obj: Any) -> str | None:
    if isinstance(obj, dict):
        if "site" in obj and ("alerts" in obj or any(isinstance(site, dict) and "alerts" in site for site in obj.get("site", []))):
            return "OWASP ZAP"
        if "Results" in obj and isinstance(obj.get("Results"), list):
            return "Trivy"
        if "results" in obj and isinstance(obj.get("results"), list) and any("check_id" in r or "extra" in r for r in obj.get("results", []) if isinstance(r, dict)):
            return "Semgrep"
    return None


def _normalize_zap(obj: Dict[str, Any]) -> tuple[List[str], int]:
    alerts: List[Dict[str, Any]] = []
    if isinstance(obj.get("alerts"), list):
        alerts.extend(obj["alerts"])
    for site in obj.get("site", []) if isinstance(obj.get("site"), list) else []:
        if isinstance(site, dict) and isinstance(site.get("alerts"), list):
            alerts.extend(site["alerts"])
    lines = ["Scanner Report Type: OWASP ZAP", "Source: dynamic application security testing report", ""]
    for idx, alert in enumerate(alerts[:120], 1):
        name = alert.get("name") or alert.get("alert") or "Unnamed ZAP Alert"
        risk = alert.get("riskdesc") or alert.get("risk") or "Unknown"
        desc = _strip_html(alert.get("desc") or alert.get("description") or "")
        solution = _strip_html(alert.get("solution") or "")
        cwe = alert.get("cweid") or alert.get("cwe") or ""
        url = alert.get("url") or ""
        evidence = alert.get("evidence") or ""
        lines += [f"Finding {idx}: {name}", f"Severity: {risk}", f"CWE: CWE-{cwe}" if str(cwe).isdigit() else f"CWE: {cwe}", f"Location: {url}", f"Evidence: {evidence}", f"Description: {desc}", f"Recommendation: {solution}", ""]
    return lines, len(alerts)


def _normalize_trivy(obj: Dict[str, Any]) -> tuple[List[str], int]:
    lines = ["Scanner Report Type: Trivy", "Source: container/dependency vulnerability report", ""]
    count = 0
    for result in obj.get("Results", []) if isinstance(obj.get("Results"), list) else []:
        target = result.get("Target", "unknown target") if isinstance(result, dict) else "unknown target"
        for vuln in result.get("Vulnerabilities", []) if isinstance(result, dict) and isinstance(result.get("Vulnerabilities"), list) else []:
            count += 1
            vid = vuln.get("VulnerabilityID", "Unknown CVE")
            pkg = vuln.get("PkgName", "unknown package")
            severity = vuln.get("Severity", "Unknown")
            title = vuln.get("Title") or vuln.get("Description", "")[:100]
            fixed = vuln.get("FixedVersion", "")
            desc = vuln.get("Description", "")
            lines += [f"Finding {count}: Vulnerable Dependency {vid} in {pkg}", f"Severity: {severity}", f"Location: {target}", f"Package: {pkg}", f"CVE: {vid}", f"Description: {title}. {desc}", f"Recommendation: upgrade {pkg} to fixed version {fixed or 'a patched version'}", ""]
        for misconf in result.get("Misconfigurations", []) if isinstance(result, dict) and isinstance(result.get("Misconfigurations"), list) else []:
            count += 1
            lines += [f"Finding {count}: Insecure Configuration {misconf.get('ID', '')}", f"Severity: {misconf.get('Severity', 'Unknown')}", f"Location: {target}", f"Description: {misconf.get('Title', '')} {misconf.get('Description', '')}", f"Recommendation: {misconf.get('Resolution', 'Harden configuration according to scanner guidance.')}", ""]
    return lines, count


def _normalize_semgrep(obj: Dict[str, Any]) -> tuple[List[str], int]:
    lines = ["Scanner Report Type: Semgrep", "Source: static application security testing report", ""]
    results = obj.get("results", []) if isinstance(obj.get("results"), list) else []
    for idx, finding in enumerate(results[:200], 1):
        extra = finding.get("extra", {}) if isinstance(finding, dict) else {}
        path = finding.get("path", "")
        line = finding.get("start", {}).get("line", "") if isinstance(finding.get("start"), dict) else ""
        lines += [
            f"Finding {idx}: {finding.get('check_id', 'Semgrep Finding')}",
            f"Severity: {extra.get('severity', 'Unknown')}",
            f"Location: {path}:{line}",
            f"Evidence: {extra.get('lines', '')}",
            f"Description: {extra.get('message', '')}",
            f"Recommendation: Review code and apply secure coding guidance for {finding.get('check_id', 'this rule')}.",
            "",
        ]
    return lines, len(results)


def _parse_xml_report(filename: str, text: str) -> ParsedUpload:
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return ParsedUpload(filename, clean_text(text), {"parser": "xml-raw", "source_filename": filename})
    if root.tag.lower().endswith("nmaprun"):
        lines = ["Scanner Report Type: Nmap", "Source: network exposure scan", ""]
        count = 0
        for host in root.findall(".//host"):
            address = "unknown-host"
            addr = host.find("address")
            if addr is not None:
                address = addr.attrib.get("addr", address)
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                count += 1
                service = port.find("service")
                service_name = service.attrib.get("name", "unknown") if service is not None else "unknown"
                product = service.attrib.get("product", "") if service is not None else ""
                portid = port.attrib.get("portid", "")
                proto = port.attrib.get("protocol", "tcp")
                lines += [f"Finding {count}: Open Port {portid}/{proto} {service_name}", "Severity: Medium", f"Location: {address}:{portid}", f"Evidence: tcp open service {service_name} {product}", f"Description: Nmap reports an open {service_name} service on {address}:{portid}.", "Recommendation: confirm business need, restrict exposure, patch service, and enforce authentication/TLS where required.", ""]
        return ParsedUpload(f"Nmap Scanner Report: {filename}", clean_text("\n".join(lines)), {"parser": "scanner-xml", "scanner": "Nmap", "finding_count": count, "source_filename": filename})
    return ParsedUpload(filename, clean_text(text), {"parser": "xml-generic", "source_filename": filename})


def _parse_csv_report(filename: str, text: str) -> ParsedUpload:
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return ParsedUpload(filename, clean_text(text), {"parser": "csv-raw", "source_filename": filename})
    lines = ["Scanner Report Type: Generic CSV", "Source: imported vulnerability tracker or scanner CSV", ""]
    for idx, row in enumerate(rows[:300], 1):
        lower = {str(k).lower().strip(): v for k, v in row.items()}
        name = lower.get("name") or lower.get("title") or lower.get("vulnerability") or lower.get("finding") or f"CSV Finding {idx}"
        severity = lower.get("severity") or lower.get("risk") or lower.get("priority") or "Unknown"
        desc = lower.get("description") or lower.get("details") or lower.get("summary") or ""
        evidence = lower.get("evidence") or lower.get("proof") or lower.get("url") or lower.get("location") or ""
        rec = lower.get("recommendation") or lower.get("solution") or lower.get("remediation") or ""
        lines += [f"Finding {idx}: {name}", f"Severity: {severity}", f"Location: {lower.get('location') or lower.get('url') or lower.get('asset') or ''}", f"Evidence: {evidence}", f"Description: {desc}", f"Recommendation: {rec}", ""]
    return ParsedUpload(f"CSV Scanner Report: {filename}", clean_text("\n".join(lines)), {"parser": "scanner-csv", "scanner": "Generic CSV", "finding_count": len(rows), "source_filename": filename})


def _parse_pdf(raw: bytes) -> str:
    try:
        from pypdf import PdfReader  # type: ignore
        import io as _io

        reader = PdfReader(_io.BytesIO(raw))
        pages = []
        for page in reader.pages[:30]:
            pages.append(page.extract_text() or "")
        text = "\n".join(pages)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("PDF parsing requires pypdf and a text-based PDF. Scanned PDFs are not supported in this MVP.") from exc
    return clean_text(text)


def _strip_html(value: str) -> str:
    import re

    return re.sub(r"<[^>]+>", " ", str(value)).replace("&quot;", '"').replace("&amp;", "&").strip()
