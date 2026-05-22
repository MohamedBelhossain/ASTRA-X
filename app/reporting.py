SCAN_USAGE_NOTICE = (
    "Authorized security testing only. WebVulnScan and its authors are not responsible "
    "for misuse, unauthorized scanning, service disruption, or any damage caused by how this tool is used."
)
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def empty_risk_summary():
    return {
        "total_findings": 0,
        "severity_counts": {severity: 0 for severity in SEVERITY_ORDER},
        "risk_level": "none",
        "recommendations": [],
    }


def _severity_bucket(severity):
    severity = (severity or "").lower()
    return severity if severity in SEVERITY_ORDER else "info"


def _sqli_severity(finding):
    vuln_type = finding.get("type")
    if vuln_type == "error-based":
        return "critical"
    if vuln_type in {"boolean-based", "time-based"}:
        return "high"
    if vuln_type == "response-diff":
        return "medium"
    return _severity_bucket(finding.get("severity") or "low")


def _xss_severity(finding):
    vuln_type = finding.get("type")
    if vuln_type == "stored":
        return "critical"
    if vuln_type == "reflected":
        return "high"
    return _severity_bucket(finding.get("severity") or "medium")


def _rate_limit_severity(probe):
    if not probe or not probe.get("tested") or probe.get("blocked"):
        return None
    return "low"


def build_risk_summary(report):
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    recommendations = []

    def add(severity, count=1):
        if count <= 0:
            return
        counts[_severity_bucket(severity)] += count

    for finding in report.get("vulnerabilities", []):
        add(_sqli_severity(finding))
    for finding in report.get("xss_vulnerabilities", []):
        add(_xss_severity(finding))
    for finding in report.get("lfi_vulnerabilities", []):
        add(finding.get("severity") or "critical")
    for finding in report.get("file_findings", []):
        add(finding.get("severity") or "high")
    for finding in report.get("subdomain_findings", []):
        add(finding.get("severity") or "low")

    header_findings = (report.get("header_result") or {}).get("findings", [])
    for finding in header_findings:
        add(finding.get("severity") or "medium")

    cms_cves = (report.get("cms_result") or {}).get("cves", [])
    for finding in cms_cves:
        add(finding.get("severity") or "medium")

    bruteforce = report.get("bruteforce_result") or {}
    credentials = bruteforce.get("credentials_found", [])
    add("critical", len(credentials))
    if bruteforce.get("waf_detected"):
        add("medium")
    rate_limit_severity = _rate_limit_severity(bruteforce.get("rate_limit_probe"))
    if rate_limit_severity:
        add(rate_limit_severity)

    if report.get("crawl_diagnostics", {}).get("anti_bot_detected"):
        add("medium")

    if counts["critical"]:
        risk_level = "critical"
    elif counts["high"]:
        risk_level = "high"
    elif counts["medium"]:
        risk_level = "medium"
    elif counts["low"]:
        risk_level = "low"
    elif counts["info"]:
        risk_level = "info"
    else:
        risk_level = "none"

    if counts["critical"] or counts["high"]:
        recommendations.append("Prioritize confirmed critical and high findings before broad hardening work.")
    if report.get("vulnerabilities"):
        recommendations.append("Review affected parameters for parameterized queries and server-side input validation.")
    if report.get("xss_vulnerabilities"):
        recommendations.append("Apply context-aware output encoding and sanitize any intentionally allowed HTML.")
    if report.get("lfi_vulnerabilities"):
        recommendations.append("Restrict file access to allowlisted paths and normalize paths before reading files.")
    if credentials:
        recommendations.append("Disable discovered credentials, enforce strong passwords, and add login throttling or MFA.")
    if header_findings:
        recommendations.append("Fix missing security headers and cookie attributes to reduce browser-side attack surface.")
    if report.get("file_findings"):
        recommendations.append("Remove exposed sensitive files from the web root and block them in deployment.")
    if not recommendations and sum(counts.values()) == 0:
        recommendations.append("No exploitable findings were confirmed by this scan; keep monitoring and retest after changes.")

    return {
        "total_findings": sum(counts.values()),
        "severity_counts": counts,
        "risk_level": risk_level,
        "recommendations": recommendations[:5],
    }
