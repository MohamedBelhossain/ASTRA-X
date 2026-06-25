SCAN_USAGE_NOTICE = (
    "Authorized security testing only. ASTRA-X and its authors are not responsible "
    "for misuse, unauthorized scanning, service disruption, or any damage caused by how this tool is used."
)
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
PROOF_CATEGORIES = (
    ("vulnerabilities", "sqli"),
    ("xss_vulnerabilities", "xss"),
    ("lfi_vulnerabilities", "lfi"),
    ("file_findings", "file"),
)


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


def _finding_value(finding, *keys, default=None):
    for key in keys:
        value = finding.get(key)
        if value not in (None, ""):
            return value
    return default


def _request_summary(finding, default_method="GET"):
    return {
        "method": _finding_value(finding, "method", default=default_method),
        "url": _finding_value(finding, "login_url", "url", default="unknown"),
        "parameter": _finding_value(finding, "parameter", "param", "header", default=None),
        "payload": _finding_value(finding, "payload", default=None),
        "status_code": _finding_value(finding, "status_code", "status", default=None),
    }


def _base_proof(finding, category, title, summary, impact, fix_steps, false_positive_checks):
    confidence = (_finding_value(finding, "confidence", default="observed") or "observed").lower()
    severity = (_finding_value(finding, "severity", default="info") or "info").lower()
    evidence = _finding_value(finding, "evidence", "matched_error", default="Scanner behavior matched this finding type.")
    excerpt = _finding_value(finding, "evidence_excerpt", default=None)
    request_summary = _request_summary(finding)

    return {
        "category": category,
        "title": title,
        "summary": summary,
        "confidence": confidence,
        "severity": severity,
        "request": request_summary,
        "evidence": {
            "observed": evidence,
            "excerpt": excerpt,
        },
        "false_positive_checks": false_positive_checks,
        "reproduction_steps": [
            f"Send a {request_summary['method']} request to {request_summary['url']}.",
            (
                f"Set parameter {request_summary['parameter']} to the recorded payload."
                if request_summary.get("parameter") and request_summary.get("payload")
                else "Repeat the request with the same path and headers observed by the scanner."
            ),
            "Compare the response with a normal baseline request and confirm the observed behavior still appears.",
        ],
        "impact": impact,
        "fix_steps": fix_steps,
    }


def _sqli_proof(finding):
    vuln_type = finding.get("type", "sql injection")
    if vuln_type == "error-based":
        summary = "The payload produced a database error marker in the HTTP response."
        checks = [
            "Retest with a harmless baseline value and confirm the database error disappears.",
            "Confirm the error comes from the application response, not from a shared error page.",
            "Try a second SQL quote or comment probe to confirm the same input point changes backend behavior.",
        ]
    elif vuln_type == "boolean-based":
        summary = "True and false SQL conditions produced meaningfully different responses."
        checks = [
            "Repeat both boolean payloads several times and confirm the response difference is stable.",
            "Confirm the difference is not caused by changing content, ads, timestamps, or rate limits.",
            "Compare with a normal baseline request for the same parameter.",
        ]
    elif vuln_type == "time-based":
        summary = "A delay payload made the response slower than the baseline."
        checks = [
            "Repeat the delayed and baseline requests to rule out network jitter.",
            "Use a shorter delay payload and confirm response time changes predictably.",
            "Confirm no target-side throttling or WAF challenge caused the delay.",
        ]
    else:
        summary = "A SQL probe changed the response enough to make the parameter suspicious."
        checks = [
            "Repeat the probe and baseline request to verify the response change is stable.",
            "Check whether the changed response is an application error or validation message.",
            "Review backend query construction for this parameter.",
        ]

    return _base_proof(
        finding,
        "sqli",
        f"{vuln_type.replace('-', ' ').title()} SQL Injection",
        summary,
        "An attacker may read, modify, or delete database data if this input reaches SQL without parameter binding.",
        [
            "Use parameterized queries or the framework ORM binding API for this value.",
            "Validate the input server-side before it reaches query logic.",
            "Return generic errors to users and log database details server-side only.",
            "Retest this exact parameter after the fix.",
        ],
        checks,
    )


def _xss_proof(finding):
    vuln_type = finding.get("type", "xss")
    if vuln_type == "stored":
        summary = "The payload appeared after a follow-up request, suggesting stored script content."
        impact = "An attacker may persist script that later runs in another user's browser."
    elif vuln_type == "reflected":
        summary = "The payload appeared in the immediate response for the tested parameter."
        impact = "An attacker may craft a link that executes script in a victim's browser if the payload reaches executable context."
    else:
        summary = "The page contains DOM sinks that may process attacker-controlled browser input."
        impact = "Client-side code may turn URL or DOM-controlled data into executable HTML or JavaScript."

    return _base_proof(
        finding,
        "xss",
        f"{vuln_type.replace('-', ' ').title()} XSS",
        summary,
        impact,
        [
            "Apply context-aware output encoding for HTML, attributes, JavaScript, and URLs.",
            "Sanitize intentionally allowed HTML with an allowlist sanitizer.",
            "Avoid assigning untrusted data to dangerous DOM sinks such as innerHTML.",
            "Add or tighten Content-Security-Policy as a defense-in-depth control.",
        ],
        [
            "Confirm the payload appears in an executable browser context, not only as harmless text.",
            "Retest with a unique marker to rule out cached or reflected scanner output.",
            "Check whether server-side encoding or CSP prevents actual execution.",
        ],
    )


def _lfi_proof(finding):
    return _base_proof(
        finding,
        "lfi",
        "Local File Inclusion / Path Traversal",
        "A traversal payload returned content matching a local server file marker.",
        "An attacker may read local files such as configuration, credentials, source, or operating system files.",
        [
            "Resolve requested files against an allowlisted base directory.",
            "Normalize paths before access and reject traversal outside the allowed directory.",
            "Map user choices to server-side file IDs instead of accepting raw paths.",
            "Run the application with the least filesystem privileges needed.",
        ],
        [
            "Confirm the marker is from the target response and not from a generic example page.",
            "Retest with a harmless known file path in a controlled environment.",
            "Verify the application actually reads files based on this parameter.",
        ],
    )


def _file_proof(finding):
    return _base_proof(
        finding,
        "file",
        "Sensitive File Exposure",
        "A path commonly associated with sensitive files returned a non-error response.",
        "Public files may disclose source, deployment metadata, credentials, backups, or endpoint maps.",
        [
            "Remove the file from the public web root.",
            "Block sensitive path patterns at the web server or reverse proxy.",
            "Add deployment checks that fail builds when sensitive files are publishable.",
            "Retest the exact URL and confirm it returns 404 or an intentional access control response.",
        ],
        [
            "Open the URL and confirm the content is not an intentional public document.",
            "Check whether the response body is a custom error page despite the status code.",
            "Confirm the file contents are current and relevant to the target.",
        ],
    )


def build_proof_assistant(finding, category):
    builders = {
        "sqli": _sqli_proof,
        "xss": _xss_proof,
        "lfi": _lfi_proof,
        "file": _file_proof,
    }
    builder = builders.get(category)
    if not builder:
        return None
    return builder(finding)


def enrich_report_with_proofs(report):
    for field, category in PROOF_CATEGORIES:
        for finding in report.get(field, []) or []:
            if finding.get("proof_assistant"):
                continue
            proof = build_proof_assistant(finding, category)
            if proof:
                finding["proof_assistant"] = proof
    return report
