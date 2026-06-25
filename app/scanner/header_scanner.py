from urllib.parse import urlparse

import requests

from app.scanner.common import scanner_log, should_stop_scan
from app.scanner.http_client import safe_scanner_session

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "severity": "medium",
        "risk": "Browsers are not instructed to enforce HTTPS for future visits.",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": "medium",
        "risk": "Missing CSP increases the impact of injected script content.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "low",
        "risk": "The page may be frameable, which can enable clickjacking.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "risk": "Browsers may MIME-sniff responses in unsafe ways.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "risk": "URLs may leak more referrer information than intended.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "info",
        "risk": "Browser capabilities are not explicitly restricted.",
    },
}


def _cookie_findings(response):
    findings = []
    cookies = response.headers.get("set-cookie")
    if not cookies:
        return findings

    parsed = urlparse(response.url)
    lowered = cookies.lower()
    if "httponly" not in lowered:
        findings.append(
            {
                "type": "Cookie Missing HttpOnly",
                "url": response.url,
                "header": "Set-Cookie",
                "severity": "medium",
                "evidence": "At least one cookie was set without an HttpOnly attribute.",
            }
        )
    if parsed.scheme == "https" and "secure" not in lowered:
        findings.append(
            {
                "type": "Cookie Missing Secure",
                "url": response.url,
                "header": "Set-Cookie",
                "severity": "medium",
                "evidence": "At least one HTTPS cookie was set without a Secure attribute.",
            }
        )
    if "samesite" not in lowered:
        findings.append(
            {
                "type": "Cookie Missing SameSite",
                "url": response.url,
                "header": "Set-Cookie",
                "severity": "low",
                "evidence": "At least one cookie was set without a SameSite attribute.",
            }
        )
    return findings


def scan_security_headers(target_url, should_stop=None):
    scanner_log(f"\n[HEADERS] Inspecting: {target_url}")
    result = {
        "url": target_url,
        "status": None,
        "headers": {},
        "findings": [],
        "error": None,
    }

    if should_stop_scan(should_stop):
        return result

    session = safe_scanner_session(timeout=8)
    try:
        response = session.get(target_url, timeout=8, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        result["error"] = str(exc)
        return result

    result["url"] = response.url
    result["status"] = response.status_code
    result["headers"] = dict(response.headers)

    headers = {key.lower(): value for key, value in response.headers.items()}
    for header_name, meta in SECURITY_HEADERS.items():
        if header_name in headers:
            continue
        result["findings"].append(
            {
                "type": f"Missing {meta['name']}",
                "url": response.url,
                "header": meta["name"],
                "severity": meta["severity"],
                "evidence": meta["risk"],
            }
        )

    result["findings"].extend(_cookie_findings(response))
    scanner_log(f"[HEADERS] Found {len(result['findings'])} issue(s)")
    return result
