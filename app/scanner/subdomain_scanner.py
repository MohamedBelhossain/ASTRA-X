from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

from app.scanner.common import should_stop_scan
from app.scanner.http_client import safe_scanner_session
from app.scanner.payloads import SUBDOMAINS, SUBDOMAIN_HIGH_RISK as HIGH_RISK


def _check_subdomain(subdomain, domain, scheme):
    hostname = f"{subdomain}.{domain}"
    url = f"{scheme}://{hostname}"
    client = safe_scanner_session(timeout=5)

    try:
        target_info = client.validator.validate_target(url, verify_head=False)
        ip = target_info["addresses"][0]
    except ValueError:
        return None

    try:
        response = client.get(url, timeout=5, allow_redirects=True)
        status = response.status_code
        title = _extract_title(response.text)
    except requests.exceptions.RequestException:
        status = "no response"
        title = ""

    severity = _get_severity(subdomain, status)
    return {
        "subdomain": hostname,
        "url": url,
        "ip": ip,
        "status": status,
        "title": title,
        "severity": severity,
        "confidence": "high" if status == 200 else "medium",
    }


def _extract_title(html):
    lowered = (html or "").lower()
    try:
        start = lowered.index("<title>") + 7
        end = lowered.index("</title>")
        return (html or "")[start:end].strip()[:60]
    except ValueError:
        return ""


def _get_severity(subdomain, status_code):
    if subdomain in HIGH_RISK and status_code == 200:
        return "high"
    if status_code == 200:
        return "medium"
    return "low"


def scan_subdomains(base_url, max_workers=20, should_stop=None, on_progress=None, on_finding=None):
    print(f"\n[SUBDOMAIN] Scanning: {base_url}")

    parsed = urlparse(base_url)
    scheme = parsed.scheme
    hostname = parsed.netloc
    domain = hostname.replace("www.", "")
    candidates = sorted(set(SUBDOMAINS))

    findings = []
    checked = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_subdomain, subdomain, domain, scheme): subdomain
            for subdomain in candidates
        }
        for future in as_completed(futures):
            if should_stop_scan(should_stop):
                break
            checked += 1
            if on_progress:
                on_progress({"checked": checked, "total": len(candidates), "subdomain": futures[future]})
            result = future.result()
            if result:
                print(f"  [FOUND] {result['subdomain']} -> {result['ip']} ({result['status']})")
                findings.append(result)
                if on_finding:
                    on_finding(result)

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: (order.get(item["severity"], 3), item["subdomain"]))
    print(f"  [SUBDOMAIN] Found {len(findings)} subdomain(s).")
    return findings
