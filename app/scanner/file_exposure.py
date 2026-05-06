from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests

from app.scanner.common import response_excerpt, session_headers, should_stop_scan
from app.scanner.payloads import FILE_FALSE_POSITIVE_KEYWORDS as KEYWORDS, SENSITIVE_PATHS

session = requests.Session()
session.headers.update(session_headers())


def is_false_positive(response):
    text = (response.text or "").lower()
    if any(keyword in text for keyword in KEYWORDS):
        return True
    return len((response.text or "").strip()) < 30


def _check_sensitive_path(base, path):
    url = urljoin(base, path)

    try:
        response = session.get(url, timeout=3, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        print(f"[ERROR] {url} -> {exc}")
        return None

    if response.status_code not in [200, 301, 302, 401, 403]:
        return None

    if response.status_code == 200 and is_false_positive(response):
        return None

    severity = "high"
    confidence = "high"
    if response.status_code in [401, 403]:
        severity = "low"
        confidence = "medium"
    if path in ["/robots.txt", "/sitemap.xml", "/README.md", "/LICENSE"]:
        severity = "info"
        confidence = "medium"

    return {
        "url": url,
        "status": response.status_code,
        "severity": severity,
        "confidence": confidence,
        "size": len(response.text),
        "evidence_excerpt": response_excerpt(response.text),
    }


def scan_file_exposure(base_url, should_stop=None, on_progress=None, on_finding=None):
    print(f"\n[FILE] Scanning: {base_url}")

    findings = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    checked = 0

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(_check_sensitive_path, base, path): path
            for path in SENSITIVE_PATHS
        }
        for future in as_completed(futures):
            if should_stop_scan(should_stop):
                break
            checked += 1
            if on_progress:
                on_progress({"checked": checked, "total": len(SENSITIVE_PATHS), "path": futures[future]})
            result = future.result()
            if not result:
                continue
            print(f"[FOUND] {result['url']} -> {result['status']}")
            findings.append(result)
            if on_finding:
                on_finding(result)

    print(f"[FILE] Found {len(findings)} result(s)")
    return findings
