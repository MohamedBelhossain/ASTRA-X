import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from app.scanner.common import response_excerpt, scanner_log, should_stop_scan
from app.scanner.http_client import safe_scanner_session
from app.scanner.payloads import LFI_COMMON_PARAMS as COMMON_PARAMS, LFI_PAYLOADS as PAYLOADS

REQUEST_TIMEOUT = 4


def inject_payload(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def generate_variants(original, payload):
    return list(dict.fromkeys([payload, original + payload, payload + original]))


def detect_lfi(response):
    text = (response.text or "").lower()
    if "root:x:" in text and "/bin" in text:
        return "Linux passwd file"
    if "[extensions]" in text and "for 16-bit app support" in text:
        return "Windows ini file"
    sample = response.text[:200]
    if len(response.text) > 200 and re.fullmatch(r"[A-Za-z0-9+/=\n]+", sample):
        return "Base64 encoded file (PHP wrapper)"
    return None


def _ordered_lfi_params(existing_params):
    high_value = [
        param
        for param in existing_params
        if any(token in param.lower() for token in ["file", "path", "page", "include", "template", "view", "doc"])
    ]
    ordered = high_value + [param for param in existing_params if param not in high_value]
    return list(dict.fromkeys(ordered))


def scan_lfi(
    url,
    should_stop=None,
    on_progress=None,
    on_finding=None,
    max_params=4,
    max_payloads=8,
    aggressive=False,
):
    scanner_log(f"\n[LFI] Scanning: {url}")
    session = safe_scanner_session(timeout=REQUEST_TIMEOUT)
    results = []
    found = set()

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    existing_params = list(query_params.keys())

    if existing_params:
        all_params = _ordered_lfi_params(existing_params)
        if aggressive:
            all_params = list(dict.fromkeys(all_params + COMMON_PARAMS))
    elif aggressive:
        all_params = COMMON_PARAMS[:max_params]
    else:
        scanner_log("  [-] No query parameters, skipping smart LFI checks.")
        return results

    all_params = all_params[:max_params]
    payloads = PAYLOADS[:max_payloads]
    checked = 0

    for param in all_params:
        if should_stop_scan(should_stop):
            break

        original_value = query_params.get(param, [""])[0]
        if any(token in param.lower() for token in ["file", "path", "page", "include"]):
            scanner_log(f"  [!] High value parameter: {param}")

        detected = False
        for payload in payloads:
            if should_stop_scan(should_stop):
                break
            variants = generate_variants(original_value, payload)

            for variant in variants:
                if should_stop_scan(should_stop):
                    break

                key = (param, variant)
                if key in found:
                    continue

                test_url = inject_payload(url, param, variant)
                try:
                    response = session.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                except requests.exceptions.RequestException:
                    checked += 1
                    if on_progress:
                        on_progress({"url": url, "checked": checked, "param": param})
                    continue

                checked += 1
                if on_progress:
                    on_progress({"url": url, "checked": checked, "param": param})
                detection = detect_lfi(response)
                if detection:
                    found.add(key)
                    finding = {
                        "url": test_url,
                        "param": param,
                        "parameter": param,
                        "payload": variant,
                        "type": "LFI / Path Traversal",
                        "method": "GET",
                        "evidence": detection,
                        "evidence_excerpt": response_excerpt(response.text, detection.split()[0]),
                        "severity": "critical",
                        "confidence": "high",
                        "status_code": response.status_code,
                    }
                    results.append(finding)
                    if on_finding:
                        on_finding(finding)
                    scanner_log(f"  [VULN] LFI -> param='{param}' | {detection}")
                    detected = True
                    break

            if detected:
                break

    scanner_log(f"  [LFI] Found {len(results)} vulnerability(ies).")
    return results
