import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from app.scanner.common import response_excerpt, session_headers, should_stop_scan
from app.scanner.payloads import LFI_COMMON_PARAMS as COMMON_PARAMS, LFI_PAYLOADS as PAYLOADS

REQUEST_TIMEOUT = 4

session = requests.Session()
session.headers.update(session_headers())


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


def scan_lfi(url, should_stop=None):
    print(f"\n[LFI] Scanning: {url}")
    results = []
    found = set()

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    existing_params = list(query_params.keys())

    if existing_params:
        all_params = list(dict.fromkeys(existing_params + COMMON_PARAMS))
    else:
        all_params = COMMON_PARAMS[:4]

    for param in all_params:
        if should_stop_scan(should_stop):
            break

        original_value = query_params.get(param, [""])[0]
        if any(token in param.lower() for token in ["file", "path", "page", "include"]):
            print(f"  [!] High value parameter: {param}")

        detected = False
        for payload in PAYLOADS:
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
                    continue

                detection = detect_lfi(response)
                if detection:
                    found.add(key)
                    results.append(
                        {
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
                    )
                    print(f"  [VULN] LFI -> param='{param}' | {detection}")
                    detected = True
                    break

            if detected:
                break

    print(f"  [LFI] Found {len(results)} vulnerability(ies).")
    return results
