from functools import lru_cache
from urllib.parse import urljoin

import requests

from app.form_parser import get_forms
from app.scanner.common import response_excerpt, session_headers, should_stop_scan
from app.scanner.payloads import XSS_DOM_PAYLOADS as DOM_PAYLOADS, XSS_PAYLOADS

session = requests.Session()
session.headers.update(session_headers())

DOM_SINK_MARKERS = (
    "location.hash",
    "location.search",
    "document.url",
    "document.location",
    "innerhtml",
    "outerhtml",
    "document.write",
)


@lru_cache(maxsize=200)
def get_forms_cached(url):
    return get_forms(url)


def _resolve_action(base_url, action):
    if not action or action.strip() in {"", "#"}:
        return base_url
    return urljoin(base_url, action)


def _send(method, url, data, timeout=10):
    try:
        if method == "post":
            return session.post(url, data=data, timeout=timeout, allow_redirects=True)
        return session.get(url, params=data, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        print(f"  [!] Request failed ({url}): {exc}")
        return None


def _build_data(inputs, target_name=None, payload=None):
    data = {}
    for field in inputs:
        name = field.get("name")
        if not name:
            continue
        if name == target_name and payload is not None:
            data[name] = payload
        else:
            data[name] = field.get("value") or "test"
    return data


def _check_reflected(response_text, payload):
    return payload.lower() in (response_text or "").lower()


def _detect_dom_sinks(html):
    lowered = (html or "").lower()
    return [marker for marker in DOM_SINK_MARKERS if marker in lowered]


def scan_xss(url, should_stop=None):
    print(f"\n[XSS] Scanning: {url}")

    vulnerabilities = []
    found = set()

    try:
        forms = get_forms_cached(url)
    except Exception as exc:
        print(f"  [!] Could not get forms: {exc}")
        return vulnerabilities

    print(f"  [XSS] Forms found: {len(forms) if forms else 0}")
    if not forms:
        try:
            response = session.get(url, timeout=8, allow_redirects=True)
        except requests.exceptions.RequestException:
            return vulnerabilities
        dom_sinks = _detect_dom_sinks(response.text)
        if dom_sinks:
            vulnerabilities.append(
                {
                    "type": "dom-based",
                    "url": response.url,
                    "parameter": "client-side source",
                    "payload": DOM_PAYLOADS[0],
                    "method": "GET",
                    "severity": "medium",
                    "confidence": "low",
                    "evidence": ", ".join(dom_sinks[:3]),
                    "evidence_excerpt": response_excerpt(response.text, dom_sinks[0]),
                }
            )
        return vulnerabilities

    for form_idx, form in enumerate(forms):
        if should_stop_scan(should_stop):
            break

        raw_action = form.get("action") or ""
        action = _resolve_action(url, raw_action)
        method = (form.get("method") or "get").lower().strip()
        inputs = form.get("inputs", [])
        named_inputs = [field for field in inputs if field.get("name")]

        print(f"  [XSS] Form {form_idx + 1} inputs: {[field['name'] for field in named_inputs]}")
        if not named_inputs:
            continue

        for target_input in named_inputs:
            if should_stop_scan(should_stop):
                break

            param = target_input["name"]

            key = (action, param, "reflected")
            if key not in found:
                for payload in XSS_PAYLOADS:
                    response = _send(method, action, _build_data(inputs, param, payload))
                    if response is None:
                        continue
                    if _check_reflected(response.text, payload):
                        print(f"  [VULN] Reflected XSS -> param='{param}' payload='{payload}'")
                        vulnerabilities.append(
                            {
                                "type": "reflected",
                                "url": action,
                                "parameter": param,
                                "payload": payload,
                                "method": method.upper(),
                                "severity": "high",
                                "confidence": "high",
                                "evidence": "Payload reflected in immediate server response",
                                "evidence_excerpt": response_excerpt(response.text, payload),
                                "status_code": response.status_code,
                            }
                        )
                        found.add(key)
                        break

            key = (action, param, "stored")
            if key not in found:
                for payload in XSS_PAYLOADS[:3]:
                    if should_stop_scan(should_stop):
                        break
                    _send(method, action, _build_data(inputs, param, payload))
                    check_response = _send("get", url, {})
                    if check_response is None:
                        continue
                    if _check_reflected(check_response.text, payload):
                        print(f"  [VULN] Stored XSS -> param='{param}' payload='{payload}'")
                        vulnerabilities.append(
                            {
                                "type": "stored",
                                "url": action,
                                "parameter": param,
                                "payload": payload,
                                "method": method.upper(),
                                "severity": "critical",
                                "confidence": "high",
                                "evidence": "Payload persisted and rendered on follow-up request",
                                "evidence_excerpt": response_excerpt(check_response.text, payload),
                                "status_code": check_response.status_code,
                            }
                        )
                        found.add(key)
                        break

        key = (url, "dom")
        if key not in found:
            response = _send("get", url, {})
            if response is not None:
                dom_sinks = _detect_dom_sinks(response.text)
                if dom_sinks:
                    payload = DOM_PAYLOADS[0]
                    print(f"  [VULN] Potential DOM XSS -> url='{response.url}' sinks={dom_sinks[:2]}")
                    vulnerabilities.append(
                        {
                            "type": "dom-based",
                            "url": response.url,
                            "parameter": "client-side source",
                            "payload": payload,
                            "method": "GET",
                            "severity": "medium",
                            "confidence": "low",
                            "evidence": ", ".join(dom_sinks[:3]),
                            "evidence_excerpt": response_excerpt(response.text, dom_sinks[0]),
                            "status_code": response.status_code,
                        }
                    )
                    found.add(key)

    print(f"  [XSS] Found {len(vulnerabilities)} vulnerability(ies).")
    return vulnerabilities
