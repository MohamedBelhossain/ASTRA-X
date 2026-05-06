import os
import time
from functools import lru_cache
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter

from app.form_parser import get_forms
from app.scanner.common import response_excerpt, session_headers, should_stop_scan
from app.scanner.payloads import (
    SQLI_BOOLEAN_PAYLOADS as BOOLEAN_PAYLOADS,
    SQLI_ERROR_PAYLOADS as ERROR_PAYLOADS,
    SQLI_ERROR_SIGNATURES as SQL_ERRORS,
    SQLI_TIME_PAYLOADS as TIME_PAYLOADS,
)

REQUEST_TIMEOUT = int(os.environ.get("SQLI_REQUEST_TIMEOUT", "6"))
SQLI_MAX_FORMS = int(os.environ.get("SQLI_MAX_FORMS", "3"))
SQLI_MAX_PARAMS_PER_FORM = int(os.environ.get("SQLI_MAX_PARAMS_PER_FORM", "4"))
SQLI_MAX_ERROR_PAYLOADS = int(os.environ.get("SQLI_MAX_ERROR_PAYLOADS", "4"))
SQLI_MAX_BOOLEAN_PAIRS = int(os.environ.get("SQLI_MAX_BOOLEAN_PAIRS", "2"))
SQLI_MAX_TIME_PAYLOADS = int(os.environ.get("SQLI_MAX_TIME_PAYLOADS", "1"))


def _make_session():
    client = requests.Session()
    client.headers.update(session_headers())
    adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50)
    client.mount("http://", adapter)
    client.mount("https://", adapter)
    return client


session = _make_session()


@lru_cache(maxsize=200)
def get_forms_cached(url):
    return get_forms(url)


def _resolve_action(base_url, action):
    if not action or action.strip() in {"", "#"}:
        return base_url
    return urljoin(base_url, action)


def _send(method, url, data, timeout=REQUEST_TIMEOUT):
    try:
        started = time.time()
        if method == "post":
            response = session.post(url, data=data, timeout=timeout, allow_redirects=True)
        else:
            response = session.get(url, params=data, timeout=timeout, allow_redirects=True)
        response.elapsed_seconds = round(time.time() - started, 2)
        return response
    except requests.exceptions.RequestException as exc:
        print(f"  [!] Request failed ({url}): {exc}")
        return None


def _has_sql_error(text):
    lower = (text or "").lower()
    for error in SQL_ERRORS:
        if error in lower:
            return error
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


def _append(vulnerabilities, finding):
    vulnerabilities.append(finding)


def scan_sqli(url, should_stop=None, on_progress=None, on_finding=None):
    print(f"\n[*] Scanning: {url}")

    vulnerabilities = []
    found_params = set()

    try:
        forms = get_forms_cached(url)
    except Exception as exc:
        print(f"  [!] Could not retrieve forms: {exc}")
        return vulnerabilities

    if not forms:
        print("  [-] No forms found.")
        if on_progress:
            on_progress({"url": url, "forms": 0, "checked": 0})
        return vulnerabilities

    print(f"  [+] Found {len(forms)} form(s).")
    checked = 0

    for form_idx, form in enumerate(forms[:SQLI_MAX_FORMS]):
        if should_stop_scan(should_stop):
            break

        raw_action = form.get("action") or ""
        action = _resolve_action(url, raw_action)
        method = (form.get("method") or "get").lower().strip()
        inputs = form.get("inputs", [])
        named_inputs = [field for field in inputs if field.get("name")][:SQLI_MAX_PARAMS_PER_FORM]

        if not named_inputs:
            print(f"  [-] Form {form_idx + 1}: no named inputs, skipping.")
            continue

        print(
            f"\n  [Form {form_idx + 1}] action={action} | method={method} | "
            f"inputs={[field['name'] for field in named_inputs]}"
        )

        baseline_data = _build_data(inputs)
        baseline_resp = _send(method, action, baseline_data)
        if baseline_resp is None:
            print("  [!] Baseline request failed, skipping form.")
            continue
        baseline_len = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code
        baseline_elapsed = getattr(baseline_resp, "elapsed_seconds", 0.0)
        print(
            f"  [*] Baseline -> status={baseline_status}, len={baseline_len}, "
            f"time={baseline_elapsed:.2f}s"
        )

        for target_input in named_inputs:
            if should_stop_scan(should_stop):
                break

            param = target_input["name"]
            if on_progress:
                on_progress({"url": url, "form": form_idx + 1, "forms": len(forms), "param": param, "checked": checked})

            key = (action, param, "error-based")
            if key not in found_params:
                for payload in ERROR_PAYLOADS[:SQLI_MAX_ERROR_PAYLOADS]:
                    if should_stop_scan(should_stop):
                        break
                    data = _build_data(inputs, param, payload)
                    response = _send(method, action, data)
                    checked += 1
                    if on_progress:
                        on_progress({"url": url, "form": form_idx + 1, "forms": len(forms), "param": param, "checked": checked})
                    if response is None:
                        continue

                    matched = _has_sql_error(response.text)
                    if matched:
                        print(
                            f"  [VULN] Error-based SQLi -> param='{param}' "
                            f"payload='{payload}' matched='{matched}'"
                        )
                        finding = {
                            "type": "error-based",
                            "url": action,
                            "parameter": param,
                            "payload": payload,
                            "matched_error": matched,
                            "method": method.upper(),
                            "severity": "critical",
                            "confidence": "confirmed",
                            "evidence": matched,
                            "evidence_excerpt": response_excerpt(response.text, matched),
                            "status_code": response.status_code,
                        }
                        _append(vulnerabilities, finding)
                        if on_finding:
                            on_finding(finding)
                        found_params.add(key)
                        break

            key = (action, param, "response-diff")
            if key not in found_params:
                data = _build_data(inputs, param, "'")
                response = _send(method, action, data)
                checked += 1
                if on_progress:
                    on_progress({"url": url, "form": form_idx + 1, "forms": len(forms), "param": param, "checked": checked})
                if response is not None:
                    diff = abs(len(response.text) - baseline_len)
                    status_changed = response.status_code != baseline_status
                    if diff > 200 or (status_changed and diff > 80):
                        print(f"  [VULN] Response-diff SQLi -> param='{param}' diff={diff}")
                        finding = {
                            "type": "response-diff",
                            "url": action,
                            "parameter": param,
                            "payload": "'",
                            "response_diff": diff,
                            "method": method.upper(),
                            "severity": "medium",
                            "confidence": "medium",
                            "evidence": f"Response changed by {diff} bytes",
                            "evidence_excerpt": response_excerpt(response.text),
                            "status_code": response.status_code,
                        }
                        _append(vulnerabilities, finding)
                        if on_finding:
                            on_finding(finding)
                        found_params.add(key)

            key = (action, param, "boolean-based")
            if key not in found_params:
                for true_payload, false_payload in BOOLEAN_PAYLOADS[:SQLI_MAX_BOOLEAN_PAIRS]:
                    if should_stop_scan(should_stop):
                        break
                    true_response = _send(method, action, _build_data(inputs, param, true_payload))
                    false_response = _send(method, action, _build_data(inputs, param, false_payload))
                    checked += 2
                    if on_progress:
                        on_progress({"url": url, "form": form_idx + 1, "forms": len(forms), "param": param, "checked": checked})
                    if true_response is None or false_response is None:
                        continue

                    diff = abs(len(true_response.text) - len(false_response.text))
                    baseline_diff = abs(len(true_response.text) - baseline_len)
                    if diff > 100 and baseline_diff > 50:
                        print(
                            f"  [VULN] Boolean-based SQLi -> param='{param}' true/false diff={diff}"
                        )
                        finding = {
                            "type": "boolean-based",
                            "url": action,
                            "parameter": param,
                            "payload": true_payload,
                            "true_false_diff": diff,
                            "method": method.upper(),
                            "severity": "high",
                            "confidence": "high",
                            "evidence": f"True/false responses differ by {diff} bytes",
                            "evidence_excerpt": response_excerpt(true_response.text),
                            "status_code": true_response.status_code,
                        }
                        _append(vulnerabilities, finding)
                        if on_finding:
                            on_finding(finding)
                        found_params.add(key)
                        break

            key = (action, param, "time-based")
            if key not in found_params:
                for payload in TIME_PAYLOADS[:SQLI_MAX_TIME_PAYLOADS]:
                    if should_stop_scan(should_stop):
                        break
                    response = _send(method, action, _build_data(inputs, param, payload), timeout=6)
                    checked += 1
                    if on_progress:
                        on_progress({"url": url, "form": form_idx + 1, "forms": len(forms), "param": param, "checked": checked})
                    if response is None:
                        continue
                    delay = getattr(response, "elapsed_seconds", 0.0)
                    if delay >= max(3.0, baseline_elapsed + 2.5):
                        print(
                            f"  [VULN] Time-based SQLi -> param='{param}' "
                            f"payload='{payload}' delay={delay:.2f}s"
                        )
                        finding = {
                            "type": "time-based",
                            "url": action,
                            "parameter": param,
                            "payload": payload,
                            "delay_seconds": round(delay, 2),
                            "baseline_seconds": round(baseline_elapsed, 2),
                            "method": method.upper(),
                            "severity": "high",
                            "confidence": "high",
                            "evidence": f"Response delayed to {delay:.2f}s from {baseline_elapsed:.2f}s baseline",
                            "evidence_excerpt": response_excerpt(response.text),
                            "status_code": response.status_code,
                        }
                        _append(vulnerabilities, finding)
                        if on_finding:
                            on_finding(finding)
                        found_params.add(key)
                        break

    print(f"\n[*] Scan complete. {len(vulnerabilities)} vulnerability(ies) found.")
    return vulnerabilities
