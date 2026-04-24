"""
bruteforce_scanner.py
─────────────────────
Tests whether a target has a Web Application Firewall (WAF) and, if not,
performs a login brute-force attempt against any discovered login forms.

WAF detection strategy
  1. Send benign request, record baseline status / headers.
  2. Send obviously malicious payloads (SQLi + XSS).
  3. If the server returns 403/406/429/503 or injects well-known WAF headers
     → WAF detected, mark as protected.
  4. If the server returns identical 200 on all payloads → likely no WAF.

Brute-force strategy
  • Crawl login-like forms (action contains login/signin/auth/account).
  • Try a small wordlist of common credentials.
  • Stop per-form as soon as a valid login is found (or wordlist exhausted).
  • Detect successful login by: HTTP 302 to non-login URL, or response
    that lacks a password field, or body size grows significantly.
"""

import time
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from app.form_parser import get_forms
from app.scanner.common import session_headers, should_stop_scan

# ── Constants ────────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 8
RATE_LIMIT_TEST_MAX_REQUESTS = 25
RATE_LIMIT_TEST_DELAY = 0.05
RATE_LIMIT_BLOCK_CODES = {401, 403, 406, 429, 503}
COMMON_LOGIN_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/account/login",
    "/users/login",
    "/admin/login",
    "/wp-login.php",
)
from app.scanner.payloads import (
    WAF_HEADERS,
    WAF_PROBE_PAYLOADS,
    WAF_BLOCK_CODES,
    BRUTEFORCE_WORDLIST        as DEFAULT_WORDLIST,
    BRUTEFORCE_LOGIN_KEYWORDS  as LOGIN_KEYWORDS,
)
# ── Helpers ──────────────────────────────────────────────────────────────

def _session():
    s = requests.Session()
    s.headers.update(session_headers())
    return s


def _has_waf_header(response):
    """Return (True, header_name) if a WAF header is present."""
    for header, expected_val in WAF_HEADERS.items():
        val = response.headers.get(header, "")
        if val:
            if expected_val is None or expected_val.lower() in val.lower():
                return True, f"{header}: {val}"
    return False, None


def _is_login_url(url):
    return any(kw in url.lower() for kw in LOGIN_KEYWORDS)


def _looks_like_user_field(name, input_type):
    name = (name or "").lower()
    return input_type in ("text", "email") and any(
        token in name for token in ("user", "email", "login", "name", "identifier")
    )


def _looks_like_password_field(name, input_type):
    name = (name or "").lower()
    return input_type == "password" or "pass" in name


def _iter_candidate_pages(target, pages=None):
    ordered = []

    def add(url):
        if url and url not in ordered:
            ordered.append(url)

    add(target)
    for page in pages or []:
        add(page)

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in COMMON_LOGIN_PATHS:
        add(urljoin(base, path))

    return ordered


def _find_forms_with_parser(target):
    try:
        return get_forms(target)
    except Exception:
        return []


def _find_login_forms(targets, session, should_stop=None):
    """
    Crawl the target page and return a list of dicts:
      { url, action, user_field, pass_field, extra_fields }
    """
    forms = []
    seen = set()
    for target in targets:
        if should_stop_scan(should_stop):
            break
        try:
            r = session.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            soup = BeautifulSoup(r.text, "html.parser")
        except Exception:
            continue

        parser_forms = _find_forms_with_parser(r.url)
        fallback_forms = []
        if not parser_forms:
            for form in soup.find_all("form"):
                fallback_forms.append({
                    "action": form.get("action"),
                    "method": form.get("method", "post"),
                    "inputs": [
                        {
                            "name": inp.get("name"),
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                        }
                        for inp in form.find_all("input")
                    ],
                })

        for form in parser_forms or fallback_forms:
            action = form.get("action", "")
            method = form.get("method", "post").lower()
            full_action = urljoin(r.url, action) if action else r.url
            inputs = form.get("inputs", [])
            form_marker = " ".join(
                filter(None, [action, full_action, r.url])
            ).lower()

            user_field = None
            pass_field = None
            extra = {}

            for inp in inputs:
                name = inp.get("name", "")
                itype = inp.get("type", "text").lower()
                val = inp.get("value", "")
                if not name:
                    continue
                if _looks_like_password_field(name, itype):
                    pass_field = name
                elif not user_field and _looks_like_user_field(name, itype):
                    user_field = name
                elif itype not in ("submit", "button", "image", "reset"):
                    extra[name] = val

            if pass_field and not user_field:
                for fallback_name in ("username", "email", "login", "user", "identifier"):
                    if fallback_name not in extra:
                        user_field = fallback_name
                        extra[fallback_name] = ""
                        break

            looks_like_login = (
                _is_login_url(r.url)
                or _is_login_url(full_action)
                or any(kw in form_marker for kw in LOGIN_KEYWORDS)
                or bool(pass_field)
            )
            if not (looks_like_login and pass_field):
                continue

            signature = (r.url, full_action, user_field or "", pass_field)
            if signature in seen:
                continue
            seen.add(signature)
            forms.append({
                "page_url":     r.url,
                "url":          full_action,
                "method":       method,
                "user_field":   user_field,
                "pass_field":   pass_field,
                "extra":        extra,
                "baseline_len": len(r.text),
            })

    return forms


def _test_request_rate_limit(session, target, should_stop=None):
    result = {
        "tested": True,
        "requests_sent": 0,
        "allowed_before_block": 0,
        "blocked": False,
        "blocked_at_request": None,
        "block_status": None,
        "average_response_ms": None,
        "statuses": [],
    }
    durations = []

    for index in range(1, RATE_LIMIT_TEST_MAX_REQUESTS + 1):
        if should_stop_scan(should_stop):
            break
        started = time.time()
        try:
            response = session.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.exceptions.RequestException:
            result["requests_sent"] = index - 1
            break

        elapsed_ms = round((time.time() - started) * 1000, 2)
        durations.append(elapsed_ms)
        result["requests_sent"] = index
        result["statuses"].append(response.status_code)

        if response.status_code in RATE_LIMIT_BLOCK_CODES:
            result["blocked"] = True
            result["blocked_at_request"] = index
            result["block_status"] = response.status_code
            result["allowed_before_block"] = index - 1
            break

        result["allowed_before_block"] = index
        time.sleep(RATE_LIMIT_TEST_DELAY)

    if durations:
        result["average_response_ms"] = round(sum(durations) / len(durations), 2)

    return result


def _attempt_login(session, form, username, password):
    """
    Try a single credential pair.  Returns a dict with result info.
    """
    data = dict(form["extra"])
    data[form["user_field"]] = username
    data[form["pass_field"]] = password

    try:
        t0 = time.time()
        if form["method"] == "post":
            r = session.post(form["url"], data=data, timeout=REQUEST_TIMEOUT,
                             allow_redirects=False)
        else:
            r = session.get(form["url"],  params=data, timeout=REQUEST_TIMEOUT,
                            allow_redirects=False)
        elapsed = round(time.time() - t0, 2)
    except Exception as e:
        return {"success": False, "error": str(e)}

    # Heuristics for success:
    # 1. Redirect (302/301) away from a login URL
    redirect_loc = r.headers.get("location", "")
    redirected_away = (
        r.status_code in (301, 302, 303, 307, 308)
        and not _is_login_url(redirect_loc)
    )

    # 2. Response body lacks a password input
    soup = BeautifulSoup(r.text, "html.parser")
    has_pass_field = bool(soup.find("input", {"type": "password"}))

    # 3. Status 200 and no password field (already logged in / redirect already consumed)
    body_lower = r.text.lower()
    has_failure_marker = any(
        marker in body_lower for marker in (
            "invalid password",
            "invalid credentials",
            "incorrect password",
            "login failed",
            "try again",
            "authentication failed",
            "wrong password",
        )
    )
    auth_cookie = any(
        token in cookie.name.lower()
        for cookie in session.cookies
        for token in ("session", "auth", "jwt", "token")
    )
    grew_meaningfully = len(r.text) > form.get("baseline_len", 0) + 120
    looks_logged_in = (
        r.status_code == 200
        and not has_pass_field
        and not has_failure_marker
        and (grew_meaningfully or auth_cookie or not _is_login_url(r.url))
    )

    success = redirected_away or looks_logged_in or auth_cookie

    return {
        "success":      success,
        "username":     username,
        "password":     password,
        "status_code":  r.status_code,
        "elapsed_s":    elapsed,
        "redirect":     redirect_loc or None,
        "method":       form["method"].upper(),
        "login_url":    form["url"],
        "page_url":     form.get("page_url"),
    }


# ── Public API ───────────────────────────────────────────────────────────

def scan_bruteforce(target, pages=None, wordlist=None, should_stop=None):
    """
    Main entry point.

    Returns a dict:
    {
      "waf_detected": bool,
      "waf_detail":   str | None,       # which header / response gave it away
      "bypass_hints": list[str],        # suggestions if WAF found
      "login_forms":  int,              # number of login forms found
      "attempts":     int,
      "credentials_found": list[dict],  # [{username, password, url, status_code}]
      "blocked_payloads":  list[str],   # payloads that got a block response
    }
    """
    if wordlist is None:
        wordlist = DEFAULT_WORDLIST

    result = {
        "waf_detected":       False,
        "waf_detail":         None,
        "bypass_hints":       [],
        "login_forms":        0,
        "attempts":           0,
        "credentials_found":  [],
        "blocked_payloads":   [],
        "candidate_pages":    0,
        "rate_limit_probe":   {
            "tested": False,
            "requests_sent": 0,
            "allowed_before_block": 0,
            "blocked": False,
            "blocked_at_request": None,
            "block_status": None,
            "average_response_ms": None,
            "statuses": [],
        },
    }

    session = _session()

    # ── Step 1: WAF detection ────────────────────────────────────────────
    try:
        baseline = session.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        baseline_code = baseline.status_code
        baseline_len  = len(baseline.content)

        # Check headers on baseline response
        waf_in_header, hdr_detail = _has_waf_header(baseline)
        if waf_in_header:
            result["waf_detected"] = True
            result["waf_detail"]   = f"WAF header detected: {hdr_detail}"

        # Probe with malicious payloads
        probe_url = target.rstrip("/") + "/?q="
        for payload in WAF_PROBE_PAYLOADS:
            if should_stop_scan(should_stop):
                break
            try:
                r = session.get(probe_url + payload, timeout=REQUEST_TIMEOUT,
                                allow_redirects=False)
                # Header check on each probe response
                waf_hit, hdr = _has_waf_header(r)
                if waf_hit:
                    result["waf_detected"] = True
                    result["waf_detail"]   = result["waf_detail"] or f"WAF header on probe: {hdr}"

                if r.status_code in WAF_BLOCK_CODES:
                    result["waf_detected"]    = True
                    result["blocked_payloads"].append(payload)
                    result["waf_detail"] = result["waf_detail"] or (
                        f"Payload blocked with HTTP {r.status_code}"
                    )

                time.sleep(0.15)   # be polite
            except Exception:
                pass   # connection reset = likely blocked too
    except Exception as e:
        result["waf_detail"] = f"Error during WAF probe: {e}"
        return result

    # ── Bypass hints if WAF detected ────────────────────────────────────
    if result["waf_detected"]:
        result["bypass_hints"] = [
            "Try encoding payloads (URL-encode, double-encode, Unicode).",
            "Use case-variation: SeLeCt instead of SELECT.",
            "Insert inline comments: SE/**/LECT, <scr/**/ipt>.",
            "Test HTTP parameter pollution (duplicate parameters).",
            "Try HTTP verb tampering (HEAD / PUT / PATCH).",
            "Use chunked transfer encoding to bypass body inspection.",
        ]
        # WAF detected — skip brute-force (would be blocked anyway)
        return result

    result["rate_limit_probe"] = _test_request_rate_limit(session, target, should_stop=should_stop)

    # ── Step 2: Find login forms ─────────────────────────────────────────
    candidate_pages = _iter_candidate_pages(target, pages=pages)
    result["candidate_pages"] = len(candidate_pages)
    forms = _find_login_forms(candidate_pages, session, should_stop=should_stop)
    result["login_forms"] = len(forms)

    if not forms:
        return result

    # ── Step 3: Brute-force ──────────────────────────────────────────────
    for form in forms:
        if should_stop_scan(should_stop):
            break
        found = False
        if not form.get("user_field"):
            continue
        for username, password in wordlist:
            if should_stop_scan(should_stop):
                break
            result["attempts"] += 1
            attempt = _attempt_login(session, form, username, password)
            time.sleep(0.1)   # throttle

            if attempt.get("success"):
                result["credentials_found"].append({
                    "username":    attempt["username"],
                    "password":    attempt["password"],
                    "url":         attempt.get("page_url") or form["url"],
                    "login_url":   form["url"],
                    "status_code": attempt.get("status_code"),
                    "redirect":    attempt.get("redirect"),
                    "method":      attempt.get("method"),
                    "type":        "Valid credentials discovered",
                })
                found = True
                break   # stop on first valid cred per form

        if found:
            break   # stop after first successful form

    return result
