import os
import uuid
import socket
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, render_template, request, make_response, Response, jsonify, url_for
from flask_login import LoginManager, login_required, current_user
from weasyprint import HTML
import requests as req
from dotenv import load_dotenv

from app.models import mongo, User
from app.auth import auth, bcrypt
from app.scanner.analyser import analyse_nmap
from app.scanner.file_exposure import scan_file_exposure
from app.scanner.nmap import run_nmap
from app.scanner.crawler import crawl
from app.scanner.sqli_scanner import scan_sqli
from app.scanner.xss_scanner import scan_xss
from app.scanner.lfi_scanner import scan_lfi
from app.scanner.subdomain_scanner import scan_subdomains
from app.scanner.bruteforce_scanner import scan_bruteforce

app = Flask(__name__)

ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(ENV_PATH)

# ── Configuration ─────────────────────────────────────────────────────────────
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-key-change-me"),
    MONGO_URI=os.environ.get("MONGO_URI", "mongodb://localhost:27017/webvuln"),
)

# ── Extensions ────────────────────────────────────────────────────────────────
mongo.init_app(app)
bcrypt.init_app(app)
app.register_blueprint(auth)

# ── Flask-Login ───────────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.find_by_id(user_id)


# ── Ensure MongoDB indexes on first request ───────────────────────────────────
with app.app_context():
    User.ensure_indexes()

# ── In-memory scan state (unchanged) ─────────────────────────────────────────
scan_store  = {}
event_store = {}
SCAN_MODES = {"fast", "deep"}
SCAN_RATE_LIMIT_MAX = int(os.environ.get("SCAN_RATE_LIMIT_MAX", "5"))
SCAN_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("SCAN_RATE_LIMIT_WINDOW_SECONDS", "3600"))
MAX_ACTIVE_SCANS_PER_USER = int(os.environ.get("MAX_ACTIVE_SCANS_PER_USER", "1"))
scan_quota_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────

def push(scan_id, event_type, data):
    if scan_id not in event_store:
        return
    event_store[scan_id]["events"].append(
        json.dumps({"type": event_type, "data": data})
    )


def log(scan_id, msg, level="info", request_data=None):
    d = {"msg": msg, "level": level}
    if request_data:
        d["request"] = request_data
    push(scan_id, "log", d)


def phase(scan_id, name, status, count=None):
    d = {"phase": name, "status": status}
    if count is not None:
        d["count"] = count
    push(scan_id, "phase", d)


def vuln_event(scan_id, category, data):
    push(scan_id, "vuln", {"category": category, "data": data})


def finding_signature(category, finding):
    parsed = urlparse(finding.get("url", ""))
    endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.netloc else parsed.path
    parameter = finding.get("parameter") or finding.get("param") or ""
    vuln_type = finding.get("type") or ""
    evidence = finding.get("matched_error") or finding.get("evidence") or ""
    return (category, endpoint, parameter, vuln_type, evidence)


def mark_skipped(scan_id, phase_name, reason):
    phase(scan_id, phase_name, "skipped", 0)
    log(scan_id, f"Skipping {reason} in fast scan mode.", "warn")


def get_active_scan_count_for_user(user_id):
    return sum(
        1
        for store in event_store.values()
        if store.get("owner_id") == user_id and not store.get("done")
    )


def get_scan_quota_context(user_id):
    quota = User.get_scan_quota_status(
        user_id=user_id,
        window_seconds=SCAN_RATE_LIMIT_WINDOW_SECONDS,
        max_scans=SCAN_RATE_LIMIT_MAX,
    )
    quota["active_scans"] = get_active_scan_count_for_user(user_id)
    quota["max_active_scans"] = MAX_ACTIVE_SCANS_PER_USER
    return quota


def user_owns_scan(scan_id):
    store = scan_store.get(scan_id) or event_store.get(scan_id)
    return bool(store and store.get("owner_id") == current_user.id)


# ── Background scan runner ────────────────────────────────────────────────────

def run_scan(scan_id, target, scan_mode):
    try:
        phase(scan_id, "nmap",  "running")
        phase(scan_id, "crawl", "running")
        log(scan_id, f"Starting {scan_mode} scan on {target}…")
        log(scan_id, f"Running port scan + crawl for {scan_mode} mode…")

        with ThreadPoolExecutor(max_workers=2) as ex:
            nmap_future  = ex.submit(run_nmap, target)
            crawl_future = ex.submit(crawl, target)
            nmap_result  = nmap_future.result()
            pages        = crawl_future.result()

        analysed_result = analyse_nmap(nmap_result)
        open_port_count = len(analysed_result) if analysed_result else 0

        phase(scan_id, "nmap",  "done", open_port_count)
        phase(scan_id, "crawl", "done", len(pages))
        log(scan_id,
            f"Found {open_port_count} open port(s), {len(pages)} page(s) to test.",
            "success")

        sqli_vulns = []
        xss_vulns  = []
        lfi_vulns  = []
        bruteforce_result = {
            "waf_detected": False,
            "waf_detail": None,
            "bypass_hints": [],
            "login_forms": 0,
            "attempts": 0,
            "credentials_found": [],
            "blocked_payloads": [],
            "candidate_pages": 0,
            "rate_limit_probe": {
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
        file_findings = []
        subdomain_findings = []

        phase(scan_id, "sqli", "running")
        phase(scan_id, "xss",  "running")
        if scan_mode == "deep":
            phase(scan_id, "lfi", "running")
            phase(scan_id, "brute", "pending")
            log(scan_id, "Injecting payloads across all discovered pages…")
        else:
            mark_skipped(scan_id, "lfi", "LFI checks")
            mark_skipped(scan_id, "brute", "brute-force checks")
            mark_skipped(scan_id, "files", "file exposure checks")
            mark_skipped(scan_id, "subd", "subdomain enumeration")
            log(scan_id, "Fast mode enabled: running only the quickest core checks.", "warn")

        with ThreadPoolExecutor(max_workers=10) as ex:
            sqli_futures = {ex.submit(scan_sqli, p): p for p in pages}
            xss_futures  = {ex.submit(scan_xss,  p): p for p in pages}
            lfi_futures  = {ex.submit(scan_lfi,  p): p for p in pages} if scan_mode == "deep" else {}
            seen_findings = set()

            for future in as_completed(sqli_futures):
                try:
                    for v in future.result():
                        sig = finding_signature("sqli", v)
                        if sig in seen_findings:
                            continue
                        seen_findings.add(sig)
                        sqli_vulns.append(v)
                        vuln_event(scan_id, "sqli", v)
                        log(scan_id,
                            f"[SQLi] {v.get('type','?')} on param '{v.get('parameter','?')}'"
                            f" at {v.get('url','?')}",
                            "vuln",
                            {"method": "POST", "url": v.get("url"),
                             "param": v.get("parameter"), "payload": v.get("payload")})
                except Exception as e:
                    log(scan_id, f"SQLi error: {e}", "error")

            for future in as_completed(xss_futures):
                try:
                    for v in future.result():
                        sig = finding_signature("xss", v)
                        if sig in seen_findings:
                            continue
                        seen_findings.add(sig)
                        xss_vulns.append(v)
                        vuln_event(scan_id, "xss", v)
                        log(scan_id,
                            f"[XSS] {v.get('type','?')} on param '{v.get('parameter','?')}'"
                            f" at {v.get('url','?')}",
                            "vuln",
                            {"method": "GET", "url": v.get("url"),
                             "param": v.get("parameter"), "payload": v.get("payload")})
                except Exception as e:
                    log(scan_id, f"XSS error: {e}", "error")

            if scan_mode == "deep":
                for future in as_completed(lfi_futures):
                    try:
                        for v in future.result():
                            sig = finding_signature("lfi", v)
                            if sig in seen_findings:
                                continue
                            seen_findings.add(sig)
                            lfi_vulns.append(v)
                            vuln_event(scan_id, "lfi", v)
                            log(scan_id,
                                f"[LFI] Path traversal on param '{v.get('parameter','?')}'"
                                f" at {v.get('url','?')}",
                                "vuln",
                                {"method": "GET", "url": v.get("url"),
                                 "param": v.get("parameter"), "payload": v.get("payload")})
                    except Exception as e:
                        log(scan_id, f"LFI error: {e}", "error")

        phase(scan_id, "sqli", "done", len(sqli_vulns))
        phase(scan_id, "xss",  "done", len(xss_vulns))
        if scan_mode == "deep":
            phase(scan_id, "lfi",  "done", len(lfi_vulns))
        log(scan_id,
            f"Injection tests complete — {len(sqli_vulns)} SQLi, "
            f"{len(xss_vulns)} XSS, {len(lfi_vulns)} LFI.",
            "success")

        if scan_mode == "deep":
            phase(scan_id, "brute", "running")
            log(scan_id, "Inspecting authentication forms and testing a small credential list…")
            bruteforce_result = scan_bruteforce(target, pages=pages)
            credential_count = len(bruteforce_result.get("credentials_found", []))
            phase(scan_id, "brute", "done", credential_count)

            if bruteforce_result.get("waf_detected"):
                log(
                    scan_id,
                    f"Brute-force checks paused because a WAF was detected: {bruteforce_result.get('waf_detail')}",
                    "warn",
                )
            else:
                log(
                    scan_id,
                    f"Brute-force checked {bruteforce_result.get('login_forms', 0)} login form(s) across "
                    f"{bruteforce_result.get('candidate_pages', 0)} candidate page(s) with "
                    f"{bruteforce_result.get('attempts', 0)} attempt(s).",
                    "success",
                )
                rate_probe = bruteforce_result.get("rate_limit_probe", {})
                if rate_probe.get("tested"):
                    if rate_probe.get("blocked"):
                        log(
                            scan_id,
                            f"Request-threshold probe was blocked after {rate_probe.get('allowed_before_block', 0)} successful request(s) "
                            f"with HTTP {rate_probe.get('block_status')}.",
                            "warn",
                        )
                    else:
                        log(
                            scan_id,
                            f"Request-threshold probe sent {rate_probe.get('requests_sent', 0)} rapid request(s) without hitting an explicit rate limit.",
                            "success",
                        )

            for finding in bruteforce_result.get("credentials_found", []):
                vuln_event(scan_id, "bruteforce", finding)
                log(
                    scan_id,
                    f"[Brute Force] Valid credentials found for {finding.get('login_url', finding.get('url', '?'))}",
                    "vuln",
                    {
                        "method": finding.get("method", "POST"),
                        "url": finding.get("login_url") or finding.get("url"),
                        "param": "credentials",
                        "payload": f"{finding.get('username')} / {finding.get('password')}",
                    },
                )

            phase(scan_id, "files", "running")
            phase(scan_id, "subd",  "running")
            log(scan_id, "Checking file exposure and enumerating subdomains…")

            with ThreadPoolExecutor(max_workers=2) as ex:
                file_future        = ex.submit(scan_file_exposure, target)
                subdomain_future   = ex.submit(scan_subdomains, target)
                file_findings      = file_future.result()
                subdomain_findings = subdomain_future.result()

            phase(scan_id, "files", "done", len(file_findings)      if file_findings      else 0)
            phase(scan_id, "subd",  "done", len(subdomain_findings) if subdomain_findings else 0)
            log(scan_id,
                f"Found {len(file_findings) if file_findings else 0} exposed file(s), "
                f"{len(subdomain_findings) if subdomain_findings else 0} subdomain(s).",
                "success")

        scan_store[scan_id] = {
            "scan_mode":           scan_mode,
            "target_url":          target,
            "open_ports":          analysed_result,
            "pages_scanned":       len(pages),
            "pages":               pages,
            "vulnerabilities":     sqli_vulns,
            "xss_vulnerabilities": xss_vulns,
            "lfi_vulnerabilities": lfi_vulns,
            "bruteforce_result":   bruteforce_result,
            "file_findings":       file_findings,
            "subdomain_findings":  subdomain_findings,
            "owner_id":            event_store[scan_id].get("owner_id"),
        }

        log(scan_id, "Scan complete. Building report…", "success")
        push(scan_id, "done", {"scan_id": scan_id})

    except Exception as e:
        log(scan_id, f"Scan failed: {e}", "error")
        push(scan_id, "error", {"msg": str(e)})
    finally:
        event_store[scan_id]["done"] = True


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def home():
    if current_user.is_authenticated:
        return render_template("landing.html", logged_in=True)
    return render_template("landing.html", logged_in=False)


@app.route("/dashboard", methods=["GET"])
@login_required
def index():
    return render_template("index.html", scan_quota=get_scan_quota_context(current_user.id))


@app.route("/start-scan", methods=["POST"])
@login_required
def start_scan():
    target = request.form.get("url", "").strip()
    scan_mode = request.form.get("scan_mode", "deep").strip().lower()

    if not target:
        return jsonify({"error": "No URL provided."}), 400

    if scan_mode not in SCAN_MODES:
        return jsonify({"error": "Invalid scan mode."}), 400

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    hostname = urlparse(target).hostname
    try:
        socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return jsonify({"error": f"Could not resolve hostname '{hostname}'."}), 400

    try:
        req.head(target, timeout=5, allow_redirects=True)
    except req.exceptions.ConnectionError:
        return jsonify({"error": f"Could not connect to '{target}'."}), 400
    except req.exceptions.Timeout:
        return jsonify({"error": f"Connection to '{target}' timed out."}), 400
    except req.exceptions.RequestException as e:
        return jsonify({"error": f"Invalid or unreachable URL: {e}"}), 400

    scan_id = str(uuid.uuid4())
    with scan_quota_lock:
        active_scans = get_active_scan_count_for_user(current_user.id)
        if active_scans >= MAX_ACTIVE_SCANS_PER_USER:
            return jsonify({
                "error": "You already have a scan running. Please wait for it to finish.",
                "rate_limit": get_scan_quota_context(current_user.id),
            }), 429

        quota_result = User.consume_scan_quota(
            user_id=current_user.id,
            window_seconds=SCAN_RATE_LIMIT_WINDOW_SECONDS,
            max_scans=SCAN_RATE_LIMIT_MAX,
        )
        if not quota_result.get("allowed"):
            return jsonify({
                "error": f"Scan limit reached. Try again in about {quota_result.get('retry_after', 60)} seconds.",
                "retry_after_seconds": quota_result.get("retry_after", 60),
                "rate_limit": get_scan_quota_context(current_user.id),
            }), 429
        event_store[scan_id] = {"events": [], "done": False, "owner_id": current_user.id}

    thread = threading.Thread(target=run_scan, args=(scan_id, target, scan_mode), daemon=True)
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "target": target,
        "scan_mode": scan_mode,
        "rate_limit": get_scan_quota_context(current_user.id),
    })


@app.route("/stream/<scan_id>")
@login_required
def stream(scan_id):
    owner_id = current_user.id

    def generate():
        store = event_store.get(scan_id)
        if not store:
            yield f"data: {json.dumps({'type':'error','data':{'msg':'Scan not found.'}})}\n\n"
            return
        if store.get("owner_id") != owner_id:
            yield f"data: {json.dumps({'type':'error','data':{'msg':'Access denied.'}})}\n\n"
            return

        cursor = 0
        while True:
            events = store["events"]

            while cursor < len(events):
                yield f"data: {events[cursor]}\n\n"
                cursor += 1

            if store["done"] and cursor >= len(events):
                break

            time.sleep(0.2)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/report/<scan_id>")
@login_required
def report(scan_id):
    data = scan_store.get(scan_id)
    if not data or not user_owns_scan(scan_id):
        return render_template("error.html",
                               message="Report not found or scan still running.")
    data.setdefault("bruteforce_result", {
        "waf_detected": False,
        "waf_detail": None,
        "bypass_hints": [],
        "login_forms": 0,
        "attempts": 0,
        "credentials_found": [],
        "blocked_payloads": [],
        "candidate_pages": 0,
        "rate_limit_probe": {
            "tested": False,
            "requests_sent": 0,
            "allowed_before_block": 0,
            "blocked": False,
            "blocked_at_request": None,
            "block_status": None,
            "average_response_ms": None,
            "statuses": [],
        },
    })
    return render_template(
        "report.html",
        scan_id=scan_id,
        pdf_mode=False,
        stylesheet_href=url_for("static", filename="style.css"),
        **data,
    )


@app.route("/download/<scan_id>")
@login_required
def download(scan_id):
    data = scan_store.get(scan_id)
    if not data or not user_owns_scan(scan_id):
        return render_template("error.html", message="Scan report not found or expired.")
    data.setdefault("bruteforce_result", {
        "waf_detected": False,
        "waf_detail": None,
        "bypass_hints": [],
        "login_forms": 0,
        "attempts": 0,
        "credentials_found": [],
        "blocked_payloads": [],
        "candidate_pages": 0,
        "rate_limit_probe": {
            "tested": False,
            "requests_sent": 0,
            "allowed_before_block": 0,
            "blocked": False,
            "blocked_at_request": None,
            "block_status": None,
            "average_response_ms": None,
            "statuses": [],
        },
    })

    try:
        stylesheet_href = (Path(app.root_path) / "static" / "report_pdf.css").resolve().as_uri()
        html_content = render_template(
            "report.html",
            scan_id=scan_id,
            pdf_mode=True,
            stylesheet_href=stylesheet_href,
            **data,
        )
        pdf = HTML(
            string=html_content,
            base_url=Path(app.root_path).resolve().as_uri(),
        ).write_pdf()
    except Exception as e:
        return (
            render_template(
                "error.html",
                message=f"Unable to generate the PDF report right now: {e}",
            ),
            500,
        )

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        f"attachment; filename=scan_report_{scan_id[:8]}.pdf"
    )
    return response


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
