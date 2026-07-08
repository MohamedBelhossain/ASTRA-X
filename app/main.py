import json
import logging
import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import wraps
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, make_response, redirect, render_template, request, stream_with_context, url_for
from flask_login import LoginManager, current_user, login_required
from weasyprint import HTML

APP_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(APP_DIR)
ROOT_ENV_PATH = os.path.join(ROOT_DIR, ".env")
APP_ENV_PATH = os.path.join(APP_DIR, ".env")
if os.environ.get("RUNNING_IN_DOCKER", "").lower() not in {"1", "true", "yes", "on"}:
    load_dotenv(ROOT_ENV_PATH)
    load_dotenv(APP_ENV_PATH, override=False)

from app.auth import auth, bcrypt, mail
from app.models import RateLimitBucket, ResetToken, ScanRecord, User, mongo, serialize_document
from app.scanner.analyser import analyse_nmap
from app.scanner.bruteforce_scanner import scan_bruteforce
from app.scanner.cms_scanner import scan_cms
from app.scanner.crawler import crawl
from app.scanner.file_exposure import scan_file_exposure
from app.scanner.header_scanner import scan_security_headers
from app.scanner.lfi_scanner import scan_lfi
from app.scanner.nmap import run_nmap
from app.scanner.sqli_scanner import scan_sqli
from app.scanner.subdomain_scanner import scan_subdomains
from app.scanner.xss_scanner import scan_xss
from app.reporting import SCAN_USAGE_NOTICE, build_risk_summary, empty_risk_summary, enrich_report_with_proofs
from app.security import (
    SSRFValidator,
    TargetValidationError,
    bool_env,
    register_security_headers,
    register_template_helpers,
    resolve_public_target,
)


class ConsoleFormatter(logging.Formatter):
    def format(self, record):
        return f"[{record.levelname}] {record.getMessage()}"


def configure_console_logging():
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ConsoleFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers[:] = [handler]
    root_logger.setLevel(logging.WARNING)

    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("webvulnscan.scanner").setLevel(logging.DEBUG)
    app.logger.handlers[:] = []
    app.logger.propagate = True


def local_project_url(host, port):
    visible_host = "127.0.0.1" if host in {"0.0.0.0", "::", ""} else host
    return f"http://{visible_host}:{port}"


app = Flask(__name__)


def normalize_mongo_uri(uri, default_database="webvuln"):
    parsed = urlparse(uri)
    if parsed.scheme.startswith("mongodb") and parsed.netloc and parsed.path in {"", "/"}:
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if parsed.username and "authSource" not in query:
            query["authSource"] = "admin"
        return urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                f"/{default_database}",
                parsed.params,
                urlencode(query),
                parsed.fragment,
            )
        )
    return uri


app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-key-change-me"),
    MONGO_URI=normalize_mongo_uri(
        os.environ.get("MONGO_URI", "mongodb://localhost:27017/webvuln"),
        os.environ.get("MONGO_DB_NAME", "webvuln"),
    ),
    MAIL_SERVER=os.environ.get("MAIL_SERVER", "smtp-relay.brevo.com"),
    MAIL_PORT=int(os.environ.get("MAIL_PORT", 587)),
    MAIL_USE_TLS=os.environ.get("MAIL_USE_TLS", "true").lower() == "true",
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME", "").strip(),
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD", "").strip(),
    MAIL_DEFAULT_SENDER=os.environ.get("MAIL_DEFAULT_SENDER", "").strip(),
    MAIL_TIMEOUT=int(os.environ.get("MAIL_TIMEOUT", "10")),
    BREVO_API_KEY=os.environ.get("BREVO_API_KEY", "").strip(),
    MAIL_CONSOLE_FALLBACK=os.environ.get("MAIL_CONSOLE_FALLBACK", "false").lower() == "true",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=bool_env(os.environ.get("SESSION_COOKIE_SECURE"), default=False),
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
    REMEMBER_COOKIE_SECURE=bool_env(os.environ.get("SESSION_COOKIE_SECURE"), default=False),
)
app.logger.info(
    "Mail config loaded. server=%s port=%s tls=%s username_configured=%s "
    "password_configured=%s sender_configured=%s brevo_api_configured=%s console_fallback=%s",
    app.config.get("MAIL_SERVER"),
    app.config.get("MAIL_PORT"),
    app.config.get("MAIL_USE_TLS"),
    bool(app.config.get("MAIL_USERNAME")),
    bool(app.config.get("MAIL_PASSWORD")),
    bool(app.config.get("MAIL_DEFAULT_SENDER")),
    bool(app.config.get("BREVO_API_KEY")),
    app.config.get("MAIL_CONSOLE_FALLBACK"),
)

mongo.init_app(app)
bcrypt.init_app(app)
mail.init_app(app)
app.register_blueprint(auth)
register_template_helpers(app)
register_security_headers(app)

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"
login_manager.init_app(app)

SCAN_MODES = {"fast", "deep"}
SCAN_RATE_LIMIT_MAX = int(os.environ.get("SCAN_RATE_LIMIT_MAX", "5"))
SCAN_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("SCAN_RATE_LIMIT_WINDOW_SECONDS", "3600"))
MAX_ACTIVE_SCANS_PER_USER = int(os.environ.get("MAX_ACTIVE_SCANS_PER_USER", "1"))
SCAN_WORKERS = int(os.environ.get("SCAN_WORKERS", "2"))
INJECTION_WORKERS = int(os.environ.get("INJECTION_WORKERS", "12"))
ACTIVE_TEST_MAX_PAGES = int(os.environ.get("ACTIVE_TEST_MAX_PAGES", "8"))
LFI_MAX_PAGES = int(os.environ.get("LFI_MAX_PAGES", "12"))
LFI_MAX_PARAMS = int(os.environ.get("LFI_MAX_PARAMS", "3"))
LFI_MAX_PAYLOADS = int(os.environ.get("LFI_MAX_PAYLOADS", "6"))
LFI_AGGRESSIVE = bool_env(os.environ.get("LFI_AGGRESSIVE"), default=False)
ALLOW_PRIVATE_TARGETS = bool_env(os.environ.get("ALLOW_PRIVATE_TARGETS"), default=False)
REVEAL_DISCOVERED_CREDENTIALS = bool_env(os.environ.get("REVEAL_DISCOVERED_CREDENTIALS"), default=False)
scan_executor = ThreadPoolExecutor(max_workers=SCAN_WORKERS)
scan_jobs = {}


class ScanCancelled(Exception):
    """Raised when a scan is cancelled."""


@login_manager.user_loader
def load_user(user_id):
    return User.find_by_id(user_id)


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            return render_template("error.html", message="Admin access required."), 403
        return view(*args, **kwargs)

    return wrapped


def ensure_bootstrap_admin():
    email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    username = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
    password = os.environ.get("ADMIN_PASSWORD", "").strip()

    if not email or not password:
        return

    User.ensure_admin(
        username=username,
        email=email,
        hashed_password=bcrypt.generate_password_hash(password).decode("utf-8"),
    )


@app.before_request
def _ensure_indexes():
    if getattr(app, "_indexes_created", False):
        return

    try:
        User.ensure_indexes()
        ResetToken.ensure_indexes()
        RateLimitBucket.ensure_indexes()
        ScanRecord.ensure_indexes()
        ensure_bootstrap_admin()
        if not getattr(app, "_interrupted_scans_recovered", False):
            recovered = ScanRecord.mark_interrupted_active(
                "Scan worker was interrupted by an application restart. Please start a new scan."
            )
            if recovered:
                app.logger.warning("Marked %s interrupted scan(s) as failed after startup.", recovered)
            app._interrupted_scans_recovered = True
        app._indexes_created = True
    except Exception as exc:
        app.logger.warning("Could not create indexes: %s", exc)


def default_report(scan_mode, target):
    return {
        "scan_mode": scan_mode,
        "target_url": target,
        "usage_notice": SCAN_USAGE_NOTICE,
        "risk_summary": empty_risk_summary(),
        "pages_scanned": 0,
        "pages": [],
        "crawl_diagnostics": {
            "status_counts": {},
            "blocked_urls": [],
            "timeout_urls": [],
            "error_urls": [],
            "challenge_urls": [],
            "pages_fetched": 0,
            "pages_parsed": 0,
            "sitemap_urls": 0,
            "anti_bot_detected": False,
            "anti_bot_reasons": [],
            "visited_urls": 0,
            "discovered_pages": 0,
        },
        "open_ports": [],
        "cms_result": {
            "detected": {
                "detected": False,
                "name": None,
                "version": None,
                "confidence": "none",
                "evidence": [],
            },
            "cves": [],
            "cve_source": "NVD",
            "cve_lookup": "keyword",
        },
        "header_result": {
            "url": target,
            "status": None,
            "headers": {},
            "findings": [],
            "error": None,
        },
        "vulnerabilities": [],
        "xss_vulnerabilities": [],
        "lfi_vulnerabilities": [],
        "bruteforce_result": {
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
        },
        "file_findings": [],
        "subdomain_findings": [],
    }


def push(scan_id, event_type, data):
    ScanRecord.append_event(scan_id, event_type, serialize_document(data))


def log(scan_id, msg, level="info", request_data=None):
    payload = {"msg": msg, "level": level}
    if request_data:
        payload["request"] = serialize_document(request_data)
    push(scan_id, "log", payload)


def phase(scan_id, name, status, count=None):
    payload = {"phase": name, "status": status}
    if count is not None:
        payload["count"] = count
    ScanRecord.update_phase(scan_id, name, status, count=count)
    push(scan_id, "phase", payload)


def vuln_event(scan_id, category, data):
    push(scan_id, "vuln", {"category": category, "data": serialize_document(data)})


def crawl_page_event(scan_id, url, count):
    ScanRecord.update_phase(scan_id, "crawl", "running", count=count)
    push(scan_id, "crawl_page", {"url": url, "count": count})


def port_event(scan_id, port):
    push(scan_id, "port", serialize_document(port))


def progress_event(scan_id, phase_name, data):
    push(scan_id, "progress", {"phase": phase_name, **serialize_document(data)})


def mark_skipped(scan_id, phase_name, reason):
    phase(scan_id, phase_name, "skipped", 0)
    log(scan_id, f"Skipping {reason}.", "warn")


def get_active_scan_count_for_user(user_id):
    return ScanRecord.count_active_for_user(user_id)


def get_scan_quota_context(user_id, is_admin=False):
    active_scans = get_active_scan_count_for_user(user_id)
    if is_admin:
        return {
            "allowed": True,
            "admin_unlimited": True,
            "active_scans": active_scans,
            "count": 0,
            "limit": "unlimited",
            "max_active_scans": "unlimited",
            "remaining": "unlimited",
            "reset_in": 0,
            "used": 0,
            "window_seconds": SCAN_RATE_LIMIT_WINDOW_SECONDS,
        }

    quota = RateLimitBucket.status(
        namespace="scan_start",
        key=str(user_id),
        limit=SCAN_RATE_LIMIT_MAX,
        window_seconds=SCAN_RATE_LIMIT_WINDOW_SECONDS,
    )
    quota["active_scans"] = get_active_scan_count_for_user(user_id)
    quota["max_active_scans"] = MAX_ACTIVE_SCANS_PER_USER
    return quota


def consume_scan_quota(user_id):
    status = RateLimitBucket.check_and_record(
        namespace="scan_start",
        key=str(user_id),
        limit=SCAN_RATE_LIMIT_MAX,
        window_seconds=SCAN_RATE_LIMIT_WINDOW_SECONDS,
    )
    return {
        "allowed": status["allowed"],
        "remaining": max(0, SCAN_RATE_LIMIT_MAX - status["count"]),
        "retry_after": status.get("retry_after", 0),
    }


def can_start_more_scans(user_id, is_admin=False):
    if is_admin:
        return True
    return get_active_scan_count_for_user(user_id) < MAX_ACTIVE_SCANS_PER_USER


def should_stop(scan_id):
    return ScanRecord.is_cancel_requested(scan_id)


def raise_if_cancelled(scan_id):
    if should_stop(scan_id):
        raise ScanCancelled()


def user_owns_scan(scan_id):
    if getattr(current_user, "is_admin", False):
        return bool(ScanRecord.find_by_scan_id(scan_id))
    return bool(ScanRecord.find_owned(scan_id, current_user.id))


def scan_doc_for_current_user(scan_id):
    if getattr(current_user, "is_admin", False):
        return ScanRecord.find_by_scan_id(scan_id)
    return ScanRecord.find_owned(scan_id, current_user.id)


def report_for_current_user(scan_id):
    if getattr(current_user, "is_admin", False):
        data = ScanRecord.serializable_report(scan_id)
    else:
        data = ScanRecord.serializable_report_for_owner(scan_id, current_user.id)
    if data:
        enrich_report_with_proofs(data)
    return data


def scan_doc_for_user(scan_id, user_id, is_admin=False):
    if is_admin:
        return ScanRecord.find_by_scan_id(scan_id)
    return ScanRecord.find_owned(scan_id, user_id)


def _admin_user_map(scans):
    owner_ids = {str(scan.get("owner_id")) for scan in scans if scan.get("owner_id")}
    users = User.list_by_ids(owner_ids)
    return {str(user.get("_id")): user for user in users}


def _report_finding_counts(report):
    report = report or {}
    bruteforce = report.get("bruteforce_result") or {}
    header = report.get("header_result") or {}
    cms = report.get("cms_result") or {}
    counts = {
        "sqli": len(report.get("vulnerabilities") or []),
        "xss": len(report.get("xss_vulnerabilities") or []),
        "lfi": len(report.get("lfi_vulnerabilities") or []),
        "files": len(report.get("file_findings") or []),
        "headers": len(header.get("findings") or []),
        "cves": len(cms.get("cves") or []),
        "credentials": len(bruteforce.get("credentials_found") or []),
    }
    counts["total"] = sum(counts.values())
    return counts


def _risk_level_from_report(report):
    risk = (report or {}).get("risk_summary") or {}
    risk_level = (risk.get("risk_level") or "none").lower()
    if risk_level != "none":
        return risk_level

    counts = _report_finding_counts(report)
    if counts["credentials"] or counts["lfi"]:
        return "critical"
    if counts["sqli"] or counts["xss"] or counts["files"] or counts["cves"]:
        return "high"
    if counts["headers"]:
        return "medium"
    return "none"


def _coerce_datetime(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _scan_runtime_label(scan):
    started = _coerce_datetime(scan.get("started_at")) or _coerce_datetime(scan.get("created_at"))
    finished = _coerce_datetime(scan.get("finished_at"))
    if not started:
        return "—"
    end = finished or datetime.utcnow()
    try:
        seconds = max(0, int((end - started).total_seconds()))
    except Exception:
        return "—"
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _last_event_summary(scan):
    events = scan.get("events") or []
    for event in reversed(events):
        data = event.get("data") or {}
        message = data.get("msg") or data.get("message")
        if message:
            return {
                "type": event.get("type", "event"),
                "message": message,
                "level": data.get("level", "info"),
            }
    if scan.get("last_error"):
        return {"type": "error", "message": scan["last_error"], "level": "error"}
    return {"type": "status", "message": scan.get("status", "unknown"), "level": "info"}


def _admin_scan_row(scan, users_by_id):
    report = scan.get("report") or {}
    owner_id = str(scan.get("owner_id") or "")
    user = users_by_id.get(owner_id, {})
    counts = _report_finding_counts(report)
    return {
        "scan_id": scan.get("scan_id"),
        "target_url": scan.get("target_url"),
        "target_host": scan.get("target_host"),
        "scan_mode": scan.get("scan_mode", "deep"),
        "status": scan.get("status", "unknown"),
        "risk_level": _risk_level_from_report(report),
        "finding_counts": counts,
        "runtime": _scan_runtime_label(scan),
        "last_event": _last_event_summary(scan),
        "owner": {
            "id": owner_id,
            "username": user.get("username") or "Unknown",
            "email": user.get("email") or "Unknown",
        },
        "created_at": serialize_document(scan.get("created_at")),
        "last_error": scan.get("last_error"),
        "is_active": scan.get("status") in ScanRecord.ACTIVE_STATUSES,
    }


def _admin_triage_item(scan, users_by_id):
    row = _admin_scan_row(scan, users_by_id)
    report = scan.get("report") or {}
    counts = row["finding_counts"]
    risk = row["risk_level"]
    status = row["status"]
    reasons = []
    score = 0

    if status == "failed":
        score += 80
        reasons.append("Scan failed")
    if row["is_active"]:
        score += 45
        reasons.append("Active scan")
    if risk == "critical":
        score += 100
        reasons.append("Critical risk")
    elif risk == "high":
        score += 70
        reasons.append("High risk")
    elif risk == "medium":
        score += 35
        reasons.append("Medium risk")
    if counts["credentials"]:
        score += 80
        reasons.append("Credentials found")
    if counts["lfi"]:
        score += 60
        reasons.append("LFI confirmed")
    if counts["total"] >= 5:
        score += 25
        reasons.append(f"{counts['total']} findings")
    if (report.get("crawl_diagnostics") or {}).get("anti_bot_detected"):
        score += 20
        reasons.append("WAF / anti-bot signals")
    if scan.get("last_error") and status != "failed":
        score += 15
        reasons.append("Has error detail")

    if score >= 100:
        priority = "critical"
    elif score >= 70:
        priority = "high"
    elif score >= 35:
        priority = "medium"
    else:
        priority = "low"

    row.update(
        {
            "priority": priority,
            "priority_score": score,
            "reasons": reasons[:4] or ["Monitor"],
        }
    )
    return row


def finding_request_data(category, finding):
    payload = finding.get("payload")
    if category == "bruteforce":
        payload = f"{finding.get('username')} / {'********' if finding.get('password') else ''}"
    return {
        "method": finding.get("method", "GET"),
        "url": finding.get("login_url") or finding.get("url"),
        "param": finding.get("parameter") or finding.get("param") or "credentials",
        "payload": payload,
        "evidence": finding.get("evidence"),
        "confidence": finding.get("confidence"),
        "severity": finding.get("severity"),
    }


def redact_discovered_credentials(bruteforce_result):
    if REVEAL_DISCOVERED_CREDENTIALS:
        return bruteforce_result
    sanitized = dict(bruteforce_result or {})
    sanitized["credentials_found"] = [
        {**finding, "password": "********", "password_redacted": True}
        for finding in sanitized.get("credentials_found", [])
    ]
    return sanitized


def _has_query_params(url):
    return bool(urlparse(url).query)


def _canonical_url_key(url):
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((scheme, netloc, path, "", query, ""))


def unique_scan_pages(target, pages):
    ordered = []
    seen = set()

    for url in [target, *(pages or [])]:
        key = _canonical_url_key(url)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(url)

    return ordered


def _is_lfi_candidate(url):
    parsed = urlparse(url)
    query = parsed.query.lower()
    path = parsed.path.lower()
    suspicious_tokens = ("file", "path", "page", "include", "template", "view", "doc")
    return bool(query) and (
        any(token in query for token in suspicious_tokens)
        or any(token in path for token in suspicious_tokens)
    )


def finalize_scan(scan_id, status, report, last_error=None):
    report["usage_notice"] = SCAN_USAGE_NOTICE
    enrich_report_with_proofs(report)
    report["risk_summary"] = build_risk_summary(report)
    ScanRecord.finalize_report(scan_id, report)
    ScanRecord.update_status(scan_id, status, last_error=last_error)
    push(scan_id, "done", {"scan_id": scan_id, "status": status, "error": last_error})


def run_scan(scan_id):
    doc = ScanRecord.find_by_scan_id(scan_id)
    if not doc:
        return

    target = doc["target_url"]
    scan_mode = doc["scan_mode"]
    report = default_report(scan_mode, target)

    try:
        ScanRecord.mark_running(scan_id)
        ssrf_validator = SSRFValidator(allow_private=ALLOW_PRIVATE_TARGETS)
        target_info = ssrf_validator.verify_before_scan(
            target,
            expected_addresses=doc.get("resolved_ips", []),
        )
        log(
            scan_id,
            f"SSRF guard verified {target_info['hostname']} still resolves to "
            f"{', '.join(target_info['addresses'])}.",
        )

        phase(scan_id, "cms", "running")
        phase(scan_id, "headers", "running")
        phase(scan_id, "nmap", "running")
        phase(scan_id, "crawl", "running")
        log(scan_id, f"Starting {scan_mode} scan on {target}...")
        log(scan_id, f"Queued worker picked up the scan using {SCAN_WORKERS} worker slot(s).")

        pages = []
        crawl_diagnostics = {}
        analysed_result = []
        cms_result = report["cms_result"]
        header_result = report["header_result"]
        seen_crawl_pages = set()

        def on_crawl_page(url, count):
            if url in seen_crawl_pages:
                return
            seen_crawl_pages.add(url)
            crawl_page_event(scan_id, url, count)
            log(scan_id, f"[CRAWL] Page {count}: {url}", "info")

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_names = {}
            cms_future = executor.submit(
                scan_cms,
                target,
                should_stop=lambda: should_stop(scan_id),
            )
            future_names[cms_future] = "cms"
            header_future = executor.submit(
                scan_security_headers,
                target,
                should_stop=lambda: should_stop(scan_id),
            )
            future_names[header_future] = "headers"
            nmap_future = executor.submit(run_nmap, target, resolved_ip=target_info["addresses"][0])
            future_names[nmap_future] = "nmap"
            crawl_future = executor.submit(
                crawl,
                target,
                should_stop=lambda: should_stop(scan_id),
                return_diagnostics=True,
                on_page=on_crawl_page,
            )
            future_names[crawl_future] = "crawl"

            for future in as_completed(future_names):
                raise_if_cancelled(scan_id)
                name = future_names[future]

                if name == "cms":
                    cms_result = future.result()
                    report["cms_result"] = cms_result
                    cms_cves = cms_result.get("cves", [])
                    phase(scan_id, "cms", "done", len(cms_cves))
                    cms_detected = cms_result.get("detected", {})
                    if cms_detected.get("detected"):
                        cms_label = cms_detected.get("name")
                        if cms_detected.get("version"):
                            cms_label = f"{cms_label} {cms_detected.get('version')}"
                        log(
                            scan_id,
                            f"Detected CMS: {cms_label} ({cms_detected.get('confidence')} confidence). Found {len(cms_cves)} candidate CVE record(s).",
                            "success" if not cms_cves else "warn",
                        )
                        for finding in cms_cves:
                            vuln_event(scan_id, "cms", finding)
                            log(
                                scan_id,
                                f"[CMS] Candidate CVE {finding.get('id')} for {cms_label}",
                                "vuln",
                                {
                                    "method": "GET",
                                    "url": finding.get("url"),
                                    "param": cms_detected.get("name"),
                                    "payload": cms_detected.get("version"),
                                    "evidence": finding.get("description"),
                                    "confidence": finding.get("confidence"),
                                    "severity": finding.get("severity"),
                                },
                            )
                    else:
                        log(scan_id, "No known CMS fingerprint was detected.", "info")

                elif name == "headers":
                    header_result = future.result()
                    report["header_result"] = header_result
                    header_findings = header_result.get("findings", [])
                    phase(scan_id, "headers", "done", len(header_findings))
                    if header_result.get("error"):
                        log(scan_id, f"Security header check failed: {header_result['error']}", "warn")
                    else:
                        log(
                            scan_id,
                            f"Security header check found {len(header_findings)} issue(s).",
                            "success" if not header_findings else "warn",
                        )
                        for finding in header_findings:
                            vuln_event(scan_id, "headers", finding)
                            log(
                                scan_id,
                                f"[HEADERS] {finding.get('type')} at {finding.get('url')}",
                                "vuln",
                                {
                                    "method": "GET",
                                    "url": finding.get("url"),
                                    "param": finding.get("header"),
                                    "payload": None,
                                    "evidence": finding.get("evidence"),
                                    "confidence": "observed",
                                    "severity": finding.get("severity"),
                                },
                            )

                elif name == "nmap":
                    nmap_result = future.result()
                    analysed_result = analyse_nmap(nmap_result)
                    report["open_ports"] = analysed_result
                    phase(scan_id, "nmap", "done", len(analysed_result))
                    for port in analysed_result:
                        port_event(scan_id, port)
                    log(scan_id, f"Found {len(analysed_result)} open port(s).", "success")

                elif name == "crawl":
                    crawl_result = future.result()
                    pages = unique_scan_pages(target, crawl_result.get("pages", []))
                    crawl_diagnostics = crawl_result.get("diagnostics", {})
                    report["pages"] = pages
                    report["pages_scanned"] = len(pages)
                    report["crawl_diagnostics"] = crawl_diagnostics
                    phase(scan_id, "crawl", "done", len(pages))
                    log(scan_id, f"Crawl complete: {len(pages)} page(s) discovered.", "success")

        raise_if_cancelled(scan_id)

        log(
            scan_id,
            f"Found {len(analysed_result)} open port(s), {len(pages)} page(s) to test.",
            "success",
        )
        if crawl_diagnostics.get("blocked_urls"):
            blocked = crawl_diagnostics["blocked_urls"][:3]
            preview = ", ".join(
                f"{item.get('status')}:{item.get('url')}"
                for item in blocked
            )
            log(
                scan_id,
                f"Crawl encountered blocking responses on {len(crawl_diagnostics['blocked_urls'])} page(s): {preview}",
                "warn",
            )
        if crawl_diagnostics.get("timeout_urls"):
            log(
                scan_id,
                f"Crawl timed out on {len(crawl_diagnostics['timeout_urls'])} page(s).",
                "warn",
            )
        if crawl_diagnostics.get("anti_bot_detected"):
            reasons = "; ".join(crawl_diagnostics.get("anti_bot_reasons", []))
            log(
                scan_id,
                f"Anti-bot or WAF behavior likely detected during crawl. {reasons}",
                "warn",
            )
        if len(pages) <= 1 and (
            crawl_diagnostics.get("blocked_urls")
            or crawl_diagnostics.get("timeout_urls")
            or crawl_diagnostics.get("challenge_urls")
        ):
            log(
                scan_id,
                "Crawl discovered very few pages because the target appears protected or slow. Starting from the site root may work better.",
                "warn",
            )

        crawl_protected = bool(crawl_diagnostics.get("anti_bot_detected") and len(pages) <= 1)
        if crawl_protected:
            log(
                scan_id,
                "The target appears protected, but active checks will still run against the reachable page(s). Some checks may return no findings if forms or query parameters are blocked.",
                "warn",
            )

        phase(scan_id, "sqli", "running")
        phase(scan_id, "xss", "running")
        if scan_mode == "deep":
            phase(scan_id, "lfi", "running")
            phase(scan_id, "brute", "pending")
            log(scan_id, "Injecting payloads across all discovered pages...")
        else:
            mark_skipped(scan_id, "lfi", "LFI checks in fast scan mode")
            mark_skipped(scan_id, "brute", "brute-force checks in fast scan mode")
            mark_skipped(scan_id, "files", "file exposure checks in fast scan mode")
            mark_skipped(scan_id, "subd", "subdomain enumeration in fast scan mode")
            log(scan_id, "Fast mode enabled: running only the quickest core checks.", "warn")

        sqli_vulns = []
        xss_vulns = []
        lfi_vulns = []
        seen_findings = set()
        finding_lock = Lock()
        progress_counts = {"sqli": 0, "xss": 0, "lfi": 0, "brute": 0, "files": 0, "subd": 0}
        progress_by_item = {name: {} for name in progress_counts}

        def collect_one(category, finding, sink):
            if category == "bruteforce" and not REVEAL_DISCOVERED_CREDENTIALS:
                finding = {**finding, "password": "********", "password_redacted": True}
            with finding_lock:
                signature = (
                    category,
                    finding.get("url"),
                    finding.get("parameter") or finding.get("param"),
                    finding.get("type"),
                    finding.get("evidence"),
                )
                if signature in seen_findings:
                    return
                seen_findings.add(signature)
                sink.append(finding)

            vuln_event(scan_id, category, finding)
            log(
                scan_id,
                f"[{category.upper()}] {finding.get('type', category)} on {finding.get('parameter') or finding.get('param') or '?'} at {finding.get('url', '?')}",
                "vuln",
                finding_request_data(category, finding),
            )

        def collect(category, findings, sink):
            for finding in findings:
                collect_one(category, finding, sink)

        def progress_callback(category):
            def _callback(data):
                data = dict(data)
                raw_checked = int(data.get("checked") or 0)
                item_key = (
                    data.get("url")
                    or data.get("path")
                    or data.get("subdomain")
                    or data.get("stage")
                    or "__phase"
                )
                previous = progress_by_item[category].get(item_key, 0)
                progress_by_item[category][item_key] = max(raw_checked, previous)
                progress_counts[category] = sum(progress_by_item[category].values())
                data["checked"] = progress_counts[category]
                progress_event(scan_id, category, data)
            return _callback

        lfi_pages = []
        if scan_mode == "deep":
            suspicious_lfi_pages = [page for page in pages if _is_lfi_candidate(page)]
            other_query_pages = [
                page
                for page in pages
                if _has_query_params(page) and page not in suspicious_lfi_pages
            ]
            lfi_pages = (suspicious_lfi_pages + other_query_pages)[:LFI_MAX_PAGES]
            if len(lfi_pages) < len(pages):
                log(
                    scan_id,
                    f"LFI smart mode: testing {len(lfi_pages)} query page(s) instead of all {len(pages)} crawled page(s).",
                    "info",
                )

        active_pages = pages[:ACTIVE_TEST_MAX_PAGES]
        if len(active_pages) < len(pages):
            log(
                scan_id,
                f"Active checks limited to {len(active_pages)} page(s) out of {len(pages)} discovered page(s) to avoid long-running duplicate or slow target scans.",
                "warn",
            )

        with ThreadPoolExecutor(max_workers=INJECTION_WORKERS) as executor:
            future_info = {}
            remaining_by_category = {"sqli": 0, "xss": 0, "lfi": 0}

            for page in active_pages:
                future = executor.submit(
                    scan_sqli,
                    page,
                    should_stop=lambda: should_stop(scan_id),
                    on_progress=progress_callback("sqli"),
                    on_finding=lambda finding: collect_one("sqli", finding, sqli_vulns),
                )
                future_info[future] = ("sqli", page, sqli_vulns)
                remaining_by_category["sqli"] += 1

                future = executor.submit(
                    scan_xss,
                    page,
                    should_stop=lambda: should_stop(scan_id),
                    on_progress=progress_callback("xss"),
                    on_finding=lambda finding: collect_one("xss", finding, xss_vulns),
                )
                future_info[future] = ("xss", page, xss_vulns)
                remaining_by_category["xss"] += 1

            if scan_mode == "deep":
                for page in lfi_pages:
                    future = executor.submit(
                        scan_lfi,
                        page,
                        should_stop=lambda: should_stop(scan_id),
                        on_progress=progress_callback("lfi"),
                        on_finding=lambda finding: collect_one("lfi", finding, lfi_vulns),
                        max_params=LFI_MAX_PARAMS,
                        max_payloads=LFI_MAX_PAYLOADS,
                        aggressive=LFI_AGGRESSIVE,
                    )
                    future_info[future] = ("lfi", page, lfi_vulns)
                    remaining_by_category["lfi"] += 1

            for future in as_completed(future_info):
                raise_if_cancelled(scan_id)
                category, page, sink = future_info[future]
                try:
                    collect(category, future.result(), sink)
                except Exception as exc:
                    log(scan_id, f"{category.upper()} checks failed on {page}: {exc}", "error")

                remaining_by_category[category] -= 1
                if remaining_by_category[category] == 0:
                    count = {
                        "sqli": len(sqli_vulns),
                        "xss": len(xss_vulns),
                        "lfi": len(lfi_vulns),
                    }[category]
                    phase(scan_id, category, "done", count)
                    log(scan_id, f"{category.upper()} checks finished with {count} finding(s).", "success")

        report["vulnerabilities"] = sqli_vulns
        report["xss_vulnerabilities"] = xss_vulns
        report["lfi_vulnerabilities"] = lfi_vulns

        if remaining_by_category["sqli"] == 0 and not active_pages:
            phase(scan_id, "sqli", "done", len(sqli_vulns))
        if remaining_by_category["xss"] == 0 and not active_pages:
            phase(scan_id, "xss", "done", len(xss_vulns))
        if scan_mode == "deep" and remaining_by_category["lfi"] == 0 and not lfi_pages:
            phase(scan_id, "lfi", "done", len(lfi_vulns))
        log(
            scan_id,
            f"Injection tests complete: {len(sqli_vulns)} SQLi, {len(xss_vulns)} XSS, {len(lfi_vulns)} LFI.",
            "success",
        )

        if scan_mode == "deep":
            raise_if_cancelled(scan_id)

            phase(scan_id, "brute", "running")
            log(scan_id, "Inspecting authentication forms and testing a small credential list...")
            bruteforce_result = scan_bruteforce(
                target,
                pages=pages,
                should_stop=lambda: should_stop(scan_id),
                on_progress=progress_callback("brute"),
                on_finding=lambda finding: collect_one("bruteforce", finding, report["bruteforce_result"]["credentials_found"]),
            )
            raise_if_cancelled(scan_id)

            bruteforce_result = redact_discovered_credentials(bruteforce_result)
            report["bruteforce_result"] = bruteforce_result
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

            for finding in bruteforce_result.get("credentials_found", []):
                finding.setdefault("severity", "critical")
                finding.setdefault("confidence", "confirmed")
                finding.setdefault("evidence", "Valid credentials accepted by target")
                collect_one("bruteforce", finding, report["bruteforce_result"]["credentials_found"])

            phase(scan_id, "files", "running")
            phase(scan_id, "subd", "running")
            log(scan_id, "Checking file exposure and enumerating subdomains...")

            with ThreadPoolExecutor(max_workers=2) as executor:
                followup_futures = {}
                file_future = executor.submit(
                    scan_file_exposure,
                    target,
                    should_stop=lambda: should_stop(scan_id),
                    on_progress=progress_callback("files"),
                    on_finding=lambda finding: collect_one("files", finding, report["file_findings"]),
                )
                followup_futures[file_future] = "files"
                subdomain_future = executor.submit(
                    scan_subdomains,
                    target,
                    should_stop=lambda: should_stop(scan_id),
                    on_progress=progress_callback("subd"),
                    on_finding=lambda finding: collect_one("subd", finding, report["subdomain_findings"]),
                )
                followup_futures[subdomain_future] = "subd"
                file_findings = []
                subdomain_findings = []

                for future in as_completed(followup_futures):
                    raise_if_cancelled(scan_id)
                    category = followup_futures[future]
                    try:
                        findings = future.result()
                    except Exception as exc:
                        log(scan_id, f"{category.upper()} checks failed: {exc}", "error")
                        findings = []

                    if category == "files":
                        file_findings = findings
                        report["file_findings"] = file_findings
                    else:
                        subdomain_findings = findings
                        report["subdomain_findings"] = subdomain_findings

                    phase(scan_id, category, "done", len(findings))
                    log(scan_id, f"{category.upper()} checks finished with {len(findings)} finding(s).", "success")

            raise_if_cancelled(scan_id)
            report["file_findings"] = file_findings
            report["subdomain_findings"] = subdomain_findings
            log(
                scan_id,
                f"Found {len(file_findings)} exposed file(s), {len(subdomain_findings)} subdomain(s).",
                "success",
            )

        log(scan_id, "Scan complete. Building report...", "success")
        finalize_scan(scan_id, "completed", report)

    except ScanCancelled:
        log(scan_id, "Scan cancelled by the user.", "warn")
        finalize_scan(scan_id, "cancelled", report)
    except TargetValidationError as exc:
        app.logger.warning(
            "scan_blocked_by_ssrf_guard",
            extra={
                "security_event": {
                    "event": "blocked_request",
                    "scan_id": scan_id,
                    "target": target,
                    "reason": str(exc),
                }
            },
        )
        log(scan_id, f"Scan blocked by SSRF protection: {exc}", "error")
        finalize_scan(scan_id, "failed", report, last_error=str(exc))
        push(scan_id, "error", {"msg": str(exc)})
    except Exception as exc:
        app.logger.exception("Scan %s failed", scan_id)
        log(scan_id, f"Scan failed: {exc}", "error")
        finalize_scan(scan_id, "failed", report, last_error=str(exc))
        push(scan_id, "error", {"msg": str(exc)})
    finally:
        scan_jobs.pop(scan_id, None)


def render_report_not_found():
    return render_template("error.html", message="Scan report not found or scan still running.")


@app.route("/", methods=["GET"])
def home():
    if current_user.is_authenticated:
        return render_template("landing.html", logged_in=True, usage_notice=SCAN_USAGE_NOTICE)
    return render_template("landing.html", logged_in=False, usage_notice=SCAN_USAGE_NOTICE)


@app.route("/dashboard", methods=["GET"])
@login_required
def index():
    return render_template(
        "index.html",
        scan_quota=get_scan_quota_context(current_user.id, current_user.is_admin),
        scan_history=ScanRecord.list_for_user(current_user.id, limit=12),
        usage_notice=SCAN_USAGE_NOTICE,
    )


@app.route("/admin", methods=["GET"])
@admin_required
def admin_dashboard():
    scan_statuses = ScanRecord.count_by_status()
    recent_scan_docs = ScanRecord.list_recent(limit=40)
    users_by_id = _admin_user_map(recent_scan_docs)
    triage_queue = sorted(
        (_admin_triage_item(scan, users_by_id) for scan in recent_scan_docs),
        key=lambda item: item["priority_score"],
        reverse=True,
    )
    recent_scan_rows = [_admin_scan_row(scan, users_by_id) for scan in recent_scan_docs[:12]]
    return render_template(
        "admin.html",
        stats={
            "users": User.count_all(),
            "admins": User.count_admins(),
            "scans": ScanRecord.count_all(),
            "active_scans": sum(scan_statuses.get(status, 0) for status in ScanRecord.ACTIVE_STATUSES),
            "completed_scans": scan_statuses.get("completed", 0),
            "failed_scans": scan_statuses.get("failed", 0),
            "critical_queue": len([item for item in triage_queue if item["priority"] == "critical"]),
            "high_queue": len([item for item in triage_queue if item["priority"] == "high"]),
        },
        recent_users=User.list_recent(limit=8),
        triage_queue=triage_queue[:12],
        recent_scans=recent_scan_rows,
    )


@app.route("/start-scan", methods=["POST"])
@login_required
def start_scan():
    target = request.form.get("url", "").strip()
    scan_mode = request.form.get("scan_mode", "deep").strip().lower()

    if scan_mode not in SCAN_MODES:
        return jsonify({"error": "Invalid scan mode."}), 400

    try:
        target_info = resolve_public_target(
            target,
            allow_private=ALLOW_PRIVATE_TARGETS,
            verify_head=True,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if not can_start_more_scans(current_user.id, current_user.is_admin):
        return jsonify(
            {
                "error": "You already have a scan running. Please wait for it to finish.",
                "rate_limit": get_scan_quota_context(current_user.id, current_user.is_admin),
            }
        ), 429

    quota_result = {"allowed": True} if current_user.is_admin else consume_scan_quota(current_user.id)
    if not current_user.is_admin and not quota_result.get("allowed"):
        return jsonify(
            {
                "error": f"Scan limit reached. Try again in about {quota_result.get('retry_after', 60)} seconds.",
                "retry_after_seconds": quota_result.get("retry_after", 60),
                "rate_limit": get_scan_quota_context(current_user.id, current_user.is_admin),
            }
        ), 429

    scan_id = str(uuid.uuid4())
    ScanRecord.create(
        scan_id=scan_id,
        owner_id=current_user.id,
        target_url=target_info["target"],
        target_host=target_info["hostname"],
        resolved_ips=target_info["addresses"],
        scan_mode=scan_mode,
    )
    log(scan_id, f"Scan queued for {target_info['target']} ({', '.join(target_info['addresses'])}).")
    log(scan_id, SCAN_USAGE_NOTICE, "warn")

    future = scan_executor.submit(run_scan, scan_id)
    scan_jobs[scan_id] = future

    return jsonify(
        {
            "scan_id": scan_id,
            "target": target_info["target"],
            "scan_mode": scan_mode,
            "rate_limit": get_scan_quota_context(current_user.id, current_user.is_admin),
        }
    )


@app.route("/cancel-scan/<scan_id>", methods=["POST"])
@login_required
def cancel_scan(scan_id):
    if not user_owns_scan(scan_id):
        return jsonify({"error": "Scan not found."}), 404

    future = scan_jobs.get(scan_id)
    if future and future.cancel():
        ScanRecord.append_event(scan_id, "log", {"msg": "Queued scan cancelled before execution.", "level": "warn"})
        ScanRecord.update_status(scan_id, "cancelled")
        push(scan_id, "done", {"scan_id": scan_id, "status": "cancelled"})
        return jsonify({"status": "cancelled"})

    cancel_requested = (
        ScanRecord.request_cancel_any(scan_id)
        if current_user.is_admin
        else ScanRecord.request_cancel(scan_id, current_user.id)
    )
    if cancel_requested:
        log(scan_id, "Cancellation requested. The active worker will stop at the next safe checkpoint.", "warn")
        return jsonify({"status": "cancelling"})

    return jsonify({"error": "This scan is already finished."}), 409


@app.route("/stream/<scan_id>")
@login_required
def stream(scan_id):
    user_id = current_user.id
    is_admin = current_user.is_admin

    @stream_with_context
    def generate():
        cursor = 0
        while True:
            doc = scan_doc_for_user(scan_id, user_id, is_admin=is_admin)
            if not doc:
                yield f"data: {json.dumps({'type': 'error', 'data': {'msg': 'Scan not found.'}})}\n\n"
                return

            events = doc.get("events", [])
            while cursor < len(events):
                event = serialize_document(events[cursor])
                payload = {"type": event.get("type"), "data": event.get("data")}
                yield f"data: {json.dumps(payload)}\n\n"
                cursor += 1

            if doc.get("status") in {"completed", "failed", "cancelled"} and cursor >= len(events):
                break

            time.sleep(0.25)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/report/<scan_id>")
@login_required
def report(scan_id):
    data = report_for_current_user(scan_id)
    if not data:
        return render_report_not_found()
    return render_template(
        "report.html",
        pdf_mode=False,
        stylesheet_href=url_for("static", filename="style.css"),
        **data,
    )


@app.route("/download/<scan_id>")
@login_required
def download(scan_id):
    data = report_for_current_user(scan_id)
    if not data:
        return render_template("error.html", message="Scan report not found or expired.")

    try:
        stylesheet_href = (Path(app.root_path) / "static" / "report_pdf.css").resolve().as_uri()
        html_content = render_template(
            "report.html",
            pdf_mode=True,
            stylesheet_href=stylesheet_href,
            **data,
        )
        pdf = HTML(
            string=html_content,
            base_url=Path(app.root_path).resolve().as_uri(),
        ).write_pdf()
    except Exception as exc:
        return (
            render_template(
                "error.html",
                message=f"Unable to generate the PDF report right now: {exc}",
            ),
            500,
        )

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=scan_report_{scan_id[:8]}.pdf"
    return response


@app.route("/export/<scan_id>.json")
@login_required
def export_json(scan_id):
    data = report_for_current_user(scan_id)
    if not data:
        return jsonify({"error": "Scan report not found."}), 404
    return jsonify(data)


if __name__ == "__main__":
    from flask import cli

    cli.show_server_banner = lambda *args, **kwargs: None

    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", "5000"))
    configure_console_logging()
    print(f"ASTRA-X: {local_project_url(host, port)}", flush=True)
    app.run(
        debug=bool_env(os.environ.get("FLASK_DEBUG"), default=False),
        host=host,
        port=port,
        threaded=True,
    )
