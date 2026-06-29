import hashlib
import hmac
import ipaddress
import logging
import secrets
import socket
import threading
import time
from urllib.parse import urljoin, urlparse

from flask import current_app, g, has_request_context, request, session
import requests


CSRF_SESSION_KEY = "_csrf_token"
LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain"}
SSRF_BLOCKED_PORTS = {25, 465, 587, 3306, 5432, 6379, 27017, 11211, 8080, 8888, 9090}
DNS_VALIDATION_ATTEMPTS = 3
DNS_CACHE_TTL_SECONDS = 300
HEAD_VERIFICATION_TIMEOUT_SECONDS = 5
METADATA_IPS = {"169.254.169.254"}
HSTS_VALUE = "max-age=31536000; includeSubDomains"
PERMISSIONS_POLICY_VALUE = "geolocation=(), camera=(), microphone=(), payment=(), usb=()"

security_logger = logging.getLogger("webvulnscan.security")


class TargetValidationError(ValueError):
    """Raised when a scan target fails validation."""


class SSRFValidator:
    """Validate outbound scan targets against SSRF and DNS rebinding risks."""

    _cache = {}
    _cache_lock = threading.Lock()

    def __init__(
        self,
        *,
        allow_private=False,
        dns_attempts=DNS_VALIDATION_ATTEMPTS,
        cache_ttl=DNS_CACHE_TTL_SECONDS,
        blocked_ports=None,
        head_timeout=HEAD_VERIFICATION_TIMEOUT_SECONDS,
    ):
        # Kept for backward-compatible call sites; mandatory SSRF blocks are always enforced.
        self.allow_private = allow_private
        self.dns_attempts = max(3, int(dns_attempts or DNS_VALIDATION_ATTEMPTS))
        self.cache_ttl = int(cache_ttl or DNS_CACHE_TTL_SECONDS)
        self.blocked_ports = set(blocked_ports or SSRF_BLOCKED_PORTS)
        self.head_timeout = head_timeout

    def validate_target(self, raw_target, *, verify_head=True):
        target = normalize_target(raw_target)
        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        self._validate_hostname(hostname, target)
        self._validate_port(parsed, target)

        cached = self._get_cache(hostname)
        if cached:
            addresses = cached["addresses"]
        else:
            attempts = self._resolve_multiple(hostname, target)
            addresses = attempts[0]
            self._cache_resolution(hostname, addresses)

        blocked = [ip for ip in addresses if self._is_blocked_ip(ip)]
        if blocked:
            self._log_security_event(
                "blocked_request",
                target,
                reason="blocked_ip",
                hostname=hostname,
                addresses=addresses,
                blocked_addresses=blocked,
            )
            raise TargetValidationError(
                "Private, loopback, link-local, multicast, metadata, or reserved addresses are blocked."
            )

        if verify_head:
            self.verify_head_request(target, hostname, addresses)

        return {
            "target": target,
            "hostname": hostname,
            "addresses": addresses,
            "blocked_addresses": blocked,
            "dns_cache_ttl": self.cache_ttl,
        }

    def verify_before_scan(self, raw_target, expected_addresses=None):
        target = normalize_target(raw_target)
        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        self._validate_hostname(hostname, target)
        self._validate_port(parsed, target)

        cached = self._get_cache(hostname)
        if cached:
            validated_addresses = cached["addresses"]
        else:
            validated_addresses = sorted(set(expected_addresses or []))
            if not validated_addresses:
                raise TargetValidationError("Validated DNS cache is missing for this target.")
            self._cache_resolution(hostname, validated_addresses)

        current_addresses = self._resolve_once(hostname, target)
        expected = sorted(set(expected_addresses or validated_addresses))
        if current_addresses != expected or current_addresses != validated_addresses:
            self._log_security_event(
                "dns_rebinding_attempt",
                target,
                reason="pre_scan_dns_mismatch",
                hostname=hostname,
                cached_addresses=validated_addresses,
                expected_addresses=expected,
                current_addresses=current_addresses,
            )
            raise TargetValidationError(
                "DNS rebinding protection blocked this scan because the hostname resolved to a different IP."
            )

        blocked = [ip for ip in current_addresses if self._is_blocked_ip(ip)]
        if blocked:
            self._log_security_event(
                "blocked_request",
                target,
                reason="blocked_ip_before_scan",
                hostname=hostname,
                addresses=current_addresses,
                blocked_addresses=blocked,
            )
            raise TargetValidationError(
                "Private, loopback, link-local, multicast, metadata, or reserved addresses are blocked."
            )

        self.verify_head_request(target, hostname, current_addresses)
        return {
            "target": target,
            "hostname": hostname,
            "addresses": current_addresses,
            "blocked_addresses": blocked,
        }

    def verify_head_request(self, target, hostname, expected_addresses):
        current_addresses = self._resolve_once(hostname, target)
        if current_addresses != sorted(set(expected_addresses)):
            self._log_security_event(
                "dns_rebinding_attempt",
                target,
                reason="head_preflight_dns_mismatch",
                hostname=hostname,
                expected_addresses=expected_addresses,
                current_addresses=current_addresses,
            )
            raise TargetValidationError(
                "DNS rebinding protection blocked this target before the HTTP preflight."
            )

        try:
            response = requests.head(target, timeout=self.head_timeout, allow_redirects=False)
        except requests.exceptions.RequestException as exc:
            self._log_security_event(
                "invalid_target",
                target,
                reason="head_preflight_failed",
                hostname=hostname,
                addresses=current_addresses,
                error=str(exc),
            )
            raise TargetValidationError("Target failed the HTTP HEAD preflight verification.") from exc

        if 300 <= response.status_code < 400:
            redirect_target = response.headers.get("Location", "")
            if redirect_target:
                self._validate_redirect_target(target, redirect_target)

        return response

    def _validate_redirect_target(self, source_target, redirect_target):
        redirect = normalize_target(urljoin(source_target, redirect_target))
        parsed = urlparse(redirect)
        hostname = parsed.hostname or ""
        self._validate_hostname(hostname, redirect)
        self._validate_port(parsed, redirect)
        addresses = self._resolve_multiple(hostname, redirect)[0]
        blocked = [ip for ip in addresses if self._is_blocked_ip(ip)]
        if blocked:
            self._log_security_event(
                "blocked_request",
                source_target,
                reason="blocked_redirect_target",
                redirect_target=redirect,
                hostname=hostname,
                addresses=addresses,
                blocked_addresses=blocked,
            )
            raise TargetValidationError(
                "Redirects to private, loopback, link-local, multicast, metadata, or reserved addresses are blocked."
            )

    def _validate_hostname(self, hostname, target):
        if hostname.lower() in LOCAL_HOSTNAMES:
            self._log_security_event(
                "blocked_request",
                target,
                reason="localhost_hostname",
                hostname=hostname,
            )
            raise TargetValidationError("Localhost targets are not allowed.")

        try:
            is_ip_literal = self._is_blocked_ip(hostname)
        except ValueError:
            return

        if is_ip_literal:
            self._log_security_event(
                "blocked_request",
                target,
                reason="blocked_ip_literal",
                hostname=hostname,
            )
            raise TargetValidationError(
                "Private, loopback, link-local, multicast, metadata, or reserved addresses are blocked."
            )

    def _validate_port(self, parsed, target):
        try:
            port = parsed.port
        except ValueError as exc:
            self._log_security_event("invalid_target", target, reason="invalid_port")
            raise TargetValidationError("Target includes an invalid port.") from exc

        if port in self.blocked_ports:
            self._log_security_event("blocked_request", target, reason="blocked_port", port=port)
            raise TargetValidationError(f"Port {port} is blocked for scan targets.")

    def _resolve_multiple(self, hostname, target):
        attempts = [self._resolve_once(hostname, target) for _ in range(self.dns_attempts)]
        first = attempts[0]
        if any(addresses != first for addresses in attempts[1:]):
            self._log_security_event(
                "dns_rebinding_attempt",
                target,
                reason="inconsistent_dns_results",
                hostname=hostname,
                dns_attempts=attempts,
            )
            raise TargetValidationError(
                "DNS rebinding protection blocked this target because DNS results changed during validation."
            )
        return attempts

    def _resolve_once(self, hostname, target):
        try:
            addrinfo = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            self._log_security_event(
                "invalid_target",
                target,
                reason="dns_resolution_failed",
                hostname=hostname,
                error=str(exc),
            )
            raise TargetValidationError(f"Could not resolve hostname '{hostname}'.") from exc

        addresses = sorted({info[4][0] for info in addrinfo})
        if not addresses:
            self._log_security_event("invalid_target", target, reason="empty_dns_result", hostname=hostname)
            raise TargetValidationError(f"Could not resolve hostname '{hostname}'.")
        return addresses

    def _get_cache(self, hostname):
        key = hostname.lower()
        now = time.monotonic()
        with self._cache_lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            if entry["expires_at"] <= now:
                self._cache.pop(key, None)
                return None
            return {"addresses": list(entry["addresses"]), "expires_at": entry["expires_at"]}

    def _cache_resolution(self, hostname, addresses):
        key = hostname.lower()
        with self._cache_lock:
            self._cache[key] = {
                "addresses": sorted(set(addresses)),
                "expires_at": time.monotonic() + self.cache_ttl,
            }

    def _is_blocked_ip(self, ip_text):
        ip_obj = ipaddress.ip_address(ip_text)
        return any(
            (
                str(ip_obj) in METADATA_IPS,
                ip_obj.is_private,
                ip_obj.is_loopback,
                ip_obj.is_link_local,
                ip_obj.is_multicast,
                ip_obj.is_reserved,
                ip_obj.is_unspecified,
            )
        )

    def _log_security_event(self, event, target, **fields):
        payload = {"event": event, "target": target, **fields}
        try:
            current_app.logger.warning("ssrf_validation_event", extra={"security_event": payload})
        except RuntimeError:
            security_logger.warning("ssrf_validation_event", extra={"security_event": payload})


def bool_env(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def issue_csrf_token():
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
        session.modified = True
    return token


def validate_csrf():
    expected = session.get(CSRF_SESSION_KEY)
    provided = (
        request.headers.get("X-CSRFToken")
        or request.form.get("_csrf_token")
        or request.headers.get("X-CSRF-Token")
    )
    return bool(expected and provided and secrets.compare_digest(expected, provided))


def hash_code(secret_key, namespace, subject, code):
    material = f"{namespace}:{subject}:{code}".encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), material, hashlib.sha256).hexdigest()


def code_matches(secret_key, namespace, subject, code, expected_digest):
    if not code or not expected_digest:
        return False
    actual = hash_code(secret_key, namespace, subject, code)
    return secrets.compare_digest(actual, expected_digest)


def get_client_ip(request_obj=None):
    active_request = request if request_obj is None else request_obj
    forwarded_for = active_request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return active_request.remote_addr or "unknown"


def get_csp_nonce():
    if not has_request_context():
        return ""
    nonce = getattr(g, "csp_nonce", "")
    if not nonce:
        nonce = secrets.token_urlsafe(16)
        g.csp_nonce = nonce
    return nonce


def build_content_security_policy(nonce):
    nonce_source = f"'nonce-{nonce}'"
    directives = [
        "default-src 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        f"script-src 'self' {nonce_source} https://challenges.cloudflare.com",
        "script-src-attr 'none'",
        f"style-src 'self' {nonce_source} https://fonts.googleapis.com",
        "style-src-attr 'none'",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data:",
        "connect-src 'self' https://challenges.cloudflare.com",
        "frame-src https://challenges.cloudflare.com",
        "child-src https://challenges.cloudflare.com",
        "media-src 'self'",
        "manifest-src 'self'",
        "worker-src 'none'",
        "upgrade-insecure-requests",
    ]
    return "; ".join(directives)


def register_security_headers(app):
    if getattr(app, "_security_headers_registered", False):
        return

    app._security_headers_registered = True

    @app.before_request
    def issue_csp_nonce():
        get_csp_nonce()

    @app.context_processor
    def inject_csp_nonce():
        return {"csp_nonce": get_csp_nonce}

    @app.after_request
    def apply_security_headers(response):
        response.headers["Strict-Transport-Security"] = HSTS_VALUE
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = PERMISSIONS_POLICY_VALUE
        response.headers["Content-Security-Policy"] = build_content_security_policy(get_csp_nonce())
        return response


def normalize_target(raw_target):
    target = (raw_target or "").strip()
    if not target:
        raise TargetValidationError("No URL provided.")
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"}:
        raise TargetValidationError("Only http:// and https:// targets are supported.")
    if not parsed.hostname:
        raise TargetValidationError("Target must include a valid hostname.")

    cleaned = parsed._replace(fragment="")
    return cleaned.geturl()


def _is_blocked_ip(ip_text):
    return SSRFValidator()._is_blocked_ip(ip_text)


def resolve_public_target(raw_target, allow_private=False, verify_head=False):
    validator = SSRFValidator(allow_private=allow_private)
    return validator.validate_target(raw_target, verify_head=verify_head)


def register_template_helpers(app):
    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": issue_csrf_token}

    @app.before_request
    def enforce_csrf():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if request.endpoint in {"static"}:
                return None
            if not validate_csrf():
                if request.path.startswith("/start-scan") or request.path.startswith("/cancel-scan"):
                    return {"error": "CSRF validation failed."}, 400
                return current_app.response_class("CSRF validation failed.", status=400)
        return None
