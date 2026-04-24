import hashlib
import hmac
import ipaddress
import secrets
import socket
from urllib.parse import urlparse

from flask import current_app, request, session


CSRF_SESSION_KEY = "_csrf_token"
LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain"}


class TargetValidationError(ValueError):
    """Raised when a scan target fails validation."""


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


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


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
    ip_obj = ipaddress.ip_address(ip_text)
    return any(
        (
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_link_local,
            ip_obj.is_multicast,
            ip_obj.is_reserved,
            ip_obj.is_unspecified,
        )
    )


def resolve_public_target(raw_target, allow_private=False):
    target = normalize_target(raw_target)
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    if hostname.lower() in LOCAL_HOSTNAMES:
        raise TargetValidationError("Localhost targets are not allowed.")

    try:
        addrinfo = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetValidationError(f"Could not resolve hostname '{hostname}'.") from exc

    addresses = sorted({info[4][0] for info in addrinfo})
    if not addresses:
        raise TargetValidationError(f"Could not resolve hostname '{hostname}'.")

    blocked = [ip for ip in addresses if _is_blocked_ip(ip)]
    if blocked and not allow_private:
        raise TargetValidationError(
            "Private, loopback, link-local, multicast, or reserved addresses are blocked."
        )

    return {
        "target": target,
        "hostname": hostname,
        "addresses": addresses,
        "blocked_addresses": blocked,
    }


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
