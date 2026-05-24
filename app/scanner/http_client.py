import socket
import threading
from contextlib import contextmanager
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter

from app.scanner.common import session_headers
from app.security import SSRFValidator


DEFAULT_TIMEOUT = 8
MAX_REDIRECTS = 5
_DNS_PATCH_LOCK = threading.RLock()


@contextmanager
def _pinned_dns(hostname, addresses):
    original_getaddrinfo = socket.getaddrinfo
    pinned = tuple(addresses)

    def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        if host == hostname:
            results = []
            for address in pinned:
                ip_obj_family = socket.AF_INET6 if ":" in address else socket.AF_INET
                if family not in (0, ip_obj_family):
                    continue
                results.append(
                    (
                        ip_obj_family,
                        type or socket.SOCK_STREAM,
                        proto or socket.IPPROTO_TCP,
                        "",
                        (address, port),
                    )
                )
            if results:
                return results
        return original_getaddrinfo(host, port, family, type, proto, flags)

    with _DNS_PATCH_LOCK:
        socket.getaddrinfo = getaddrinfo
        try:
            yield
        finally:
            socket.getaddrinfo = original_getaddrinfo


class SafeScannerSession:
    """Requests-compatible session that validates every target and redirect."""

    def __init__(self, *, timeout=DEFAULT_TIMEOUT, validator=None):
        self.timeout = timeout
        self.validator = validator or SSRFValidator()
        self.session = requests.Session()
        self.session.headers.update(session_headers())
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self, method, url, **kwargs):
        follow_redirects = kwargs.pop("allow_redirects", True)
        timeout = kwargs.pop("timeout", self.timeout)
        current_url = url

        for _ in range(MAX_REDIRECTS + 1):
            target_info = self.validator.validate_target(current_url, verify_head=False)
            hostname = urlparse(current_url).hostname
            with _pinned_dns(hostname, target_info["addresses"]):
                response = self.session.request(
                    method,
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    **kwargs,
                )

            if not follow_redirects or not response.is_redirect:
                return response

            location = response.headers.get("Location")
            if not location:
                return response
            current_url = urljoin(response.url, location)

        raise requests.exceptions.TooManyRedirects(f"Exceeded {MAX_REDIRECTS} redirects for {url}")

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    @property
    def cookies(self):
        return self.session.cookies


def safe_scanner_session(*, timeout=DEFAULT_TIMEOUT):
    return SafeScannerSession(timeout=timeout)
