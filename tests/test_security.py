import re
import unittest
from unittest.mock import patch

from flask import Flask, render_template_string

from app.security import (
    SSRFValidator,
    code_matches,
    hash_code,
    normalize_target,
    register_security_headers,
    resolve_public_target,
)


class SecurityHelpersTest(unittest.TestCase):
    def test_hash_code_round_trip(self):
        digest = hash_code("secret-key", "reset", "user@example.com", "123456")
        self.assertTrue(
            code_matches("secret-key", "reset", "user@example.com", "123456", digest)
        )
        self.assertFalse(
            code_matches("secret-key", "reset", "user@example.com", "000000", digest)
        )

    def test_normalize_target_adds_scheme_and_drops_fragment(self):
        normalized = normalize_target("example.com/path?b=2#a")
        self.assertEqual(normalized, "http://example.com/path?b=2")

    @patch("app.security.socket.getaddrinfo")
    def test_resolve_public_target_blocks_private_ip(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]
        with self.assertRaisesRegex(ValueError, "blocked"):
            resolve_public_target("http://internal.example")

    @patch("app.security.socket.getaddrinfo")
    def test_resolve_public_target_allows_public_ip(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]
        resolved = resolve_public_target("https://example.com")
        self.assertEqual(resolved["hostname"], "example.com")
        self.assertEqual(resolved["addresses"], ["93.184.216.34"])

    @patch("app.security.socket.getaddrinfo")
    def test_resolve_public_target_blocks_dns_rebinding(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = [
            [(2, 1, 6, "", ("93.184.216.34", 0))],
            [(2, 1, 6, "", ("127.0.0.1", 0))],
            [(2, 1, 6, "", ("93.184.216.34", 0))],
        ]
        with self.assertRaisesRegex(ValueError, "DNS rebinding"):
            resolve_public_target("https://rebind.example")

    def test_resolve_public_target_blocks_suspicious_port(self):
        with self.assertRaisesRegex(ValueError, "Port 8080"):
            resolve_public_target("https://example.com:8080")

    @patch("app.security.requests.head")
    @patch("app.security.socket.getaddrinfo")
    def test_head_verification_uses_timeout_without_redirects(self, mock_getaddrinfo, mock_head):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
        ]
        mock_head.return_value.status_code = 200
        mock_head.return_value.headers = {}

        resolved = resolve_public_target("https://head.example", verify_head=True)

        self.assertEqual(resolved["addresses"], ["93.184.216.34"])
        mock_head.assert_called_once_with(
            "https://head.example",
            timeout=5,
            allow_redirects=False,
        )

    @patch("app.security.socket.getaddrinfo")
    def test_verify_before_scan_blocks_cached_ip_mismatch(self, mock_getaddrinfo):
        validator = SSRFValidator()
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("93.184.216.35", 0)),
        ]

        with self.assertRaisesRegex(ValueError, "DNS rebinding"):
            validator.verify_before_scan(
                "https://queued.example",
                expected_addresses=["93.184.216.34"],
            )

    def test_security_headers_and_nonce_csp_are_applied(self):
        app = Flask(__name__)
        app.secret_key = "test-secret"
        register_security_headers(app)

        @app.route("/")
        def index():
            return render_template_string(
                """
                <style nonce="{{ csp_nonce() }}">body { color: #fff; }</style>
                <script nonce="{{ csp_nonce() }}">window.__ok = true;</script>
                """
            )

        response = app.test_client().get("/")
        csp = response.headers["Content-Security-Policy"]

        self.assertEqual(
            response.headers["Strict-Transport-Security"],
            "max-age=31536000; includeSubDomains",
        )
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "strict-origin-when-cross-origin")
        self.assertEqual(
            response.headers["Permissions-Policy"],
            "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
        )
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src-attr 'none'", csp)
        self.assertIn("style-src-attr 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("https://challenges.cloudflare.com", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)

        nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
        body = response.get_data(as_text=True)
        self.assertIn(f'nonce="{nonce}"', body)


if __name__ == "__main__":
    unittest.main()
