import unittest
from unittest.mock import patch

from app.security import SSRFValidator, code_matches, hash_code, normalize_target, resolve_public_target


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


if __name__ == "__main__":
    unittest.main()
