import unittest
from unittest.mock import patch

from app.security import code_matches, hash_code, normalize_target, resolve_public_target


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


if __name__ == "__main__":
    unittest.main()
