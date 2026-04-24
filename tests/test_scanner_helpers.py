import unittest

from app.scanner.common import response_excerpt
from app.scanner.crawler import normalize


class ScannerHelpersTest(unittest.TestCase):
    def test_crawler_normalize_sorts_query_and_removes_fragment(self):
        normalized = normalize("https://example.com/search?b=2&a=1#frag")
        self.assertEqual(normalized, "https://example.com/search?a=1&b=2")

    def test_response_excerpt_centers_on_needle(self):
        excerpt = response_excerpt("prefix matched error marker suffix", "error")
        self.assertIn("error", excerpt.lower())
        self.assertLessEqual(len(excerpt), 180)


if __name__ == "__main__":
    unittest.main()
