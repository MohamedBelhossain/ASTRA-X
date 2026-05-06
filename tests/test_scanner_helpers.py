import unittest
from unittest.mock import patch

from app.scanner.common import response_excerpt
from app.scanner.crawler import normalize
from app.scanner.cms_scanner import detect_cms, lookup_cves
from app.scanner.header_scanner import scan_security_headers


class FakeResponse:
    def __init__(self, text="", headers=None, payload=None, status_code=200, url="https://example.test/"):
        self.text = text
        self.headers = headers or {}
        self._payload = payload
        self.status_code = status_code
        self.url = url

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("bad status")


class ScannerHelpersTest(unittest.TestCase):
    def test_crawler_normalize_sorts_query_and_removes_fragment(self):
        normalized = normalize("https://example.com/search?b=2&a=1#frag")
        self.assertEqual(normalized, "https://example.com/search?a=1&b=2")

    def test_response_excerpt_centers_on_needle(self):
        excerpt = response_excerpt("prefix matched error marker suffix", "error")
        self.assertIn("error", excerpt.lower())
        self.assertLessEqual(len(excerpt), 180)

    def test_detect_cms_extracts_wordpress_version(self):
        html = """
        <html>
          <head><meta name="generator" content="WordPress 6.4.3"></head>
          <body><script src="/wp-includes/js/jquery.js?ver=6.4.3"></script></body>
        </html>
        """

        with patch(
            "app.scanner.cms_scanner.session.get",
            return_value=FakeResponse(html, headers={"X-Powered-By": "PHP"}),
        ):
            result = detect_cms("https://example.test/")

        self.assertTrue(result["detected"])
        self.assertEqual(result["name"], "WordPress")
        self.assertEqual(result["version"], "6.4.3")
        self.assertIn(result["confidence"], {"medium", "high"})

    def test_lookup_cves_normalizes_nvd_results(self):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-12345",
                        "published": "2024-01-02T00:00:00.000",
                        "lastModified": "2024-01-03T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Example WordPress issue."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseSeverity": "HIGH",
                                        "baseScore": 8.1,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        }

        with patch(
            "app.scanner.cms_scanner.session.get",
            return_value=FakeResponse(payload=payload),
        ):
            cves = lookup_cves("WordPress", "6.4.3")

        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["id"], "CVE-2024-12345")
        self.assertEqual(cves[0]["severity"], "high")
        self.assertEqual(cves[0]["score"], 8.1)
        self.assertEqual(cves[0]["confidence"], "candidate")

    def test_security_header_scanner_reports_missing_headers(self):
        with patch(
            "app.scanner.header_scanner.session.get",
            return_value=FakeResponse("ok", headers={"content-type": "text/html"}),
        ):
            result = scan_security_headers("https://example.test/")

        finding_types = {finding["type"] for finding in result["findings"]}
        self.assertIn("Missing Content-Security-Policy", finding_types)
        self.assertIn("Missing X-Frame-Options", finding_types)


if __name__ == "__main__":
    unittest.main()
