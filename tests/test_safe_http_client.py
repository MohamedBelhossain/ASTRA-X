import socket
import unittest
from urllib.parse import urlparse

from app.scanner.http_client import SafeScannerSession
from app.security import TargetValidationError


class FakeValidator:
    def __init__(self, results):
        self.results = results
        self.seen = []

    def validate_target(self, url, verify_head=False):
        self.seen.append(url)
        result = self.results[url]
        if isinstance(result, Exception):
            raise result
        return result


class FakeResponse:
    def __init__(self, url, status_code=200, location=None):
        self.url = url
        self.status_code = status_code
        self.headers = {}
        if location:
            self.headers["Location"] = location

    @property
    def is_redirect(self):
        return self.status_code in {301, 302, 303, 307, 308} and "Location" in self.headers


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.resolved = []

    def request(self, method, url, **kwargs):
        hostname = urlparse(url).hostname
        self.resolved.append(socket.getaddrinfo(hostname, 443)[0][4][0])
        return self.responses.pop(0)


class SafeScannerSessionTest(unittest.TestCase):
    def test_pins_dns_to_validated_address_during_request(self):
        url = "https://example.test/"
        validator = FakeValidator({url: {"addresses": ["93.184.216.34"]}})
        client = SafeScannerSession(validator=validator)
        client.session = FakeTransport([FakeResponse(url)])

        client.get(url)

        self.assertEqual(client.session.resolved, ["93.184.216.34"])

    def test_validates_redirect_target_before_following(self):
        first = "https://example.test/"
        redirect = "http://127.0.0.1/admin"
        validator = FakeValidator(
            {
                first: {"addresses": ["93.184.216.34"]},
                redirect: TargetValidationError("blocked redirect"),
            }
        )
        client = SafeScannerSession(validator=validator)
        client.session = FakeTransport([FakeResponse(first, status_code=302, location=redirect)])

        with self.assertRaisesRegex(TargetValidationError, "blocked redirect"):
            client.get(first)

        self.assertEqual(validator.seen, [first, redirect])


if __name__ == "__main__":
    unittest.main()
