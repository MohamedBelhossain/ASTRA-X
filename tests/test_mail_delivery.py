import socket
import unittest
from unittest.mock import patch

from flask import Flask

import app.auth as auth_module


class FakeResponse:
    def __init__(self, status_code=200, text='{"id":"email_123"}'):
        self.status_code = status_code
        self.text = text


def make_app(**config):
    app = Flask(__name__)
    app.config.update(
        MAIL_BACKEND="smtp",
        MAIL_USERNAME="mailer@example.com",
        MAIL_PASSWORD="app-password",
        MAIL_DEFAULT_SENDER="ASTRA-X <verify@example.com>",
        RESEND_API_URL="https://api.resend.com/emails",
        MAIL_HTTP_TIMEOUT=3,
    )
    app.config.update(config)
    return app


class MailDeliveryTest(unittest.TestCase):
    def test_ipv4_dns_patch_forces_af_inet_resolution(self):
        calls = []

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            calls.append(
                {
                    "host": host,
                    "port": port,
                    "family": family,
                    "type": type,
                    "proto": proto,
                    "flags": flags,
                }
            )
            return [
                (
                    family,
                    type or socket.SOCK_STREAM,
                    proto or socket.IPPROTO_TCP,
                    "",
                    ("203.0.113.10", port),
                )
            ]

        with patch.object(auth_module, "_ORIGINAL_GETADDRINFO", fake_getaddrinfo):
            result = socket.getaddrinfo(
                "smtp.example.com",
                587,
                family=socket.AF_INET6,
                type=socket.SOCK_STREAM,
            )

        self.assertEqual(calls[0]["family"], socket.AF_INET)
        self.assertEqual(result[0][0], socket.AF_INET)

    def test_smtp_backend_uses_flask_mail_by_default(self):
        app = make_app()

        with app.app_context(), patch.object(auth_module.mail, "send") as send:
            sent = auth_module._send_mail(
                "user@example.com",
                "ASTRA-X - Verify your email",
                "Your verification code is: 123456",
            )

        self.assertTrue(sent)
        message = send.call_args.args[0]
        self.assertEqual(message.recipients, ["user@example.com"])
        self.assertEqual(message.sender, "ASTRA-X <verify@example.com>")

    def test_resend_backend_posts_text_email(self):
        app = make_app(MAIL_BACKEND="resend", RESEND_API_KEY="re_test")

        with app.app_context(), patch("app.auth.requests.post", return_value=FakeResponse()) as post:
            sent = auth_module._send_mail(
                "user@example.com",
                "ASTRA-X - Verify your email",
                "Your verification code is: 123456",
            )

        self.assertTrue(sent)
        post.assert_called_once_with(
            "https://api.resend.com/emails",
            headers={
                "Authorization": "Bearer re_test",
                "Accept": "application/json",
                "User-Agent": "ASTRA-X/1.0",
            },
            json={
                "from": "ASTRA-X <verify@example.com>",
                "to": ["user@example.com"],
                "subject": "ASTRA-X - Verify your email",
                "text": "Your verification code is: 123456",
            },
            timeout=3,
        )

    def test_resend_backend_requires_api_key_and_sender(self):
        app = make_app(MAIL_BACKEND="resend", RESEND_API_KEY="", MAIL_DEFAULT_SENDER="")

        with app.app_context(), patch("app.auth.requests.post") as post:
            sent = auth_module._send_mail(
                "user@example.com",
                "ASTRA-X - Verify your email",
                "Your verification code is: 123456",
            )

        self.assertFalse(sent)
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
