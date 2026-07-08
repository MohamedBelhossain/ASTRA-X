import socket
import unittest
from unittest.mock import patch

from flask import Flask

import app.auth as auth_module


def make_app(**config):
    app = Flask(__name__)
    app.config.update(
        MAIL_SERVER="smtp-relay.brevo.com",
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USE_SSL=False,
        MAIL_USERNAME="brevo-smtp-login",
        MAIL_PASSWORD="brevo-smtp-key",
        MAIL_DEFAULT_SENDER="ASTRA-X <verify@example.com>",
        MAIL_TIMEOUT=10,
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

    def test_brevo_smtp_uses_flask_mail(self):
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
        self.assertEqual(app.config["MAIL_SERVER"], "smtp-relay.brevo.com")
        self.assertEqual(app.config["MAIL_PORT"], 587)
        self.assertTrue(app.config["MAIL_USE_TLS"])
        self.assertFalse(app.config["MAIL_USE_SSL"])

    def test_brevo_smtp_requires_credentials_and_sender(self):
        app = make_app(
            MAIL_USERNAME="<Brevo SMTP login>",
            MAIL_PASSWORD="<Brevo SMTP key>",
            MAIL_DEFAULT_SENDER="<Verified Brevo sender email>",
        )

        with app.app_context(), patch.object(auth_module.mail, "send") as send:
            sent = auth_module._send_mail(
                "user@example.com",
                "ASTRA-X - Verify your email",
                "Your verification code is: 123456",
            )

        self.assertFalse(sent)
        send.assert_not_called()

    def test_smtp_is_used_even_when_brevo_api_key_is_set(self):
        app = make_app(BREVO_API_KEY="xsmtpsib-ignored-by-smtp")

        with (
            app.app_context(),
            patch.object(auth_module.requests, "post") as post,
            patch.object(auth_module.mail, "send") as send,
        ):
            sent = auth_module._send_mail(
                "user@example.com",
                "ASTRA-X - Verify your email",
                "Your verification code is: 123456",
            )

        self.assertTrue(sent)
        post.assert_not_called()
        send.assert_called_once()


if __name__ == "__main__":
    unittest.main()
