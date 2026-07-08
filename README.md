# ASTRA-X

ASTRA-X is a Flask-based web vulnerability scanning dashboard for authorized security testing. It combines crawling, vulnerability checks, live scan progress, persistent reports, and an admin triage console backed by MongoDB.

The project focuses on making scan results understandable, not just detectable. Findings include a **Proof Assistant** panel with evidence, impact, false-positive checks, safe reproduction steps, and fix guidance.

## Highlights

- Authenticated dashboard with registration, login, email verification, password reset, and profile management
- Live scan streaming with MongoDB-backed scan history, cancellation, JSON export, and PDF reports
- Web crawler with form discovery, sitemap support, diagnostics, and anti-bot/WAF signals
- Security checks for SQL injection, XSS, LFI/path traversal, brute-force exposure, sensitive files, subdomains, CMS/CVE signals, security headers, and open ports
- Proof Assistant for clearer vulnerability evidence and remediation guidance
- Admin Risk Triage Console for prioritizing critical/high-risk scans, failed scans, active scans, and noisy targets
- SSRF protections, DNS rebinding checks, CSRF protection, auth throttling, scan quotas, and safer cookie defaults

## Tech Stack

- Python 3.12, Flask, Flask-Login, Flask-Bcrypt, Flask-Mail
- MongoDB, Flask-PyMongo
- Requests, BeautifulSoup, lxml
- python-nmap
- WeasyPrint
- Docker / Docker Compose

## Project Structure

```text
app/
  app.py             Main Flask app, routes, scan orchestration
  auth.py            Authentication and account routes
  models.py          MongoDB models for users, scans, tokens, rate limits
  reporting.py       Risk summaries and Proof Assistant enrichment
  scanner/           Crawler and scanner modules
  templates/         Dashboard, report, admin, auth, landing pages
  static/            CSS assets
tests/               Security and scanner helper tests
Dockerfile
docker-compose.yml
requirements.txt
.env.example
```

## Configuration

Create `.env` from `.env.example` and change the secrets before running.

Minimum useful configuration:

```env
SECRET_KEY=replace_with_a_random_secret
MONGO_URI=mongodb://localhost:27017/webvuln
MONGO_ROOT_USERNAME=webvuln_admin
MONGO_ROOT_PASSWORD=replace_with_a_random_mongo_password

ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=change_this_admin_password

MAIL_CONSOLE_FALLBACK=true
TURNSTILE_SITE_KEY=
TURNSTILE_SECRET_KEY=
TURNSTILE_USE_TEST_KEYS=false
ALLOW_PRIVATE_TARGETS=false
REVEAL_DISCOVERED_CREDENTIALS=false
```

Important options:

- `ALLOW_PRIVATE_TARGETS=false` blocks localhost/private-network scan targets by default.
- `REVEAL_DISCOVERED_CREDENTIALS=false` redacts discovered passwords in reports.
- `SCAN_RATE_LIMIT_MAX`, `SCAN_RATE_LIMIT_WINDOW_SECONDS`, and `MAX_ACTIVE_SCANS_PER_USER` control user scan limits.
- `MAIL_CONSOLE_FALLBACK=true` prints verification/reset mail to the console when SMTP is not configured.
- Brevo SMTP is used for verification/reset mail. Configure `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USERNAME`, `MAIL_PASSWORD`, and `MAIL_DEFAULT_SENDER`.
- `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` enable Cloudflare Turnstile on registration. When they are empty, the local math captcha fallback is used.
- `TURNSTILE_USE_TEST_KEYS=true` uses Cloudflare's official test keys for local development on `localhost` or `127.0.0.1`.
- Set `SESSION_COOKIE_SECURE=true` when serving over HTTPS.

### Mail Delivery

Email delivery uses Brevo SMTP with STARTTLS on port `587`:

```env
MAIL_SERVER=smtp-relay.brevo.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=<Brevo SMTP login>
MAIL_PASSWORD=<Brevo SMTP key>
MAIL_DEFAULT_SENDER=<Verified Brevo sender email>
```

Use the Brevo SMTP login and SMTP key from Brevo's SMTP settings, not a Brevo REST API key.

### Free Captcha Setup

Cloudflare Turnstile is used for the real captcha integration.

1. Create a free Turnstile widget in the Cloudflare dashboard.
2. Add your app hostname, for example `localhost` for local testing and your real domain for production.
3. Copy the site key and secret key into `.env`:

```env
TURNSTILE_SITE_KEY=your_site_key
TURNSTILE_SECRET_KEY=your_secret_key
```

Restart the app after changing `.env`.

For localhost testing, use:

```env
TURNSTILE_USE_TEST_KEYS=true
```

For production, use your real keys and set:

```env
TURNSTILE_USE_TEST_KEYS=false
```

## Run With Docker Compose

Recommended for local full-stack usage:

```bash
docker compose up --build
```

Open:

```text
http://localhost:5000
```

Compose starts both the Flask app and MongoDB. MongoDB is available inside the Compose network and uses the credentials from `.env`.

## Run Locally

Install system dependencies first. `nmap` is required for port scanning, and WeasyPrint may require native libraries depending on your OS.

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y nmap
```

Create the virtual environment and install Python dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Start MongoDB locally or point `MONGO_URI` to an existing MongoDB instance, then run:

```bash
venv/bin/python -m app.app
```

Open:

```text
http://localhost:5000
```

If port `5000` is already in use:

```bash
FLASK_RUN_PORT=5001 venv/bin/python -m app.app
```

## Basic Workflow

1. Register or sign in.
2. Start a scan against a target you are authorized to test.
3. Watch live phase progress and scanner events.
4. Open the report for risk summary, findings, Proof Assistant details, JSON export, or PDF download.
5. Use the admin console to triage high-priority scans across users.

## Testing

Run the focused test suite:

```bash
venv/bin/python -m unittest tests.test_scanner_helpers tests.test_safe_http_client tests.test_security
```

Or run pytest if installed in your environment:

```bash
venv/bin/python -m pytest
```

## Notes

- Use this project only on systems you own or are explicitly authorized to test.
- Active checks can be slow or noisy depending on the target, scan mode, forms, redirects, WAF behavior, and network latency.
- Scan reports, events, users, reset tokens, and rate-limit data are stored in MongoDB.
- The development server is not intended for production. Use a proper WSGI server and HTTPS for deployed environments.
