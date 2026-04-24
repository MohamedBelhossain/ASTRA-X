# WebVulnScan

WebVulnScan is a Flask-based web vulnerability scanning dashboard with authentication, live scan streaming, report generation, PDF export, and MongoDB-backed users.

## Features

- User registration and login with `flask-login`
- CSRF protection, auth throttling, and safer session cookie defaults
- Email verification and password reset with `Flask-Mail`
- Public landing page at `/`
- Live scan progress via server-sent events
- Durable Mongo-backed scan jobs, history, cancellation, and JSON export
- Port scanning with `python-nmap`
- Web crawling and form discovery
- SQL injection, XSS, LFI, and brute-force checks
- Sensitive file exposure checks
- Subdomain enumeration
- Per-user scan quotas and single active-scan enforcement
- HTML report view and PDF download
- MongoDB-backed users, reset tokens, rate-limit buckets, and scan storage

## Tech Stack

- Python 3.12
- Flask
- MongoDB
- Flask-PyMongo
- Flask-Login
- Flask-Bcrypt
- Flask-Mail
- WeasyPrint
- Requests
- BeautifulSoup
- python-nmap

## Project Structure

```text
app/
  app.py                Main Flask app and routes
  auth.py               Authentication routes
  models.py             Mongo-backed user and reset-token models
  templates/            Landing, auth, dashboard, report, error pages
  static/               Shared CSS
  scanner/              Scanning modules
Dockerfile
docker-compose.yml
requirements.txt
README.md
.env                   Local environment variables
.env.example           Example environment variables
```

## Environment Variables

The app loads environment variables from `.env` at the project root.

Minimum required values:

```env
SECRET_KEY=replace_with_a_random_secret
MONGO_URI=mongodb://localhost:27017/webvuln
```

To enable email verification and password reset, also configure:

```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_16char_app_password
MAIL_DEFAULT_SENDER=your_email@gmail.com
```

Notes:

- `SECRET_KEY` is required for login sessions and flash messages.
- `MONGO_URI` points to your MongoDB instance.
- `ALLOW_PRIVATE_TARGETS=false` blocks localhost/private-network targets by default to reduce SSRF risk.
- Optional scan throttling and security knobs:

```env
SCAN_RATE_LIMIT_MAX=5
SCAN_RATE_LIMIT_WINDOW_SECONDS=3600
MAX_ACTIVE_SCANS_PER_USER=1
SCAN_WORKERS=2
MIN_PASSWORD_LENGTH=10
SESSION_COOKIE_SECURE=false
SESSION_COOKIE_SAMESITE=Lax
ALLOW_PRIVATE_TARGETS=false
```

## Local Development

### 1. Install system dependencies

You need `nmap` available on the machine because the app uses `python-nmap`.

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y nmap
```

WeasyPrint may also require extra native libraries depending on your OS.

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create `.env` from `.env.example` and edit it:

```env
SECRET_KEY=replace_with_a_random_secret
MONGO_URI=mongodb://localhost:27017/webvuln
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_16char_app_password
MAIL_DEFAULT_SENDER=your_email@gmail.com
SCAN_RATE_LIMIT_MAX=5
SCAN_RATE_LIMIT_WINDOW_SECONDS=3600
MAX_ACTIVE_SCANS_PER_USER=1
SCAN_WORKERS=2
MIN_PASSWORD_LENGTH=10
SESSION_COOKIE_SECURE=false
SESSION_COOKIE_SAMESITE=Lax
ALLOW_PRIVATE_TARGETS=false
```

### 5. Start MongoDB

Make sure MongoDB is running locally, or use a remote MongoDB URI in `.env`.

### 6. Run the app

```bash
python3 -m app.app
```

Then open:

```text
http://localhost:5000
```

## Docker

### Build and run with Docker

```bash
docker build -t webvulnscan .
docker run --rm -p 5000:5000 \
  -e SECRET_KEY=replace_with_a_random_secret \
  -e MONGO_URI=mongodb://host.docker.internal:27017/webvuln \
  webvulnscan
```

## Docker Compose

This repo also includes `docker-compose.yml` with both the web app and MongoDB.

```bash
docker compose up --build
```

Then open:

```text
http://localhost:5000
```

Default compose environment:

- App: `http://localhost:5000`
- MongoDB: `mongodb://mongo:27017/webvuln`
- Mail and scan-rate settings are loaded from `.env` when present

## App Flow

1. Open `/`
2. Register your account
3. Verify your email and sign in
4. Start a scan on a target URL
5. Watch the live stream output
6. Open the generated report
7. Export JSON or download the PDF report if needed
8. Revisit prior scans from the dashboard history table

## Important Notes

- This project is intended for authorized security testing only.
- Scans can take time depending on the target and enabled modules.
- Scan events, reports, and history are persisted in MongoDB.
- User accounts, reset tokens, and auth throttle buckets are stored in MongoDB.

## Troubleshooting

### PDF download shows an error

Check:

- WeasyPrint system dependencies are installed
- the scan has completed successfully
- the scan has stored a completed report in MongoDB

### Scan appears stuck

Some phases such as LFI checks, file exposure checks, and subdomain enumeration can take longer depending on the target.

### Login/session issues

Make sure `SECRET_KEY` is set and stable. Changing it invalidates existing sessions.

## License / Usage

Use this project only on systems you own or are explicitly authorized to test.
