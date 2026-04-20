# WebVulnScan

WebVulnScan is a Flask-based web vulnerability scanning dashboard with authentication, live scan streaming, report generation, and PDF export.

## Features

- User registration and login with `flask-login`
- Public landing page at `/`
- Live scan progress via server-sent events
- Port scanning with `python-nmap`
- Web crawling and form discovery
- SQL injection, XSS, and LFI checks
- Sensitive file exposure checks
- Subdomain enumeration
- HTML report view and PDF download
- MongoDB-backed user storage

## Tech Stack

- Python 3.12
- Flask
- MongoDB
- Flask-PyMongo
- Flask-Login
- Flask-Bcrypt
- WeasyPrint
- Requests
- BeautifulSoup
- python-nmap

## Project Structure

```text
app/
  app.py                Main Flask app and routes
  auth.py               Authentication routes
  models.py             Mongo-backed user model
  templates/            Landing, auth, dashboard, report, error pages
  static/               Shared CSS
  scanner/              Scanning modules
  .env                  Local environment variables
Dockerfile
docker-compose.yml
requirements.txt
README.md
```

## Environment Variables

The app loads environment variables from `app/.env`.

Minimum required values:

```env
SECRET_KEY=replace_with_a_random_secret
MONGO_URI=mongodb://localhost:27017/webvuln
```

Notes:

- `SECRET_KEY` is required for login sessions and flash messages.
- `MONGO_URI` points to your MongoDB instance.

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

Edit `app/.env`:

```env
SECRET_KEY=replace_with_a_random_secret
MONGO_URI=mongodb://localhost:27017/webvuln
```

### 5. Start MongoDB

Make sure MongoDB is running locally, or use a remote MongoDB URI in `app/.env`.

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

## App Flow

1. Open `/`
2. Register or log in
3. Start a scan on a target URL
4. Watch the live stream output
5. Open the generated report
6. Download the PDF report if needed

## Important Notes

- This project is intended for authorized security testing only.
- Scans can take time depending on the target and enabled modules.
- Scan results are currently kept in memory for report display during runtime.
- User accounts are stored in MongoDB.

## Troubleshooting

### PDF download shows an error

Check:

- WeasyPrint system dependencies are installed
- the scan has completed successfully
- the report exists in memory for the current app session

### Scan appears stuck

Some phases such as LFI checks, file exposure checks, and subdomain enumeration can take longer depending on the target.

### Login/session issues

Make sure `SECRET_KEY` is set and stable. Changing it invalidates existing sessions.

## License / Usage

Use this project only on systems you own or are explicitly authorized to test.
