import os

bind = "0.0.0.0:5000"
workers = int(os.environ.get("GUNICORN_WORKERS", "2"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "120"))

accesslog = None
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "warning")


def on_starting(server):
    print("WebVulnScan: http://127.0.0.1:5000", flush=True)
