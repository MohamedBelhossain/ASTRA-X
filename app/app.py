from flask import Flask, render_template, request, make_response, Response, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed
from weasyprint import HTML
import uuid, socket, time, json, threading
import requests as req
from urllib.parse import urlparse

from app.scanner.analyser import analyse_nmap
from app.scanner.file_exposure import scan_file_exposure
from app.scanner.nmap import run_nmap
from app.scanner.crawler import crawl
from app.scanner.sqli_scanner import scan_sqli
from app.scanner.xss_scanner import scan_xss
from app.scanner.lfi_scanner import scan_lfi
from app.scanner.subdomain_scanner import scan_subdomains

app = Flask(__name__)

# scan_store holds final results keyed by scan_id
scan_store = {}

# event_store holds SSE queues keyed by scan_id
# Each value is a list of JSON strings (events) + a "done" flag
event_store = {}


# ── helpers ──────────────────────────────────────────────────────────────

def push(scan_id, event_type, data):
    """Append a SSE event to the event store for a given scan."""
    if scan_id not in event_store:
        return
    event_store[scan_id]["events"].append(
        json.dumps({"type": event_type, "data": data})
    )

def log(scan_id, msg, level="info", request_data=None):
    d = {"msg": msg, "level": level}
    if request_data:
        d["request"] = request_data
    push(scan_id, "log", d)

def phase(scan_id, name, status, count=None):
    d = {"phase": name, "status": status}
    if count is not None:
        d["count"] = count
    push(scan_id, "phase", d)

def vuln_event(scan_id, category, data):
    push(scan_id, "vuln", {"category": category, "data": data})


# ── background scan runner ────────────────────────────────────────────────

def run_scan(scan_id, target):
    try:
        # ── Phase 1: nmap + crawl ────────────────────────────────────────
        phase(scan_id, "nmap", "running")
        phase(scan_id, "crawl", "running")
        log(scan_id, f"Starting port scan + crawl on {target}…")

        with ThreadPoolExecutor(max_workers=2) as ex:
            nmap_future  = ex.submit(run_nmap, target)
            crawl_future = ex.submit(crawl, target)
            nmap_result  = nmap_future.result()
            pages        = crawl_future.result()

        analysed_result = analyse_nmap(nmap_result)
        open_port_count = len(analysed_result) if analysed_result else 0

        phase(scan_id, "nmap",  "done", open_port_count)
        phase(scan_id, "crawl", "done", len(pages))
        log(scan_id, f"Found {open_port_count} open port(s), {len(pages)} page(s) to test.", "success")

        # ── Phase 2: SQLi / XSS / LFI ───────────────────────────────────
        sqli_vulns = []
        xss_vulns  = []
        lfi_vulns  = []

        phase(scan_id, "sqli", "running")
        phase(scan_id, "xss",  "running")
        phase(scan_id, "lfi",  "running")
        log(scan_id, "Injecting payloads across all discovered pages…")

        with ThreadPoolExecutor(max_workers=10) as ex:
            sqli_futures = {ex.submit(scan_sqli, p): p for p in pages}
            xss_futures  = {ex.submit(scan_xss,  p): p for p in pages}
            lfi_futures  = {ex.submit(scan_lfi,  p): p for p in pages}

            for future in as_completed(sqli_futures):
                try:
                    results = future.result()
                    for v in results:
                        sqli_vulns.append(v)
                        vuln_event(scan_id, "sqli", v)
                        log(scan_id,
                            f"[SQLi] {v.get('type','?')} on param '{v.get('parameter','?')}' at {v.get('url','?')}",
                            "vuln",
                            {"method": "POST", "url": v.get("url"), "param": v.get("parameter"), "payload": v.get("payload")})
                except Exception as e:
                    log(scan_id, f"SQLi error: {e}", "error")

            for future in as_completed(xss_futures):
                try:
                    results = future.result()
                    for v in results:
                        xss_vulns.append(v)
                        vuln_event(scan_id, "xss", v)
                        log(scan_id,
                            f"[XSS] {v.get('type','?')} on param '{v.get('parameter','?')}' at {v.get('url','?')}",
                            "vuln",
                            {"method": "GET", "url": v.get("url"), "param": v.get("parameter"), "payload": v.get("payload")})
                except Exception as e:
                    log(scan_id, f"XSS error: {e}", "error")

            for future in as_completed(lfi_futures):
                try:
                    results = future.result()
                    for v in results:
                        lfi_vulns.append(v)
                        vuln_event(scan_id, "lfi", v)
                        log(scan_id,
                            f"[LFI] Path traversal on param '{v.get('parameter','?')}' at {v.get('url','?')}",
                            "vuln",
                            {"method": "GET", "url": v.get("url"), "param": v.get("parameter"), "payload": v.get("payload")})
                except Exception as e:
                    log(scan_id, f"LFI error: {e}", "error")

        phase(scan_id, "sqli", "done", len(sqli_vulns))
        phase(scan_id, "xss",  "done", len(xss_vulns))
        phase(scan_id, "lfi",  "done", len(lfi_vulns))
        log(scan_id, f"Injection tests complete — {len(sqli_vulns)} SQLi, {len(xss_vulns)} XSS, {len(lfi_vulns)} LFI.", "success")

        # ── Phase 3: file exposure + subdomains ──────────────────────────
        phase(scan_id, "files", "running")
        phase(scan_id, "subd",  "running")
        log(scan_id, "Checking file exposure and enumerating subdomains…")

        with ThreadPoolExecutor(max_workers=2) as ex:
            file_future      = ex.submit(scan_file_exposure, target)
            subdomain_future = ex.submit(scan_subdomains, target)
            file_findings      = file_future.result()
            subdomain_findings = subdomain_future.result()

        phase(scan_id, "files", "done", len(file_findings) if file_findings else 0)
        phase(scan_id, "subd",  "done", len(subdomain_findings) if subdomain_findings else 0)
        log(scan_id, f"Found {len(file_findings) if file_findings else 0} exposed file(s), "
                     f"{len(subdomain_findings) if subdomain_findings else 0} subdomain(s).", "success")

        # ── Store results ────────────────────────────────────────────────
        scan_store[scan_id] = {
            "target_url":        target,
            "open_ports":        analysed_result,
            "pages_scanned":     len(pages),
            "vulnerabilities":   sqli_vulns,
            "xss_vulnerabilities": xss_vulns,
            "lfi_vulnerabilities": lfi_vulns,
            "file_findings":     file_findings,
            "subdomain_findings": subdomain_findings,
        }

        log(scan_id, "Scan complete. Building report…", "success")
        push(scan_id, "done", {"scan_id": scan_id})

    except Exception as e:
        log(scan_id, f"Scan failed: {e}", "error")
        push(scan_id, "error", {"msg": str(e)})
    finally:
        event_store[scan_id]["done"] = True


# ── routes ────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/start-scan", methods=["POST"])
def start_scan():
    """Validate target, create scan_id, launch background thread, return scan_id."""
    target = request.form.get("url", "").strip()

    if not target:
        return jsonify({"error": "No URL provided."}), 400

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    hostname = urlparse(target).hostname
    try:
        socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return jsonify({"error": f"Could not resolve hostname '{hostname}'."}), 400

    try:
        req.head(target, timeout=5, allow_redirects=True)
    except req.exceptions.ConnectionError:
        return jsonify({"error": f"Could not connect to '{target}'."}), 400
    except req.exceptions.Timeout:
        return jsonify({"error": f"Connection to '{target}' timed out."}), 400
    except req.exceptions.RequestException as e:
        return jsonify({"error": f"Invalid or unreachable URL: {e}"}), 400

    scan_id = str(uuid.uuid4())
    event_store[scan_id] = {"events": [], "done": False, "cursor": 0}

    thread = threading.Thread(target=run_scan, args=(scan_id, target), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id, "target": target})


@app.route("/stream/<scan_id>")
def stream(scan_id):
    """SSE endpoint — streams events for a given scan_id."""
    def generate():
        store = event_store.get(scan_id)
        if not store:
            yield f"data: {json.dumps({'type':'error','data':{'msg':'Scan not found.'}})}\n\n"
            return

        while True:
            cursor = store["cursor"]
            events = store["events"]

            while cursor < len(events):
                yield f"data: {events[cursor]}\n\n"
                cursor += 1

            store["cursor"] = cursor

            if store["done"] and cursor >= len(events):
                break

            time.sleep(0.2)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/report/<scan_id>")
def report(scan_id):
    data = scan_store.get(scan_id)
    if not data:
        return render_template("error.html", message="Report not found or scan still running.")
    return render_template("report.html", scan_id=scan_id, pdf_mode=False, **data)


@app.route("/download/<scan_id>")
def download(scan_id):
    data = scan_store.get(scan_id)
    if not data:
        return render_template("error.html", message="Scan report not found or expired.")

    html_content = render_template("report.html", scan_id=scan_id, pdf_mode=True, **data)
    pdf = HTML(string=html_content, base_url=request.host_url).write_pdf()

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=scan_report_{scan_id[:8]}.pdf"
    return response


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)