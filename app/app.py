from flask import Flask, render_template, request, make_response
from concurrent.futures import ThreadPoolExecutor, as_completed
from weasyprint import HTML
import uuid
import socket
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

scan_store = {}


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    target = request.form.get("url", "").strip()

    # ── 1. basic input check ────────────────────────────
    if not target:
        return render_template("error.html", message="No URL provided.")

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    # ── 2. DNS check ────────────────────────────────────
    hostname = urlparse(target).hostname
    try:
        socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return render_template("error.html", message=f"Could not resolve hostname <strong>{hostname}</strong>. Check the URL and try again.")

    # ── 3. reachability check ───────────────────────────
    try:
        req.head(target, timeout=5, allow_redirects=True)
    except req.exceptions.ConnectionError:
        return render_template("error.html", message=f"Could not connect to <strong>{target}</strong>. Check the URL and try again.")
    except req.exceptions.Timeout:
        return render_template("error.html", message=f"Connection to <strong>{target}</strong> timed out.")
    except req.exceptions.RequestException as e:
        return render_template("error.html", message=f"Invalid or unreachable URL: {e}")

    # ── 4. run scan ─────────────────────────────────────
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            nmap_future = executor.submit(run_nmap, target)
            crawl_future = executor.submit(crawl, target)
            nmap_result = nmap_future.result()
            pages = crawl_future.result()

        analysed_result = analyse_nmap(nmap_result)

        sqli_vulnerabilities = []
        xss_vulnerabilities = []
        lfi_vulnerabilities = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            sqli_futures = {executor.submit(scan_sqli, page): page for page in pages}
            xss_futures  = {executor.submit(scan_xss,  page): page for page in pages}
            lfi_futures  = {executor.submit(scan_lfi,  page): page for page in pages}

            for future in as_completed(sqli_futures):
                try:
                    sqli_vulnerabilities.extend(future.result())
                except Exception as e:
                    print(f"[!] SQLi error: {e}")

            for future in as_completed(xss_futures):
                try:
                    xss_vulnerabilities.extend(future.result())
                except Exception as e:
                    print(f"[!] XSS error: {e}")

            for future in as_completed(lfi_futures):
                try:
                    lfi_vulnerabilities.extend(future.result())
                except Exception as e:
                    print(f"[!] LFI error: {e}")

        with ThreadPoolExecutor(max_workers=2) as executor:
            file_future      = executor.submit(scan_file_exposure, target)
            subdomain_future = executor.submit(scan_subdomains, target)
            file_findings      = file_future.result()
            subdomain_findings = subdomain_future.result()

    except Exception as e:
        return render_template("error.html", message=f"Scan failed unexpectedly: {e}")

    # ── 5. store and render ─────────────────────────────
    scan_id = str(uuid.uuid4())
    scan_store[scan_id] = {
        "target_url": target,
        "open_ports": analysed_result,
        "pages_scanned": len(pages),
        "vulnerabilities": sqli_vulnerabilities,
        "xss_vulnerabilities": xss_vulnerabilities,
        "lfi_vulnerabilities": lfi_vulnerabilities,
        "file_findings": file_findings,
        "subdomain_findings": subdomain_findings,
    }

    return render_template("report.html",
                           scan_id=scan_id,
                           pdf_mode=False,
                           target_url=target,
                           open_ports=analysed_result,
                           pages_scanned=len(pages),
                           vulnerabilities=sqli_vulnerabilities,
                           xss_vulnerabilities=xss_vulnerabilities,
                           lfi_vulnerabilities=lfi_vulnerabilities,
                           file_findings=file_findings,
                           subdomain_findings=subdomain_findings)


@app.route("/download/<scan_id>")
def download(scan_id):
    data = scan_store.get(scan_id)
    if not data:
        return render_template("error.html", message="Scan report not found or expired.")

    html_content = render_template("report.html",
                                   scan_id=scan_id,
                                   pdf_mode=True,
                                   **data)

    pdf = HTML(string=html_content, base_url=request.host_url).write_pdf()

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=scan_report_{scan_id[:8]}.pdf"
    return response


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)