from flask import Flask, render_template, request, make_response
from concurrent.futures import ThreadPoolExecutor, as_completed
from weasyprint import HTML
import uuid

from app.scanner.analyser import analyse_nmap
from app.scanner.nmap import run_nmap
from app.scanner.crawler import crawl
from app.scanner.sqli_scanner import scan_sqli

app = Flask(__name__)

# temporary in-memory store for scan results
scan_store = {}


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form["url"]
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    # run nmap and crawler in parallel
    with ThreadPoolExecutor(max_workers=2) as executor:
        nmap_future = executor.submit(run_nmap, target)
        crawl_future = executor.submit(crawl, target)
        nmap_result = nmap_future.result()
        pages = crawl_future.result()

    analysed_result = analyse_nmap(nmap_result)

    # scan all pages in parallel
    sqli_vulnerabilities = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_sqli, page): page for page in pages}
        for future in as_completed(futures):
            try:
                results = future.result()
                sqli_vulnerabilities.extend(results)
            except Exception as e:
                print(f"[!] Error scanning page: {e}")

    # store results for PDF download
    scan_id = str(uuid.uuid4())
    scan_store[scan_id] = {
        "target_url": target,
        "open_ports": analysed_result,
        "pages_scanned": len(pages),
        "vulnerabilities": sqli_vulnerabilities,
    }

    return render_template("report.html",
                           scan_id=scan_id,
                           target_url=target,
                           open_ports=analysed_result,
                           pages_scanned=len(pages),
                           vulnerabilities=sqli_vulnerabilities)


@app.route("/download/<scan_id>")
def download(scan_id):
    data = scan_store.get(scan_id)
    if not data:
        return "Scan not found", 404

    html_content = render_template("report.html",
                                   scan_id=scan_id,
                                   pdf_mode=True,   # hides the download button in PDF
                                   **data)

    pdf = HTML(string=html_content, base_url=request.host_url).write_pdf()

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=scan_report_{scan_id[:8]}.pdf"
    return response


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)