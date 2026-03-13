from flask import Flask, render_template, request
from app.scanner.analyser import analyse_nmap
from app.scanner.nmap import run_nmap
from app.scanner.crawler import crawl
from app.scanner.sqli_scanner import scan_sqli
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form["url"]
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    # run nmap and crawler IN PARALLEL
    with ThreadPoolExecutor(max_workers=2) as executor:
        nmap_future = executor.submit(run_nmap, target)
        crawl_future = executor.submit(crawl, target)
        nmap_result = nmap_future.result()
        pages = crawl_future.result()

    analysed_result = analyse_nmap(nmap_result)

    # scan all pages IN PARALLEL
    sqli_vulnerabilities = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_sqli, page): page for page in pages}
        for future in as_completed(futures):
            try:
                results = future.result()
                sqli_vulnerabilities.extend(results)
            except Exception as e:
                print(f"[!] Error scanning page: {e}")

    return render_template("report.html",
                           target_url=target,
                           open_ports=analysed_result,
                           pages_scanned=len(pages),
                           vulnerabilities=sqli_vulnerabilities)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)