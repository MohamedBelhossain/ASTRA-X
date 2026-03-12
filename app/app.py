from flask import Flask, render_template, request
from app.scanner.analyser import analyse_nmap
from app.scanner.nmap import run_nmap
from app.scanner.crawler import crawl
from app.scanner.sqli_scanner import scan_sqli

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():

    target = request.form["url"]
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    # NMAP SCAN
    nmap_result = run_nmap(target)
    print(nmap_result)
    analysed_result = analyse_nmap(nmap_result)
    print("-------------")
    print(analysed_result)
    print("---------------")

    # CRAWLER
    pages = crawl(target)

    # SQL INJECTION SCAN
    sqli_vulnerabilities = []
    for page in pages:
        results = scan_sqli(page)
        sqli_vulnerabilities.extend(results)  
        print(sqli_vulnerabilities)
        
    return render_template("report.html",
                       target_url=target,
                       open_ports=analysed_result,
                       pages_scanned=len(pages),
                       vulnerabilities=sqli_vulnerabilities)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)