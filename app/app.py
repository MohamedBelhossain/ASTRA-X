from flask import Flask, render_template, request
from app.scanner.analyser import analyse_nmap
from app.scanner.nmap import run_nmap

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form["url"]
    result = run_nmap(target)
    print(result)
    result_analysed = analyse_nmap(result)
    print(result_analysed)
    
    # Pass BOTH results AND target to the template
    return render_template("report.html", 
                         results=result_analysed, 
                         target=target)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)