from flask import Flask, render_template

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")



@app.route("/scan", methods=["POST"])
def scan():
        return render_template("report.html", message="Le site est en cours de developpement")



if __name__ == "__main__":
    app.run(debug=True)
