from flask import Flask, render_template, send_file
app = Flask(__name__)

@app.route("/")
def homepage():
    return render_template("homepage.html")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/report")
def report():
    return render_template("report.html")

@app.route("/admin")
def admin():
    return render_template("admin_panel.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
