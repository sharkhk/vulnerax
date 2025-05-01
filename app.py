
from flask import Flask, render_template, request, send_file, redirect, url_for, session
from fpdf import FPDF
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "vulnerax2025")

app = Flask(__name__)
app.secret_key = "super-secret-key"
subscribers = []

@app.route("/")
def home():
    return render_template("dashboard.html")

@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form["email"]
    if email and email not in subscribers:
        subscribers.append(email)
    return redirect(url_for("home"))

@app.route("/view-subscribers")
def view_subscribers():
    if session.get("logged_in"):
        return render_template("admin_panel.html", subscribers=subscribers)
    return redirect(url_for("admin_login"))

@app.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form["username"] == ADMIN_USER and request.form["password"] == ADMIN_PASS:
            session["logged_in"] = True
            return redirect(url_for("view_subscribers"))
    return '''
    <form method="post">
        <input type="text" name="username" placeholder="User" />
        <input type="password" name="password" placeholder="Pass" />
        <button type="submit">Login</button>
    </form>
    '''

@app.route("/report")
def report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "VulneraX Cyber Threat Intelligence Report", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 10, "- Executive Summary:\nAI-powered insights on CVEs\n\n- CVE Samples:\nCVE-2025-1234: Example Apache RCE\n\n- Patch Advice:\nUpdate Apache to 2.4.58\n\n- Stats and AI Insight Provided")
    pdf.ln(5)
    pdf.set_font("Arial", "I", 10)
    pdf.cell(0, 10, "© 2025 VulneraX", ln=True, align="C")
    filename = "/tmp/vulnerax_live_report.pdf"
    pdf.output(filename)
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
