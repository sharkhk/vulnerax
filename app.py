
from flask import Flask, render_template, request, send_file, redirect, url_for, session
from fpdf import FPDF
from datetime import datetime
import os
import threading
import time

app = Flask(__name__)
app.secret_key = "vulnerax_secret"
subscribers = []

@app.route("/")
def home():
    return render_template("dashboard.html")

@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form["email"]
    if email not in subscribers:
        subscribers.append(email)
    return redirect("/")

@app.route("/view-subscribers")
def view_subscribers():
    if session.get("admin"):
        return render_template("admin_panel.html", subscribers=subscribers)
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "vulnerax2025":
            session["admin"] = True
            return redirect("/view-subscribers")
    return '''
    <form method="post">
      <input name="username" placeholder="Username" />
      <input name="password" type="password" placeholder="Password" />
      <button type="submit">Login</button>
    </form>
    '''

@app.route("/report")
def report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "VulneraX Weekly Threat Report", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 10, f"Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    pdf.multi_cell(0, 10, "\nAI Risk Scoring:\n- CVE-2025-1234: Apache RCE\n- CVE-2025-5678: CMS XSS")
    pdf.multi_cell(0, 10, "\nPatch Recommendations:\n- Apache 2.4.58\n- Sanitize input in CMS forms")
    pdf.multi_cell(0, 10, "\nSecurity Awareness:\n- Use MFA\n- Train staff\n- Enable threat alerts")
    pdf.ln(4)
    pdf.set_font("Arial", "I", 10)
    pdf.cell(0, 10, "© VulneraX AI Agent · All rights reserved.", ln=True, align="C")
    file_path = "/tmp/vulnerax_final_weekly.pdf"
    pdf.output(file_path)
    return send_file(file_path, as_attachment=True)

# Weekly scheduler simulation
def run_weekly():
    while True:
        now = datetime.utcnow()
        if now.weekday() == 6 and now.hour == 4 and now.minute == 0:  # Sunday 8AM UAE = 4AM UTC
            print("Weekly Report Task Triggered")
            # logic to send reports to subscribers could go here
        time.sleep(60)

@app.before_first_request
def activate_scheduler():
    thread = threading.Thread(target=run_weekly)
    thread.daemon = True
    thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
