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

from flask import Flask, render_template, send_file
from fpdf import FPDF
from datetime import datetime
import os

app = Flask(__name__)

@app.route("/report")
def report():
    return render_template("report.html")

@app.route("/generate-report")
def generate_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Title
    pdf.cell(200, 10, txt="VulneraX CVE Intelligence Report", ln=True, align='C')
    pdf.ln(10)

    # Content
    pdf.multi_cell(0, 10, txt="This is an automatically generated report from VulneraX, detailing critical CVEs and global threat activity.")
    pdf.ln(5)
    pdf.cell(200, 10, txt=f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", ln=True, align='R')

    # Save and return
    output_path = "/tmp/vulnerax_report.pdf"  # ✅ Render-compatible directory
    pdf.output(output_path)
    return send_file(output_path, as_attachment=True)


@app.route("/admin")
def admin():
    return render_template("admin_panel.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
