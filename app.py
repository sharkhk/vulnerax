from flask import Flask, render_template, request, redirect, send_file, jsonify
from datetime import datetime
from fpdf import FPDF

app = Flask(__name__)

visit_count = 0
subscriber_emails = []

@app.route('/')
def home():
    global visit_count
    visit_count += 1
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
def admin():
    return render_template('admin_panel.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    if email and email not in subscriber_emails:
        subscriber_emails.append(email)
    return redirect('/')

@app.route('/api/admin-stats')
def admin_stats():
    return jsonify({
        'subscriberCount': len(subscriber_emails),
        'visitCount': visit_count,
        'subscribers': subscriber_emails
    })

@app.route('/generate-report')
def generate_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Cover Page
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Weekly Cybersecurity Report", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, txt=(
        "This report includes:
"
        "- Top 10 CVEs (scored by ML)
"
        "- Real-world threat updates
"
        "- Risk overview and visual breakdown
"
        "- Recommended patch actions
"
        "- Awareness advice."
    ))
    pdf.ln(5)
    pdf.cell(200, 10, txt="Generated: " + datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), ln=True, align="L")

    # Page 2
    pdf.add_page()
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, txt="Cyber Threat Highlights", ln=True)
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, txt="- Multiple zero-day exploits discovered in enterprise platforms.
"
                              "- Ransomware targeted critical sectors.
"
                              "- Sharp rise in phishing and malware campaigns.")

    pdf.output("/mnt/data/weekly_report.pdf")
    return send_file("/mnt/data/weekly_report.pdf", as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
