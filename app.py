import os
import sqlite3
import requests
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from fpdf import FPDF
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load .env
load_dotenv()

# Constants
DB_PATH   = 'vulnerax.db'
PDF_PATH  = '/tmp/vulnerax_report.pdf'
NVD_API   = 'https://services.nvd.nist.gov/rest/json/cves/1.0'

app = Flask(__name__)

# — Database helpers —
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db(); c = conn.cursor()
    c.execute('''
      CREATE TABLE IF NOT EXISTS subscribers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        type TEXT,
        subscribed_on DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    ''')
    c.execute('''
      CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visited_on DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    ''')
    conn.commit(); conn.close()

init_db()

@app.before_request
def track_visit():
    conn = get_db()
    conn.execute('INSERT INTO visits DEFAULT VALUES')
    conn.commit()
    conn.close()

# — Fetch live CVEs from NVD —
def api_fetch_cves(days: int = 10, limit: int = 10):
    """Fetch CVEs published in the last `days` days, return up to `limit` items."""
    since = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S:000 UTC+00:00')
    params = {
        'pubStartDate': since,
        'resultsPerPage': limit
    }
    try:
        resp = requests.get(NVD_API, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json().get('result', {}).get('CVE_Items', [])
    except Exception as e:
        app.logger.error("Failed to fetch CVEs: %s", e)
        data = []

    cves = []
    for item in data[:limit]:
        meta  = item.get('cve', {}).get('CVE_data_meta', {})
        descs = item.get('cve', {}).get('description', {}).get('description_data', [])
        impacts = item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {})
        cves.append({
            'cve_id'    : meta.get('ID', 'N/A'),
            'summary'   : descs[0].get('value', '') if descs else '',
            'risk_score': impacts.get('baseScore', 0.0),
            'published' : item.get('publishedDate', '')[:10]
        })
    return cves

@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form['email']
    email_type = 'Work' if email.endswith(('.gov', '.org')) else 'Personal'
    conn = get_db()
    try:
        conn.execute('INSERT INTO subscribers (email,type) VALUES (?,?)',
                     (email, email_type))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    return redirect(url_for('homepage'))

@app.route('/dashboard')
def dashboard():
    conn = get_db()
    total_cves = conn.execute('SELECT COUNT(*) FROM visits').fetchone()[0]
    # dummy example, replace with real stats as needed
    high = med = low = 0
    recent = []  # could pull from DB or API
    conn.close()
    return render_template('dashboard.html',
                           total_cves=total_cves,
                           high=high, med=med, low=low,
                           recent=recent)

@app.route('/report')
def report():
    # 1) Generate PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial','B',16)
    pdf.cell(0,10,'VulneraX CVE Intelligence Report',ln=True,align='C')
    pdf.ln(10)
    pdf.set_font('Arial','',12)
    pdf.multi_cell(0,8,
      '- Top vulnerabilities (last 10 days)\n'
      '- Risk scores & sectors\n'
      '- Patch recommendations\n'
      '- Global threat insights'
    )
    pdf.ln(5)
    pdf.set_font('Arial','I',10)
    pdf.cell(0,8,f'Generated on: {datetime.utcnow():%Y-%m-%d %H:%M UTC}',
             ln=True, align='R')
    pdf.output(PDF_PATH)

    # 2) Fetch live CVEs
    rows = api_fetch_cves(days=10, limit=10)

    return render_template('report.html', cves=rows)

@app.route('/download-report')
def download_report():
    return send_file(PDF_PATH, as_attachment=True)

@app.route('/admin')
def admin_panel():
    conn = get_db()
    subs   = conn.execute('SELECT email, type, subscribed_on AS date FROM subscribers').fetchall()
    visits = conn.execute('SELECT COUNT(*) FROM visits').fetchone()[0]
    conn.close()
    return render_template('admin_panel.html',
                           subscribers=subs,
                           total_visits=visits,
                           total_subscribers=len(subs))

if __name__=='__main__':
    port = int(os.environ.get('PORT',5000))
    app.run(host='0.0.0.0', port=port, debug=True)
