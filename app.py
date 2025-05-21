import os
import sqlite3
import requests
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from dotenv import load_dotenv
from fpdf import FPDF
from datetime import datetime, timedelta

# Load .env
load_dotenv()

DB_PATH = 'vulnerax.db'
PDF_PATH = '/tmp/vulnerax_report.pdf'
NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/1.0'

app = Flask(__name__)

# — Database helpers —
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = get_db().cursor()
    c.execute('''
      CREATE TABLE IF NOT EXISTS subscribers (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE,
        type TEXT,
        subscribed_on DATETIME DEFAULT CURRENT_TIMESTAMP
      );''')
    c.execute('''
      CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY,
        visited_on DATETIME DEFAULT CURRENT_TIMESTAMP
      );''')
    c.execute('''
      CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY,
        cve_id TEXT,
        summary TEXT,
        risk_score REAL,
        published DATE,
        inserted_on DATETIME DEFAULT CURRENT_TIMESTAMP
      );''')
    get_db().commit()

init_db()

@app.before_request
def track_visit():
    db = get_db()
    db.execute('INSERT INTO visits DEFAULT VALUES;')
    db.commit()

# — Routes —

@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form['email']
    email_type = 'Work' if email.endswith(('.gov', '.org')) else 'Personal'
    db = get_db()
    try:
        db.execute('INSERT INTO subscribers (email,type) VALUES (?,?);',
                   (email, email_type))
        db.commit()
    except sqlite3.IntegrityError:
        pass
    return redirect(url_for('homepage'))

@app.route('/dashboard')
def dashboard():
    db = get_db()
    total_cves = db.execute('SELECT COUNT(*) FROM cves;').fetchone()[0]
    high = db.execute('SELECT COUNT(*) FROM cves WHERE risk_score>=7;').fetchone()[0]
    med  = db.execute('SELECT COUNT(*) FROM cves WHERE risk_score BETWEEN 4 AND 7;').fetchone()[0]
    low  = db.execute('SELECT COUNT(*) FROM cves WHERE risk_score<4;').fetchone()[0]
    recent = db.execute(
      'SELECT cve_id, risk_score, published FROM cves ORDER BY published DESC LIMIT 5;'
    ).fetchall()
    return render_template('dashboard.html',
                           total_cves=total_cves, high=high,
                           med=med, low=low, recent=recent)

@app.route('/api/live-cves')
def api_live_cves():
    """Fetch live CVEs from NVD for the past 1 day."""
    yesterday = (datetime.utcnow()-timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S:000 UTC-00:00')
    params = {'pubStartDate': yesterday, 'resultsPerPage': 10}
    resp = requests.get(NVD_API, params=params, timeout=10)
    data = resp.json().get('result', {}).get('CVE_Items', [])
    out = []
    for item in data:
        meta = item['cve']['CVE_data_meta']
        summary = item['cve']['description']['description_data'][0]['value']
        # attempt CVSS v3 first
        metrics = item.get('impact', {}).get('baseMetricV3', {})
        score = metrics.get('cvssV3', {}).get('baseScore', None)
        published = item.get('publishedDate', '')[:10]
        # patch recommendation placeholder
        rec = "Check vendor advisory for patch instructions."
        out.append({
            'id': meta['ID'],
            'summary': summary,
            'risk': round(score,1) if score else 'N/A',
            'date': published,
            'recommendation': rec
        })
    return jsonify(out)

@app.route('/report')
def report():
    # regenerate PDF
    pdf = FPDF()
    pdf.add_page(); pdf.set_font('Arial','B',16)
    pdf.cell(0,10,'VulneraX CVE Intelligence Report',ln=True,align='C')
    pdf.ln(8); pdf.set_font('Arial','',12)
    pdf.multi_cell(0,8,
      '- Live CVEs from past 10 days\n'
      '- Risk scores & affected sectors\n'
      '- Recommended patch actions\n'
      '- Global threat summaries'
    )
    pdf.ln(5); pdf.set_font('Arial','I',10)
    pdf.cell(0,8,f'Generated: {datetime.utcnow():%Y-%m-%d %H:%M UTC}',ln=True,align='R')
    pdf.output(PDF_PATH)

    # fetch from DB last 10 days
    cutoff = (datetime.utcnow()-timedelta(days=10)).date().isoformat()
    rows = get_db().execute(
      'SELECT cve_id, summary, risk_score, published FROM cves '
      'WHERE published>=? ORDER BY published DESC;',
      (cutoff,)
    ).fetchall()
    return render_template('report.html', cves=rows)

@app.route('/download-report')
def download_report():
    return send_file(PDF_PATH, as_attachment=True)

@app.route('/admin')
def admin_panel():
    db = get_db()
    subs = db.execute('SELECT email,type AS email_type,subscribed_on AS date FROM subscribers;').fetchall()
    visits = db.execute('SELECT COUNT(*) FROM visits;').fetchone()[0]
    cves   = db.execute('SELECT COUNT(*) FROM cves;').fetchone()[0]
    return render_template('admin_panel.html',
                           subscribers=subs,
                           total_visits=visits,
                           total_subscribers=len(subs),
                           total_cves=cves)

if __name__=='__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT',5000)), debug=True)
