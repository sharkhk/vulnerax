import os
import sqlite3
import requests
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, jsonify
)
from fpdf import FPDF
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load .env
load_dotenv()

# --- CONFIGURATION ---
DB_PATH     = 'vulnerax.db'
PDF_PATH    = '/tmp/vulnerax_report.pdf'
NVD_API_KEY = os.getenv('NVD_API_KEY')
NVD_URL     = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

app = Flask(__name__)

# --- DATABASE HELPERS ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
      CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        summary TEXT,
        risk_score REAL,
        recommendation TEXT,
        published DATE
      )
    ''')
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
    conn.commit()
    conn.close()

init_db()

@app.before_request
def track_visit():
    conn = get_db()
    conn.execute('INSERT INTO visits DEFAULT VALUES')
    conn.commit()
    conn.close()

# --- ML SCORING STUB & RECOMMENDATION GENERATOR ---
def score_and_recommend(cve_item):
    # Example: use baseMetricV3 CVSS score if present
    metrics = cve_item.get('metrics', {})
    base_score = None
    if 'cvssMetricV31' in metrics:
        base_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
    elif 'cvssMetricV30' in metrics:
        base_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
    else:
        base_score = 5.0  # default
    # Simple risk category
    if base_score >= 9:    rec = "Patch immediately"
    elif base_score >= 7:  rec = "Schedule urgent patch"
    elif base_score >= 4:  rec = "Plan patch soon"
    else:                  rec = "Monitor"
    return base_score, rec

# --- ROUTES ---

@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/dashboard')
def dashboard():
    conn = get_db()
    total_cves = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    high       = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score>=7').fetchone()[0]
    med        = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score BETWEEN 4 AND 7').fetchone()[0]
    low        = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score<4').fetchone()[0]
    recent     = conn.execute(
        'SELECT cve_id, risk_score, published FROM cves ORDER BY published DESC LIMIT 5'
    ).fetchall()
    conn.close()
    return render_template('dashboard.html',
                           total_cves=total_cves,
                           high=high, med=med, low=low,
                           recent=recent)

@app.route('/api/fetch-cves')
def api_fetch_cves():
    """Fetch last 10 days of CVEs from NVD, score them, store in DB, return JSON."""
    since_date = (datetime.utcnow() - timedelta(days=10)).strftime('%Y-%m-%dT%H:%M:%S:000 UTC+00:00')
    params = {
        'pubStartDate': since_date,
        'resultsPerPage': 20,
        'apiKey': NVD_API_KEY
    }
    resp = requests.get(NVD_URL, params=params)
    data = resp.json().get('vulnerabilities', [])

    conn = get_db()
    c = conn.cursor()
    output = []

    for item in data:
        cve = item['cve']
        cve_id = cve['id']
        summary = cve['descriptions'][0]['value']
        risk, rec = score_and_recommend(item)
        published = cve['published']
        # Insert or replace
        c.execute('''
          INSERT OR REPLACE INTO cves(cve_id, summary, risk_score, recommendation, published)
          VALUES (?,?,?,?,?)
        ''', (cve_id, summary, risk, rec, published))
        output.append({
            'id': cve_id,
            'summary': summary,
            'risk': risk,
            'recommendation': rec,
            'published': published
        })

    conn.commit()
    conn.close()
    return jsonify(output)

@app.route('/report')
def report():
    # Ensure data is fresh
    api_fetch_cves()

    conn = get_db()
    rows = conn.execute(
        'SELECT cve_id, summary, risk_score, recommendation, published '
        'FROM cves ORDER BY published DESC LIMIT 10'
    ).fetchall()
    conn.close()
    return render_template('report.html', cves=rows)

@app.route('/download-report')
def download_report():
    # (Re)generate PDF for embed
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial','B',16)
    pdf.cell(0,10,'VulneraX CVE Intelligence Report',ln=True,align='C')
    pdf.ln(8)
    pdf.set_font('Arial','',12)
    for row in get_db().execute(
        'SELECT cve_id, risk_score, recommendation FROM cves '
        'ORDER BY published DESC LIMIT 10'
    ):
        pdf.multi_cell(0,8,
            f"{row['cve_id']} — Risk {row['risk_score']:.1f}\n"
            f"Recommendation: {row['recommendation']}\n"
        )
        pdf.ln(2)
    pdf.ln(5)
    pdf.set_font('Arial','I',10)
    pdf.cell(0,8,f"Generated on {datetime.utcnow():%Y-%m-%d %H:%M UTC}",ln=True,align='R')
    pdf.output(PDF_PATH)
    return send_file(PDF_PATH)

@app.route('/admin')
def admin_panel():
    conn = get_db()
    subs   = conn.execute('SELECT email, type, subscribed_on AS date FROM subscribers').fetchall()
    visits = conn.execute('SELECT COUNT(*) FROM visits').fetchone()[0]
    cves   = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    conn.close()
    return render_template('admin_panel.html',
                           subscribers=subs,
                           total_visits=visits,
                           total_subscribers=len(subs),
                           total_cves=cves)

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form['email']
    typ   = 'Work' if email.endswith(('.gov','.org')) else 'Personal'
    conn  = get_db()
    try:
        conn.execute('INSERT INTO subscribers(email,type) VALUES(?,?)',
                     (email, typ))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    return redirect(url_for('homepage'))

if __name__=='__main__':
    port = int(os.environ.get('PORT',5000))
    app.run(host='0.0.0.0',port=port,debug=True)
