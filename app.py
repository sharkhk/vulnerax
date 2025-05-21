from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
import sqlite3
import requests
from fpdf import FPDF
from datetime import datetime, timedelta
import os

# --- CONFIGURATION ---
DB_PATH = 'vulnerax.db'
PDF_PATH = '/tmp/vulnerax_report.pdf'
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/1.0'

# --- APP SETUP ---
app = Flask(__name__)

# --- DATABASE HELPERS ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database tables
with get_db_connection() as conn:
    c = conn.cursor()
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
    c.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE,
            summary TEXT,
            risk_score REAL,
            published DATE,
            recommendation TEXT,
            inserted_on DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()

# --- UTILITIES ---
@app.before_request
def track_visit():
    conn = get_db_connection()
    conn.execute('INSERT INTO visits DEFAULT VALUES')
    conn.commit()
    conn.close()


def fetch_recent_cves(days=10, max_results=10):
    """Fetch recent CVEs from NVD, store/update in DB, return list of dicts."""
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    params = {
        'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S:000 UTC+00:00'),
        'pubEndDate': end.strftime('%Y-%m-%dT%H:%M:%S:000 UTC+00:00'),
        'resultsPerPage': max_results
    }
    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=15)
        items = resp.json().get('result', {}).get('CVE_Items', [])
    except Exception:
        items = []

    cves = []
    conn = get_db_connection()
    for item in items:
        meta = item['cve']['CVE_data_meta']
        cve_id = meta['ID']
        summary = item['cve']['description']['description_data'][0]['value']
        impact = item.get('impact', {})
        score = None
        if impact.get('baseMetricV3'):
            score = impact['baseMetricV3']['cvssV3']['baseScore']
        elif impact.get('baseMetricV2'):
            score = impact['baseMetricV2']['cvssV2']['baseScore']
        recommendation = 'Refer to official vendor advisory for patch instructions.'
        published = item.get('publishedDate', '').split('T')[0]
        cves.append({
            'cve_id': cve_id,
            'summary': summary,
            'risk_score': score,
            'published': published,
            'recommendation': recommendation
        })
        # Insert or update DB
        try:
            conn.execute(
                'INSERT INTO cves (cve_id, summary, risk_score, published, recommendation) VALUES (?, ?, ?, ?, ?)',
                (cve_id, summary, score, published, recommendation)
            )
        except sqlite3.IntegrityError:
            conn.execute(
                'UPDATE cves SET summary=?, risk_score=?, published=?, recommendation=? WHERE cve_id=?',
                (summary, score, published, recommendation, cve_id)
            )
    conn.commit()
    conn.close()
    return cves

# --- ROUTES ---
@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    email_type = 'Work' if email.endswith(('.gov', '.org')) else 'Personal'
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO subscribers (email, type) VALUES (?, ?)', (email, email_type))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    return redirect(url_for('homepage'))

@app.route('/dashboard')
def dashboard():
    conn = get_db_connection()
    total_cves = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    high = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score>=7').fetchone()[0]
    med = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score BETWEEN 4 AND 7').fetchone()[0]
    low = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score<4').fetchone()[0]
    recent = conn.execute('SELECT cve_id, risk_score, published FROM cves ORDER BY published DESC LIMIT 5').fetchall()
    conn.close()
    return render_template('dashboard.html', total_cves=total_cves, high=high, med=med, low=low, recent=recent)

@app.route('/api/cves')
def api_cves():
    cves = fetch_recent_cves(days=10, max_results=10)
    return jsonify(cves)

@app.route('/report')
def report():
    cves = fetch_recent_cves(days=10, max_results=10)
    # Generate PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'VulneraX CVE Intelligence Report', ln=True, align='C')
    pdf.ln(10)
    pdf.set_font('Arial', '', 12)
    for cv in cves:
        pdf.multi_cell(0, 8, f"{cv['cve_id']} ({cv['risk_score']}): {cv['summary']}")
        pdf.multi_cell(0, 8, f"Recommendation: {cv['recommendation']}")
        pdf.ln(3)
    pdf.ln(5)
    pdf.set_font('Arial', 'I', 10)
    pdf.cell(0, 8, f"Generated on: {datetime.utcnow():%Y-%m-%d %H:%M UTC}", ln=True, align='R')
    pdf.output(PDF_PATH)
    return render_template('report.html', cves=cves)

@app.route('/download-report')
def download_report():
    return send_file(PDF_PATH, as_attachment=False)

@app.route('/admin')
def admin_panel():
    conn = get_db_connection()
    subs = conn.execute('SELECT email, type AS email_type, subscribed_on AS date FROM subscribers').fetchall()
    visits = conn.execute('SELECT COUNT(*) FROM visits').fetchone()[0]
    cves_count = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    conn.close()
    return render_template('admin_panel.html', subscribers=subs, total_visits=visits, total_subscribers=len(subs), total_cves=cves_count)

if __name__=='__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
