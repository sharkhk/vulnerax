from dotenv import load_dotenv
load_dotenv()   # reads .env into os.environ

import sqlite3
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from fpdf import FPDF
from datetime import datetime, timedelta
import os

DB_PATH = 'vulnerax.db'
PDF_PATH = '/tmp/vulnerax_report.pdf'

app = Flask(__name__)

# — Database helpers —
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
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
        cve_id TEXT,
        summary TEXT,
        risk_score REAL,
        published DATE,
        inserted_on DATETIME DEFAULT CURRENT_TIMESTAMP
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

# — Routes —

@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form['email']
    email_type = 'Work' if email.endswith(('.gov', '.org')) else 'Personal'
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO subscribers (email, type) VALUES (?, ?)',
            (email, email_type)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    return redirect(url_for('homepage'))

@app.route('/dashboard')
def dashboard():
    conn = get_db()
    total_cves = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    high = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score>=7').fetchone()[0]
    med  = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score BETWEEN 4 AND 7').fetchone()[0]
    low  = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score<4').fetchone()[0]
    recent = conn.execute(
        'SELECT cve_id, risk_score, published FROM cves ORDER BY published DESC LIMIT 5'
    ).fetchall()
    conn.close()
    return render_template('dashboard.html',
                           total_cves=total_cves,
                           high=high, med=med, low=low,
                           recent=recent)

@app.route('/report')
def report():
    # generate PDF
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
    pdf.cell(0,8,f'Generated on: {datetime.utcnow():%Y-%m-%d %H:%M UTC}',ln=True,align='R')
    pdf.output(PDF_PATH)

    # fetch last 10 days CVEs
    cutoff = (datetime.utcnow() - timedelta(days=10)).date().isoformat()
    conn = get_db()
    rows = conn.execute(
      'SELECT cve_id, summary, risk_score, published FROM cves '
      'WHERE published>=? ORDER BY published DESC',
      (cutoff,)
    ).fetchall()
    conn.close()

    return render_template('report.html', cves=rows)

@app.route('/download-report')
def download_report():
    return send_file(PDF_PATH)

@app.route('/admin')
def admin_panel():
    conn = get_db()
    subs = conn.execute(
      'SELECT email, type, subscribed_on AS date FROM subscribers'
    ).fetchall()
    visits = conn.execute('SELECT COUNT(*) FROM visits').fetchone()[0]
    cves   = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    conn.close()
    return render_template('admin_panel.html',
                           subscribers=subs,
                           total_visits=visits,
                           total_subscribers=len(subs),
                           total_cves=cves)

if __name__=='__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
