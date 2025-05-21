import sqlite3
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from fpdf import FPDF
from datetime import datetime
import os

# --- CONFIGURATION ---
DB_PATH = 'vulnerax.db'

# --- APP SETUP ---
app = Flask(__name__)

# --- DATABASE HELPERS ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    # Subscribers table
    c.execute('''
      CREATE TABLE IF NOT EXISTS subscribers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        type TEXT,
        subscribed_on DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    ''')
    # Visits table
    c.execute('''
      CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visited_on DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    ''')
    # CVEs table
    c.execute('''
      CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        summary TEXT,
        risk_score REAL,
        published DATE,
        inserted_on DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    ''')
    conn.commit()
    conn.close()

# Initialize DB on startup
init_db()

# --- ROUTES ---

@app.before_request
def track_visit():
    conn = get_db_connection()
    conn.execute('INSERT INTO visits DEFAULT VALUES')
    conn.commit()
    conn.close()

@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    if email:
        email_type = 'Work' if (email.endswith('.gov') or email.endswith('.org')) else 'Personal'
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO subscribers (email, type) VALUES (?, ?)',
                (email, email_type)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # already subscribed
        conn.close()
    return redirect(url_for('homepage'))

@app.route('/dashboard')
def dashboard():
    conn = get_db_connection()
    total_cves = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    high = conn.execute("SELECT COUNT(*) FROM cves WHERE risk_score >= 7").fetchone()[0]
    med = conn.execute("SELECT COUNT(*) FROM cves WHERE risk_score BETWEEN 4 AND 7").fetchone()[0]
    low = conn.execute("SELECT COUNT(*) FROM cves WHERE risk_score < 4").fetchone()[0]
    recent = conn.execute('''
      SELECT cve_id, risk_score, published
      FROM cves ORDER BY published DESC LIMIT 5
    ''').fetchall()
    conn.close()
    return render_template('dashboard.html',
                           total_cves=total_cves,
                           high=high, med=med, low=low,
                           recent=recent)

@app.route('/api/latest-cves')
def api_latest_cves():
    conn = get_db_connection()
    rows = conn.execute('''
      SELECT cve_id AS id, summary, risk_score AS risk, published AS date
      FROM cves ORDER BY published DESC LIMIT 10
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/report')
def report():
    return render_template('report.html')

@app.route('/generate-report')
def generate_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'VulneraX CVE Intelligence Report', ln=True, align='C')
    pdf.ln(10)
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 8, '- Top 10 vulnerabilities (scored by AI)\n- Risk breakdown & sectors\n- Patch recommendations\n- Global threat events & awareness')
    pdf.ln(5)
    pdf.set_font('Arial', 'I', 10)
    pdf.cell(0, 8, f'Generated on: {datetime.utcnow():%Y-%m-%d %H:%M UTC}', ln=True, align='R')
    output_path = '/tmp/vulnerax_report.pdf'
    pdf.output(output_path)
    return send_file(output_path, as_attachment=True)

@app.route('/admin')
def admin_panel():
    conn = get_db_connection()
    subs = conn.execute('SELECT email, type AS email_type, subscribed_on AS date FROM subscribers').fetchall()
    visits = conn.execute('SELECT COUNT(*) FROM visits').fetchone()[0]
    cves = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    conn.close()
    return render_template('admin_panel.html',
                           subscribers=subs,
                           total_visits=visits,
                           total_subscribers=len(subs),
                           total_cves=cves)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
