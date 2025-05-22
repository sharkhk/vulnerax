from dotenv import load_dotenv
load_dotenv()

import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from fpdf import FPDF
from datetime import datetime, timedelta
import requests
import openai

# --- CONFIGURATION ---
DB_PATH      = 'vulnerax.db'
PDF_PATH     = '/tmp/vulnerax_report.pdf'
NVD_API_URL  = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
openai.api_key = os.getenv('OPENAI_API_KEY')

app = Flask(__name__)

# --- DATABASE SETUP ---
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
        email TEXT UNIQUE, type TEXT,
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
        cve_id TEXT, summary TEXT,
        risk_score REAL, published DATE,
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

# --- LIVE CVE FETCH + AI RECOMMEND ---
def fetch_live_cves(days=7, max_results=10):
    end   = datetime.utcnow()
    start = end - timedelta(days=days)
    params = {
      'modStartDate': start.strftime('%Y-%m-%dT%H:%M:%S:000 UTC+00:00'),
      'modEndDate':   end.strftime('%Y-%m-%dT%H:%M:%S:000 UTC+00:00'),
      'resultsPerPage': max_results
    }
    r = requests.get(NVD_API_URL, params=params)
    items = r.json().get('result', {}).get('CVE_Items', [])
    cves = []
    for it in items:
        meta    = it['cve']['CVE_data_meta']
        desc    = it['cve']['description']['description_data'][0]['value']
        impact  = it.get('impact', {}).get('baseMetricV3')
        score   = impact['cvssV3']['baseScore'] if impact else None
        published = it.get('publishedDate','')[:10]
        # AI recommendation
        prompt = f"Provide patch guidance for {meta['ID']}: {desc}"
        ai_resp = openai.Completion.create(
          engine="text-davinci-003",
          prompt=prompt,
          max_tokens=100
        )
        reco = ai_resp.choices[0].text.strip()
        cves.append({
          'cve_id':         meta['ID'],
          'summary':        desc,
          'risk_score':     score,
          'published':      published,
          'recommendation': reco
        })
    return cves

@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form['email']
    t = 'Work' if email.endswith(('.gov','.org')) else 'Personal'
    conn = get_db()
    try:
        conn.execute('INSERT INTO subscribers(email,type) VALUES(?,?)',(email,t))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    return redirect(url_for('homepage'))

@app.route('/dashboard')
def dashboard():
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    high  = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score>=7').fetchone()[0]
    med   = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score BETWEEN 4 AND 7').fetchone()[0]
    low   = conn.execute('SELECT COUNT(*) FROM cves WHERE risk_score<4').fetchone()[0]
    recent= conn.execute('SELECT cve_id, risk_score, published FROM cves ORDER BY published DESC LIMIT 5').fetchall()
    conn.close()
    return render_template('dashboard.html',
                           total_cves=total,
                           high=high, med=med, low=low,
                           recent=recent)

@app.route('/api/live-cves')
def api_live_cves():
    return jsonify(fetch_live_cves())

@app.route('/report')
def report():
    cves = fetch_live_cves(days=10, max_results=10)
    # also store into DB
    conn = get_db()
    for c in cves:
        conn.execute('''
          INSERT OR IGNORE INTO cves(cve_id,summary,risk_score,published)
          VALUES(?,?,?,?)
        ''',(c['cve_id'],c['summary'],c['risk_score'],c['published']))
    conn.commit(); conn.close()
    # generate PDF for embed
    pdf = FPDF(); pdf.add_page()
    pdf.set_font('Arial','B',14)
    pdf.cell(0,10,'VulneraX 10-Day CVE Report',ln=True,align='C')
    pdf.ln(8)
    pdf.set_font('Arial','',12)
    for c in cves:
        pdf.multi_cell(0,8,f"{c['cve_id']} ({c['risk_score']}): {c['summary']}")
        pdf.ln(2)
        pdf.multi_cell(0,6,f"→ Recommendation: {c['recommendation']}")
        pdf.ln(4)
    pdf.ln(4)
    pdf.set_font('Arial','I',8)
    pdf.cell(0,6,f"Generated: {datetime.utcnow():%Y-%m-%d %H:%M UTC}",align='R')
    pdf.output(PDF_PATH)
    return render_template('report.html', cves=cves)

@app.route('/download-report')
def download():
    return send_file(PDF_PATH, as_attachment=True)

@app.route('/admin')
def admin_panel():
    conn = get_db()
    subs = conn.execute('SELECT email,type,subscribed_on AS date FROM subscribers').fetchall()
    visits = conn.execute('SELECT COUNT(*) FROM visits').fetchone()[0]
    cves   = conn.execute('SELECT COUNT(*) FROM cves').fetchone()[0]
    conn.close()
    return render_template('admin_panel.html',
                           subscribers=subs,
                           total_visits=visits,
                           total_subscribers=len(subs),
                           total_cves=cves)

if __name__=='__main__':
    p = int(os.environ.get('PORT',5000))
    app.run(host='0.0.0.0',port=p,debug=True)
