import os
from dotenv import load_dotenv
load_dotenv()

import sqlite3
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from fpdf import FPDF
from datetime import datetime, timedelta
import requests

# --- CONFIG ---
DB_PATH     = 'vulnerax.db'
PDF_PATH    = '/tmp/vulnerax_report.pdf'
NVD_API_KEY = os.environ.get('NVD_API_KEY')

app = Flask(__name__)

# --- DB Helpers ---
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
        cve_id TEXT, summary TEXT, risk_score REAL, published DATE
      )
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Fetch live CVEs from NVD ---
def fetch_live_cves(days=10, limit=10):
    base = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    start = (datetime.utcnow() - timedelta(days=days))\
            .strftime('%Y-%m-%dT%H:%M:%S:000 UTC+00:00')
    params = {
        'pubStartDate': start,
        'resultsPerPage': limit
    }
    headers = {'apiKey': NVD_API_KEY}
    r = requests.get(base, params=params, headers=headers)
    r.raise_for_status()
    items = r.json().get('result', {}).get('CVE_Items', [])
    results = []
    for it in items:
        meta     = it['cve']['CVE_data_meta']
        cve_id   = meta['ID']
        desc     = it['cve']['description']['description_data'][0]['value']
        impact   = it.get('impact', {}).get('baseMetricV3')
        score    = impact['cvssV3']['baseScore'] if impact else None
        pub_date = it.get('publishedDate','')[:10]
        url      = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        results.append({
          'cve_id': cve_id,
          'summary': desc,
          'risk_score': score,
          'published': pub_date,
          'url': url
        })
    return results

# --- Routes ---

@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/report')
def report():
    # generate PDF for download in /download-report
    cves = fetch_live_cves()
    # store to DB (optional)
    conn = get_db()
    conn.execute('DELETE FROM cves')  # clear old
    for c in cves:
        conn.execute(
          'INSERT INTO cves (cve_id, summary, risk_score, published) VALUES (?,?,?,?)',
          (c['cve_id'], c['summary'], c['risk_score'], c['published'])
        )
    conn.commit(); conn.close()

    return render_template('report.html', cves=cves)

@app.route('/download-report')
def download_report():
    cves = fetch_live_cves()
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial','B',16)
    pdf.cell(0,10,'VulneraX CVE Intelligence Report',ln=True,align='C')
    pdf.ln(8)
    pdf.set_font('Arial','',12)
    pdf.multi_cell(0,8,
      '- Live Top CVEs (last 10 days)\n'
      '- Risk scores & sectors\n'
      '- Patch guidance links\n'
      '- Global threat insights'
    )
    pdf.ln(6)
    for c in cves:
        pdf.set_font('Arial','B',12)
        pdf.cell(0,6,c['cve_id'],ln=True)
        pdf.set_font('Arial','',10)
        pdf.multi_cell(0,5, c['summary'])
        pdf.cell(0,5, f"Risk: {c['risk_score']}", ln=True)
        pdf.cell(0,5, f"Published: {c['published']}", ln=True)
        pdf.set_text_color(0,0,255)
        pdf.cell(0,5, c['url'], ln=True)
        pdf.set_text_color(0,0,0)
        pdf.ln(4)
    pdf.ln(4)
    pdf.set_font('Arial','I',8)
    pdf.cell(0,5, f'Generated: {datetime.utcnow():%Y-%m-%d %H:%M UTC}', align='R')
    pdf.output(PDF_PATH)
    return send_file(PDF_PATH, as_attachment=True)

# (Other routes—dashboard, subscribe, admin—unchanged…)

if __name__=='__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)), debug=True)
