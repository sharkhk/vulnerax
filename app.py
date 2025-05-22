from flask import Flask, jsonify, request, send_file
import requests
from datetime import datetime, timedelta
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
import os

app = Flask(__name__)

# NVD CVE API configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
API_KEY = os.getenv('NVD_API_KEY')  # Optional: set your NVD API key in env var


def fetch_recent_cves(days: int = 1):
    """
    Fetch CVE data published within the last `days` days from NVD.
    """
    start_date = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'
    params = {
        'pubStartDate': start_date,
        'resultsPerPage': 50
    }
    headers = {}
    if API_KEY:
        headers['apiKey'] = API_KEY

    resp = requests.get(NVD_API_URL, params=params, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return data.get('result', {}).get('CVE_Items', [])


def simplify_cve_item(item: dict) -> dict:
    """
    Extract key fields from a raw CVE JSON item.
    """
    meta = item['cve']['CVE_data_meta']
    desc_data = item['cve']['description']['description_data']
    description = desc_data[0]['value'] if desc_data else 'No description available.'
    impact = item.get('impact', {})
    base_metric = impact.get('baseMetricV3', impact.get('baseMetricV2', {}))
    score = base_metric.get('cvssV3', base_metric).get('baseScore', None)

    return {
        'id': meta.get('ID'),
        'description': description,
        'publishedDate': item.get('publishedDate'),
        'lastModifiedDate': item.get('lastModifiedDate'),
        'cvssScore': score
    }


def generate_pdf_report(cves: list, output_path: str = 'vulnerax_report.pdf') -> str:
    """
    Generate a PDF report listing CVEs with a simple layout.
    """
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    margin = inch

    # Cover page
    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(width / 2, height - 2 * inch, "VulneraX Daily Threat Report")
    c.setFont("Helvetica", 12)
    c.drawCentredString(width / 2, height - 2.5 * inch, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    c.showPage()

    # Content pages
    for idx, item in enumerate(cves, 1):
        simple = simplify_cve_item(item)
        y = height - margin
        c.setFont("Helvetica-Bold", 16)
        c.drawString(margin, y, f"{idx}. {simple['id']}  (Score: {simple.get('cvssScore', 'N/A')})")
        y -= 20
        c.setFont("Helvetica", 10)
        text = c.beginText(margin, y)
        for line in simple['description'].split('\n'):
            text.textLine(line)
        c.drawText(text)
        c.showPage()

    c.save()
    return output_path


@app.route('/api/cves', methods=['GET'])
def api_get_cves():
    days = int(request.args.get('days', 1))
    raw_items = fetch_recent_cves(days)
    simplified = [simplify_cve_item(i) for i in raw_items]
    return jsonify({
        'count': len(simplified),
        'cves': simplified
    })


@app.route('/api/report', methods=['GET'])
def api_get_report():
    days = int(request.args.get('days', 1))
    raw_items = fetch_recent_cves(days)
    report_file = generate_pdf_report(raw_items)
    return send_file(report_file, as_attachment=True, mimetype='application/pdf')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
