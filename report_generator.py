import os
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from flask import current_app
from datetime import datetime

class PDFReport:
    @staticmethod
    def generate(cves: list, filename: str) -> str:
        os.makedirs(current_app.config['REPORTS_DIR'], exist_ok=True)
        filepath = os.path.join(current_app.config['REPORTS_DIR'], filename)

        doc = SimpleDocTemplate(filepath)
        styles = getSampleStyleSheet()
        elements = [Paragraph("VulneraX Threat Report", styles['Title']), Spacer(1, 12)]
        elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles['Normal']))
        elements.append(Spacer(1, 24))

        data = [["#", "CVE ID", "Score", "Published", "Description"]]
        for i, cve in enumerate(cves, 1):
            data.append([
                str(i), cve['id'],
                str(cve.get('cvssScore', 'N/A')),
                cve['publishedDate'][:10],
                (cve['description'][:97] + '...') if len(cve['description']) > 100 else cve['description']
            ])
        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,0), colors.lightgrey),
            ('GRID', (0,0),(-1,-1), 0.5, colors.grey),
            ('VALIGN', (0,0),(-1,-1), 'TOP')
        ]))
        elements.append(table)

        doc.build(elements)
        return filepath

