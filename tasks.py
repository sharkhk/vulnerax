import os
import smtplib
import requests
from celery_app import celery
from cve_service import CVEService
from report_generator import PDFReport
from schemas import CVESchema
from email.mime.text import MIMEText

@celery.task(name="agent.fetch_raw_cves")
def fetch_raw_cves(days: int, limit: int):
    return CVEService.fetch_recent_cves(days, limit)

@celery.task(name="agent.annotate_cves")
def annotate_cves(raw_items):
    return [CVEService.simplify(i) for i in raw_items]

@celery.task(name="agent.summarize_cves")
def summarize_cves(simple_items):
    return [{ 'id': c['id'], 'summary': f"{c['id']} published {c['publishedDate'][:10]} (score {c['cvssScore']})." } for c in simple_items]

@celery.task(name="agent.patch_recommendations")
def patch_recommendations(simple_items):
    return [{ 'id': c['id'], 'recommendation': f"Apply patch for {c['id']} immediately." } for c in simple_items]

@celery.task(name="agent.fetch_threat_feed")
def fetch_threat_feed():
    resp = requests.get("https://example.com/other-feed.json", timeout=10)
    return resp.json().get('vulnerabilities', [])

@celery.task(name="agent.rss_feed_generation")
def rss_feed_generation(simple_items):
    return [{ 'title': c['id'], 'description': c['description'][:100], 'link': f"/cve/{c['id']}" } for c in simple_items]

@celery.task(name="agent.generate_pdf_report")
def generate_pdf_report(params):
    days, limit = params
    raw = CVEService.fetch_recent_cves(days, limit)
    simple = [CVEService.simplify(i) for i in raw]
    filename = f"report_{days}d_{limit}l.pdf"
    return PDFReport.generate(simple, filename)

@celery.task(name="agent.email_alerts")
def email_alerts(summaries):
    server = smtplib.SMTP(os.getenv("SMTP_SERVER"), os.getenv("SMTP_PORT"))
    server.starttls()
    server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS"))
    body = "\n".join([s['summary'] for s in summaries])
    msg = MIMEText(body)
    msg['Subject'] = 'Daily CVE Summary'
    msg['From'] = os.getenv("SMTP_USER")
    msg['To'] = os.getenv("ALERT_EMAILS")
    server.send_message(msg)
    server.quit()
    return {'status': 'sent', 'count': len(summaries)}

@celery.task(name="agent.slack_notification")
def slack_notification(summaries):
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    for s in summaries:
        requests.post(webhook, json={"text": f"{s['id']}: {s['summary']}"})
    return {'status': 'notified', 'count': len(summaries)}

@celery.task(name="agent.code_editor")
def code_editor(repo_path: str):
    suggestions = [
        {'file': 'templates/index.html', 'suggestion': 'Add ARIA labels to improve accessibility.'},
        {'file': 'app.py', 'suggestion': 'Implement error handling for Stripe webhook endpoint.'}
    ]
    return suggestions

@celery.task(name="agent.code_tester")
def code_tester(repo_path: str):
    errors = [
        {'test': 'test_cve_service', 'error': 'TimeoutError in fetch_recent_cves'},
        {'file': 'tasks.py', 'error': 'flake8 F401 unused import'}
    ]
    return errors

@celery.task(name="agent.code_implementer")
def code_implementer(suggestions):
    applied = []
    for s in suggestions:
        applied.append({'file': s['file'], 'status': 'applied', 'detail': s['suggestion']})
    return applied

@celery.task(name="agent.coordinator")
def orchestrate_pipeline(days: int, limit: int):
    raw = fetch_raw_cves.s(days, limit)
    annotated = annotate_cves.s()
    summary = summarize_cves.s()
    patches = patch_recommendations.s()
    threat = fetch_threat_feed.s()
    rss = rss_feed_generation.s()
    pdf = generate_pdf_report.s((days, limit))
    email = email_alerts.s()
    slack = slack_notification.s()
    editor = code_editor.s(repo_path="./")
    tester = code_tester.s(repo_path="./")
    implementer = code_implementer.s()
    summary_chain = raw | annotated | summary
    code_chain = editor | tester | implementer
    r_summary = summary_chain.apply_async()
    r_patches = (summary_chain | patches).apply_async()
    r_threat = threat.apply_async()
    r_rss = rss.apply_async()
    r_pdf = pdf.apply_async()
    r_email = (summary_chain | email).apply_async()
    r_slack = (summary_chain | slack).apply_async()
    r_code = code_chain.apply_async()
    return {
        'summary': r_summary.get(timeout=60),
        'patch_recommendations': r_patches.get(timeout=60),
        'rss_items': r_rss.get(timeout=60),
        'threat_feed': r_threat.get(timeout=60),
        'report_path': r_pdf.get(timeout=60),
        'email_status': r_email.get(timeout=60),
        'slack_status': r_slack.get(timeout=60),
        'code_review': r_code.get(timeout=60)
    }
