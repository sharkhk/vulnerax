from celery_app import celery
from tasks import (
    fetch_raw_cves, annotate_cves, summarize_cves, patch_recommendations,
    fetch_threat_feed, rss_feed_generation, generate_pdf_report,
    email_alerts, slack_notification, code_editor, code_tester, code_implementer
)

class AgentManager:
    AGENTS = {
        'fetch_raw': fetch_raw_cves,
        'annotate': annotate_cves,
        'summarize': summarize_cves,
        'patch_rec': patch_recommendations,
        'threat_feed': fetch_threat_feed,
        'rss': rss_feed_generation,
        'pdf_report': generate_pdf_report,
        'email_alerts': email_alerts,
        'slack_notify': slack_notification,
        'code_editor': code_editor,
        'code_tester': code_tester,
        'code_implementer': code_implementer
    }

    @staticmethod
    def start_agent(name, *args, **kwargs):
        agent = AgentManager.AGENTS.get(name)
        if not agent:
            raise ValueError(f"Unknown agent: {name}")
        return agent.apply_async(args=args, kwargs=kwargs).id

    @staticmethod
    def status(task_id):
        res = celery.AsyncResult(task_id)
        return {'state': res.state, 'result': res.result if res.ready() else None}

    @staticmethod
    def revoke(task_id):
        celery.control.revoke(task_id, terminate=True)
        return {'revoked': True, 'task_id': task_id}
