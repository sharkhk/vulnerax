import requests
from flask import current_app

class CVEService:
    @staticmethod
    def fetch_recent_cves(limit: int):
        url = f"{current_app.config['CIRCL_API_URL']}/last"
        headers = {'User-Agent': 'VulneraX-Agentic/1.0'}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data[:limit]

    @staticmethod
    def fetch_cve(cve_id: str):
        if cve_id.upper().startswith('CVE-'):
            url = f"{current_app.config['CIRCL_API_URL']}/cve/{cve_id}"
        else:
            url = f"https://api.github.com/advisories/{cve_id}"
        headers = {'User-Agent': 'VulneraX-Agentic/1.0'}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def simplify(item: dict) -> dict:
        cve_id = item.get('id') or item.get('CVE') or item.get('ghsaId') or 'Unknown ID'
        desc = item.get('summary') or item.get('description') or ''
        pub = item.get('Published') or item.get('published') or item.get('created_at') or ''
        mod = item.get('Modified') or item.get('modified') or item.get('updated_at') or ''
        score = item.get('cvss') or item.get('cvss_score') or None
        return {
            'id': cve_id,
            'description': desc,
            'publishedDate': pub,
            'lastModifiedDate': mod,
            'cvssScore': score
        }
