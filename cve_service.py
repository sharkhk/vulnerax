import requests
from flask import current_app

class CVEService:
    @staticmethod
    def fetch_recent_cves(days: int, limit: int):
        """
        Fetch recent CVEs from CIRCL public API.
        """
        url = 'https://cve.circl.lu/api/last'
        headers = {'User-Agent': 'VulneraX-Agentic/1.0'}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # Return up to `limit` entries
        return data[:limit]

    @staticmethod
    def simplify(item: dict) -> dict:
        # Handle both lowercase and uppercase keys
        cve_id = item.get('id') or item.get('ID') or 'Unknown ID'
        desc = item.get('summary') or item.get('Summary') or ''
        pub = item.get('Published') or item.get('published') or ''
        mod = item.get('Modified') or item.get('modified') or ''
        score = item.get('cvss') or item.get('CVSS')
        return {
            'id': cve_id,
            'description': desc,
            'publishedDate': pub,
            'lastModifiedDate': mod,
            'cvssScore': score
        }
