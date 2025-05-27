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
        return {
            'id': item.get('id'),
            'description': item.get('summary', ''),
            'publishedDate': item.get('Published'),
            'lastModifiedDate': item.get('Modified'),
            'cvssScore': item.get('cvss')
        }
