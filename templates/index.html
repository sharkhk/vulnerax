import requests
from datetime import datetime
from flask import current_app

class CVEService:
    @staticmethod
    def fetch_recent_cves(days: int, limit: int):
        """
        Fetch recent CVEs using CIRCL API as fallback (no API key required).
        """
        try:
            # Attempt NVD API
            end = datetime.utcnow().isoformat() + 'Z'
            start = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'
            params = {'pubStartDate': start, 'pubEndDate': end, 'resultsPerPage': limit}
            headers = {'User-Agent': 'VulneraX-Agentic/1.0', 'apiKey': current_app.config.get('NVD_API_KEY')}
            resp = requests.get(current_app.config['NVD_API_URL'], params=params, headers=headers, timeout=10)
            resp.raise_for_status()
            items = resp.json().get('result', {}).get('CVE_Items', [])
            return items
        except Exception:
            # Fallback to CIRCL API
            url = 'https://cve.circl.lu/api/last'
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            # Map CIRCL entries to NVD-like items
            items = []
            for entry in data[:limit]:
                items.append({
                    'cve': {'CVE_data_meta': {'ID': entry.get('id')}, 'description': {'description_data': [{'value': entry.get('summary')}]}},
                    'publishedDate': entry.get('Published'),
                    'lastModifiedDate': entry.get('Modified'),
                    'impact': {'baseMetricV3': {'cvssV3': {'baseScore': entry.get('cvss')}}}
                })
            return items

    @staticmethod
    def simplify(item: dict) -> dict:
        meta = item['cve']['CVE_data_meta']
        desc_data = item['cve']['description']['description_data']
        description = desc_data[0]['value'] if desc_data else ''
        published = item.get('publishedDate') or item.get('Published')
        # Determine score
        score = None
        metric = item.get('impact', {}).get('baseMetricV3', {})
        score = metric.get('cvssV3', {}).get('baseScore') if 'cvssV3' in metric else item.get('cvss', None)
        return {
            'id': meta.get('ID'),
            'description': description,
            'publishedDate': published,
            'lastModifiedDate': item.get('lastModifiedDate') or item.get('Modified'),
            'cvssScore': score
        }
