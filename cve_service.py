import requests
from datetime import datetime, timedelta
from flask import current_app

class CVEService:
    @staticmethod
    def fetch_recent_cves(limit: int):
        """
        Fetch latest CVEs from NVD API using 30-day window.
        """
        end = datetime.utcnow().isoformat() + 'Z'
        start = (datetime.utcnow() - timedelta(days=30)).isoformat() + 'Z'
        params = {
            'pubStartDate': start,
            'pubEndDate': end,
            'resultsPerPage': limit
        }
        headers = {
            'User-Agent': 'VulneraX-Agentic/1.0',
            'apiKey': current_app.config.get('NVD_API_KEY')
        }
        resp = requests.get(
            current_app.config.get('NVD_API_URL', 'https://services.nvd.nist.gov/rest/json/cves/1.0'),
            params=params,
            headers=headers,
            timeout=10
        )
        resp.raise_for_status()
        items = resp.json().get('result', {}).get('CVE_Items', [])
        return items

    @staticmethod
    def fetch_cve(cve_id: str):
        """
        Fetch details for specific CVE/GHSA. Only CVE via NVD now.
        """
        url = f"{current_app.config.get('NVD_API_URL','https://services.nvd.nist.gov/rest/json/cves/1.0')}?cveId={cve_id}"
        headers = {'User-Agent': 'VulneraX-Agentic/1.0',
                   'apiKey': current_app.config.get('NVD_API_KEY')}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        items = resp.json().get('result', {}).get('CVE_Items', [])
        return items[0] if items else {}

    @staticmethod
    def simplify(item: dict) -> dict:
        meta = item.get('cve', {}).get('CVE_data_meta', {})
        desc_data = item.get('cve', {}).get('description', {}).get('description_data', [])
        description = desc_data[0].get('value') if desc_data else ''
        published = item.get('publishedDate', '')
        modified = item.get('lastModifiedDate', '')
        impact = item.get('impact', {})
        metric = impact.get('baseMetricV3', impact.get('baseMetricV2', {}))
        score = None
        if 'cvssV3' in metric:
            score = metric['cvssV3'].get('baseScore')
        else:
            score = metric.get('baseScore')
        return {
            'id': meta.get('ID'),
            'description': description,
            'publishedDate': published,
            'lastModifiedDate': modified,
            'cvssScore': score
        }
