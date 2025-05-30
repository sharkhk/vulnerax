import requests
from datetime import datetime, timedelta
from flask import current_app

class CVEService:
    @staticmethod
    def fetch_recent_cves(limit: int):
        """
        Fetch latest CVEs from CIRCL public API only.
        """
        url = f"{current_app.config['CIRCL_API_URL']}/last"
        headers = {'User-Agent': 'VulneraX-Agentic/1.0'}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # Map CIRCL entries directly
        items = []
        for entry in data[:limit]:
            items.append({
                'cve': {'CVE_data_meta': {'ID': entry.get('id')}},
                'description': {'description_data': [{'value': entry.get('summary', '')}]},
                'publishedDate': entry.get('Published'),
                'lastModifiedDate': entry.get('Modified'),
                'impact': {'baseMetricV3': {'cvssV3': {'baseScore': entry.get('cvss')}}}
            })
        return items

    @staticmethod
    def fetch_cve(cve_id: str):
        """
        Fetch details for a specific CVE/GHSA ID using CIRCL or GitHub.
        """
        if cve_id.upper().startswith('CVE-'):
            url = f"{current_app.config['CIRCL_API_URL']}/cve/{cve_id}"
        else:
            url = f"https://api.github.com/advisories/{cve_id}"
        headers = {'User-Agent': 'VulneraX-Agentic/1.0'}
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        # If CIRCL returns dict, wrap into list
        if isinstance(data, dict) and 'CVE_data_meta' in data.get('cve', {}):
            return data
        return data

    @staticmethod
    def simplify(item: dict) -> dict:
        meta = item.get('cve', {}).get('CVE_data_meta', {})
        desc_data = item.get('cve', {}).get('description', {}).get('description_data', [])
        description = desc_data[0].get('value') if desc_data else ''
        published = item.get('publishedDate') or item.get('Published') or ''
        modified = item.get('lastModifiedDate') or item.get('Modified') or ''
        impact = item.get('impact', {})
        metric = impact.get('baseMetricV3', impact.get('baseMetricV2', {}))
        score = None
        if 'cvssV3' in metric:
            score = metric['cvssV3'].get('baseScore')
        else:
            score = metric.get('baseScore') or item.get('cvss')
        return {
            'id': meta.get('ID') or item.get('ghsaId') or 'Unknown ID',
            'description': description,
            'publishedDate': published,
            'lastModifiedDate': modified,
            'cvssScore': score
        }
