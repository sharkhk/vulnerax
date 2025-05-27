import requests
from datetime import datetime, timedelta
from flask import current_app

class CVEService:
    @staticmethod
    def fetch_recent_cves(days: int, limit: int):
        end = datetime.utcnow().isoformat() + 'Z'
        start = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'
        params = {
            'pubStartDate': start,
            'pubEndDate': end,
            'resultsPerPage': limit
        }
        headers = {
            'User-Agent': 'VulneraX-Agentic/1.0'
        }
        # Pass api key as query parameter as required
        api_key = current_app.config.get('NVD_API_KEY')
        if api_key:
            params['apiKey'] = api_key
        api_key = current_app.config.get('NVD_API_KEY')
        if api_key:
            headers['apiKey'] = api_key
        resp = requests.get(
            current_app.config['NVD_API_URL'],
            params=params,
            headers=headers,
            timeout=10
        )
        resp.raise_for_status()
        return resp.json().get('result', {}).get('CVE_Items', [])

    @staticmethod
    def simplify(item: dict) -> dict:
        meta = item['cve']['CVE_data_meta']
        desc_data = item['cve']['description']['description_data']
        description = desc_data[0]['value'] if desc_data else ''
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
            'publishedDate': item.get('publishedDate'),
            'lastModifiedDate': item.get('lastModifiedDate'),
            'cvssScore': score
        }
