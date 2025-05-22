import os
import requests
from flask import Flask, jsonify, send_file, request
from flask_caching import Cache
from config import DevelopmentConfig, ProductionConfig
from cve_service import CVEService
from report_generator import PDFReport
from schemas import CVESchema
from datetime import datetime


def create_app():
    app = Flask(__name__)
    env = os.getenv('FLASK_ENV', 'production')
    app.config.from_object(DevelopmentConfig if env == 'development' else ProductionConfig)

    cache = Cache(app)

    @app.route('/api/cves', methods=['GET'])
    @cache.cached(query_string=True)
    def get_cves():
        days = request.args.get('days', default=1, type=int)
        limit = request.args.get('limit', default=50, type=int)
        try:
            raw = CVEService.fetch_recent_cves(days, limit)
            simplified = [CVEService.simplify(i) for i in raw]
            result = CVESchema(many=True).dump(simplified)
            return jsonify({'count': len(result), 'cves': result})
        except requests.RequestException as e:
            return jsonify({'error': str(e)}), 503

    @app.route('/api/report', methods=['GET'])
    def get_report():
        days = request.args.get('days', default=1, type=int)
        limit = request.args.get('limit', default=50, type=int)
        raw = CVEService.fetch_recent_cves(days, limit)
        simplified = [CVEService.simplify(i) for i in raw]
        filename = f"vulnerax_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"
        path = PDFReport.generate(simplified, filename)
        return send_file(path, as_attachment=True)

    return app


if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
