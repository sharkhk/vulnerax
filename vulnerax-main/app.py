import os
from flask import Flask, jsonify, send_file
from flask_restful import Api, Resource, reqparse
from flask_caching import Cache
from config import DevelopmentConfig, ProductionConfig
from cve_service import CVEService
from report_generator import PDFReport
from schemas import CVEQuerySchema, CVESchema
from marshmallow import ValidationError
from datetime import datetime

def create_app():
    app = Flask(__name__)
    env = os.getenv('FLASK_ENV', 'production')
    app.config.from_object(DevelopmentConfig if env == 'development' else ProductionConfig)

    cache = Cache(app)
    api = Api(app)

    parser = reqparse.RequestParser()
    parser.add_argument('days', type=int, default=1, help='Days range')
    parser.add_argument('limit', type=int, default=50, help='Max CVEs to return')

    class CVEList(Resource):
        @cache.cached(query_string=True)
        def get(self):
            args = parser.parse_args()
            try:
                raw = CVEService.fetch_recent_cves(args['days'], args['limit'])
                simplified = [CVEService.simplify(i) for i in raw]
                result = CVESchema(many=True).dump(simplified)
                return jsonify({ 'count': len(result), 'cves': result })
            except requests.RequestException as e:
                return { 'error': str(e) }, 503

    class CVEReport(Resource):
        def get(self):
            args = parser.parse_args()
            raw = CVEService.fetch_recent_cves(args['days'], args['limit'])
            simplified = [CVEService.simplify(i) for i in raw]
            filename = f"vulnerax_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"
            path = PDFReport.generate(simplified, filename)
            return send_file(path, as_attachment=True)

    api.add_resource(CVEList, '/api/cves')
    api.add_resource(CVEReport, '/api/report')

    return app

if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
