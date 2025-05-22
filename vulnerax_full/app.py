import os
import requests
from flask import Flask, jsonify, send_file, request, render_template
from flask_caching import Cache
from config import DevelopmentConfig, ProductionConfig
from cve_service import CVEService
from report_generator import PDFReport
from schemas import CVESchema
from stripe_integration import stripe_bp
from datetime import datetime

def create_app():
    app = Flask(__name__, template_folder='templates')
    env = os.getenv('FLASK_ENV', 'production')
    app.config.from_object(DevelopmentConfig if env == 'development' else ProductionConfig)
    Cache(app)
    app.register_blueprint(stripe_bp)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/api/cves', methods=['GET'])
    def get_cves():
        days = request.args.get('days', default=1, type=int)
        limit = request.args.get('limit', default=50, type=int)
        try:
            raw = CVEService.fetch_recent_cves(days, limit)
            simple = [CVEService.simplify(i) for i in raw]
            data = CVESchema(many=True).dump(simple)
            return jsonify({'count': len(data), 'cves': data})
        except requests.RequestException as e:
            return jsonify({'error': str(e)}), 503

    @app.route('/api/report', methods=['GET'])
    def get_report():
        days = request.args.get('days', default=1, type=int)
        limit = request.args.get('limit', default=50, type=int)
        raw = CVEService.fetch_recent_cves(days, limit)
        simple = [CVEService.simplify(i) for i in raw]
        filename = f"vulnerax_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.pdf"
        path = PDFReport.generate(simple, filename)
        return send_file(path, as_attachment=True)

    return app

if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
