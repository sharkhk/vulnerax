import os
from flask import Flask, jsonify, render_template, request
from flask_caching import Cache
from config import DevelopmentConfig, ProductionConfig
from cve_service import CVEService


def create_app():
    app = Flask(__name__, template_folder='templates')
    env = os.getenv('FLASK_ENV', 'production')
    app.config.from_object(DevelopmentConfig if env == 'development' else ProductionConfig)
    Cache(app)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/api/cves')
    def get_cves():
        days = request.args.get('days', default=30, type=int)
        limit = request.args.get('limit', default=100, type=int)
        try:
            raw = CVEService.fetch_recent_cves(days, limit)
            simple = [CVEService.simplify(i) for i in raw]
            return jsonify({'count': len(simple), 'cves': simple})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return app

if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
