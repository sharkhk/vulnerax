import os
from flask import Flask, jsonify, render_template, request
from flask_caching import Cache
from config import DevelopmentConfig, ProductionConfig
from tasks import orchestrate_pipeline
from agent_manager import AgentManager
from stripe_integration import stripe_bp


def create_app():
    app = Flask(__name__, template_folder='templates')
    env = os.getenv('FLASK_ENV', 'production')
    app.config.from_object(DevelopmentConfig if env == 'development' else ProductionConfig)
    Cache(app)
    app.register_blueprint(stripe_bp)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/api/cves')
    def get_cves():
        days = request.args.get('days', default=30, type=int)
        limit = request.args.get('limit', default=100, type=int)
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        task_id = AgentManager.start_agent('coordinator', days, limit, token)
        return jsonify({'task_id': task_id})

    @app.route('/api/agent/status/<task_id>')
    def agent_status(task_id):
        status = AgentManager.status(task_id)
        return jsonify(status)

    @app.route('/api/agent/cancel/<task_id>', methods=['POST'])
    def agent_cancel(task_id):
        result = AgentManager.revoke(task_id)
        return jsonify(result)

    @app.route('/api/agent/start/<agent_name>', methods=['POST'])
    def agent_start(agent_name):
        data = request.get_json() or {}
        args = data.get('args', [])
        kwargs = data.get('kwargs', {})
        try:
            task_id = AgentManager.start_agent(agent_name, *args, **kwargs)
            return jsonify({'task_id': task_id})
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

    return app

if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
