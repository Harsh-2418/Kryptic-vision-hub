from flask import Flask, render_template
from config import Config
from database.db import init_db
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.scanner import scanner_bp
from routes.contact import contact_bp
from routes.sql_routes import sql_bp
from routes.xss_routes import xss_bp
from routes.wifi_routes import wifi_bp
from routes.evil_twin_routes import evil_twin_bp
from routes.profile import profile_bp
from routes.settings import settings_bp
from routes.admin import admin_bp
from routes.logs import logs_bp
from routes.reports import reports_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize SQLite Database & tables
    with app.app_context():
        init_db()

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(contact_bp)
    app.register_blueprint(sql_bp)
    app.register_blueprint(xss_bp)
    app.register_blueprint(wifi_bp)
    app.register_blueprint(evil_twin_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(reports_bp)

    # Root Home Route
    @app.route('/')
    def index():
        return render_template('index.html')

    # Help Center Route
    @app.route('/help')
    def help_center():
        return render_template('help.html')

    # About Project Route
    @app.route('/about_project')
    def about_project():
        return render_template('about_project.html')

    # Custom 404 Error Handler
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
