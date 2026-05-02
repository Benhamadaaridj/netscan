from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app.models import db
import os

def create_app():
    # Initialize Flask app
    app = Flask(__name__, 
                template_folder='../templates',
                static_folder='../static')
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///network_scanner.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # ========== Email Configuration ==========
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'netscantest@gmail.com'
    app.config['MAIL_PASSWORD'] = 'qxhb bpsz jaas ahys'
    app.config['MAIL_DEFAULT_SENDER'] = 'netscantest@gmail.com'
    # ==========================================
    
    # Initialize database
    db.init_app(app)
    
    # Register blueprints
    from app.routes import auth_bp, dashboard_bp, scanner_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    
    # Create tables
    with app.app_context():
        db.create_all()
    
    
    return app