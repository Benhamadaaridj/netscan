from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('Alert', backref='user', lazy=True, cascade='all, delete-orphan')

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(20), default='quick')  # quick or full
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, nullable=True)  # in seconds
    notes = db.Column(db.Text, nullable=True)
    
    ports = db.relationship('Port', backref='scan', lazy=True, cascade='all, delete-orphan')

class Port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)  # tcp or udp
    state = db.Column(db.String(20), nullable=False)  # open, closed, filtered
    service = db.Column(db.String(100), nullable=True)
    version = db.Column(db.String(255), nullable=True)
    risk_level = db.Column(db.String(20), default='medium')  # critical, high, medium, low
    
    def to_dict(self):
        return {
            'port_number': self.port_number,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service,
            'version': self.version,
            'risk_level': self.risk_level
        }

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=True)
    alert_type = db.Column(db.String(50), nullable=False)  # new_port, port_closed, service_change
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='medium')  # critical, high, medium, low
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    scan = db.relationship('Scan', backref='alerts')

class ScanComparison(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    previous_scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    current_scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    new_ports = db.Column(db.JSON)  # JSON array of new ports
    closed_ports = db.Column(db.JSON)  # JSON array of closed ports
    modified_services = db.Column(db.JSON)  # JSON array of service changes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
