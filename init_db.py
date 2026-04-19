#!/usr/bin/env python
"""Initialize database with demo user"""
from app import create_app
from app.models import db, User
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    # Create all tables
    db.create_all()
    
    # Check if demo user already exists
    if not User.query.filter_by(username='admin').first():
        # Create demo user
        admin = User(
            username='admin',
            password_hash=generate_password_hash('password')
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Database initialized with demo user")
        print("   Username: admin")
        print("   Password: password")
    else:
        print("✅ Database already initialized")
