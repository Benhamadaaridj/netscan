from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from app.models import db, User, Scan, Port, Alert, ScanComparison
from app.scanner import create_scan, compare_scans
from datetime import datetime
import json
import os

# Create blueprints
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/')
scanner_bp = Blueprint('scanner', __name__, url_prefix='/api')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard.index'))
        
        return render_template('login_simple.html', error='Invalid credentials')
    
    return render_template('login_simple.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password:
            return render_template('register.html', error='Username and password required')
        
        if password != confirm_password:
            return render_template('register.html', error='Passwords do not match')
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username already exists')
        
        user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('dashboard.index'))
    
    return render_template('register.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

# Dashboard Routes
@dashboard_bp.route('/')
@login_required
def index():
    user_id = session['user_id']
    
    # Get user's scans
    scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.start_time.desc()).limit(10).all()
    
    # Get unread alerts
    unread_alerts = Alert.query.filter_by(user_id=user_id, is_read=False).all()
    
    # Get statistics
    total_scans = Scan.query.filter_by(user_id=user_id).count()
    critical_alerts = Alert.query.filter_by(user_id=user_id, severity='critical').count()
    
    return render_template('dashboard.html', 
                         scans=scans, 
                         unread_alerts=unread_alerts,
                         total_scans=total_scans,
                         critical_alerts=critical_alerts)

@dashboard_bp.route('/scans')
@login_required
def scans():
    user_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    
    scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.start_time.desc()).paginate(page=page, per_page=20)
    
    return render_template('scans.html', scans=scans)

@dashboard_bp.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    user_id = session['user_id']
    scan = Scan.query.get(scan_id)
    
    if not scan or scan.user_id != user_id:
        return "Not found", 404
    
    ports = Port.query.filter_by(scan_id=scan_id).order_by(Port.port_number).all()
    
    return render_template('scan_detail.html', scan=scan, ports=ports)

@dashboard_bp.route('/alerts')
@login_required
def alerts():
    user_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    
    alerts = Alert.query.filter_by(user_id=user_id).order_by(Alert.created_at.desc()).paginate(page=page, per_page=20)
    
    return render_template('alerts.html', alerts=alerts)

@dashboard_bp.route('/comparisons')
@login_required
def comparisons():
    user_id = session['user_id']
    page = request.args.get('page', 1, type=int)
    
    comparisons = ScanComparison.query.filter_by(user_id=user_id).order_by(ScanComparison.created_at.desc()).paginate(page=page, per_page=20)
    scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.start_time.desc()).all()
    
    return render_template('comparisons.html', comparisons=comparisons, scans=scans)

# Scanner API Routes
@scanner_bp.route('/scan', methods=['POST'])
@login_required
def api_scan():
    user_id = session['user_id']
    data = request.get_json()
    
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    result = create_scan(user_id, target, scan_type)
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result)

@scanner_bp.route('/scan/<int:scan_id>/results', methods=['GET'])
@login_required
def api_scan_results(scan_id):
    user_id = session['user_id']
    scan = Scan.query.get(scan_id)
    
    if not scan or scan.user_id != user_id:
        return jsonify({'error': 'Not found'}), 404
    
    ports = Port.query.filter_by(scan_id=scan_id).all()
    
    return jsonify({
        'scan': {
            'id': scan.id,
            'target': scan.target,
            'status': scan.status,
            'start_time': scan.start_time.isoformat(),
            'end_time': scan.end_time.isoformat() if scan.end_time else None,
            'duration': scan.duration
        },
        'ports': [p.to_dict() for p in ports]
    })

@scanner_bp.route('/compare', methods=['POST'])
@login_required
def api_compare():
    user_id = session['user_id']
    data = request.get_json()
    
    scan1_id = data.get('scan1_id')
    scan2_id = data.get('scan2_id')
    
    if not scan1_id or not scan2_id:
        return jsonify({'error': 'Both scan IDs required'}), 400
    
    result = compare_scans(scan1_id, scan2_id, user_id)
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result)

@scanner_bp.route('/alerts/mark-read/<int:alert_id>', methods=['POST'])
@login_required
def api_mark_alert_read(alert_id):
    user_id = session['user_id']
    alert = Alert.query.get(alert_id)
    
    if not alert or alert.user_id != user_id:
        return jsonify({'error': 'Not found'}), 404
    
    alert.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

@scanner_bp.route('/scan/<int:scan_id>/export-pdf', methods=['GET'])
@login_required
def api_export_pdf(scan_id):
    user_id = session['user_id']
    scan = Scan.query.get(scan_id)
    
    if not scan or scan.user_id != user_id:
        return jsonify({'error': 'Not found'}), 404
    
    from app.pdf_exporter import export_scan_to_pdf
    
    try:
        pdf_filename = export_scan_to_pdf(scan)
        
        # المسار الصحيح لمجلد downloads
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pdf_path = os.path.join(base_dir, 'downloads', pdf_filename)
        
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=pdf_filename,
            mimetype='application/pdf'
        )
    except Exception as e:
        print(f"PDF Export Error: {str(e)}")
        return jsonify({'error': str(e)}), 500