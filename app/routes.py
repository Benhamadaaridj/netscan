
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, send_file
from app.models import db, User, Scan, Port, Alert, ScanComparison, ScheduledScan, UserEmailSettings
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from app.scanner import create_scan, compare_scans, create_range_scan
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
    
    
    print(f"Scan ID: {scan_id}, Total ports found: {len(ports)}")
    for port in ports[:5]:
        print(f"Port {port.port_number} - Host IP: {port.host_ip}")
    
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
    is_range = data.get('is_range', False)
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    # Check if it's a range scan
    if is_range:
        result = create_range_scan(user_id, target, scan_type)
    else:
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
    
@scanner_bp.route('/alerts/unread', methods=['GET'])
@login_required
def api_get_unread_alerts():
    user_id = session['user_id']
    alerts = Alert.query.filter_by(user_id=user_id, is_read=False).order_by(Alert.created_at.desc()).limit(50).all()
    
    return jsonify({
        'count': len(alerts),
        'notifications': [{
            'id': a.id,
            'alert_type': a.alert_type,
            'message': a.message,
            'severity': a.severity,
            'created_at': a.created_at.isoformat(),
            'is_read': a.is_read
        } for a in alerts]
    })

@scanner_bp.route('/alerts/mark-all-read', methods=['POST'])
@login_required
def api_mark_all_alerts_read():
    user_id = session['user_id']
    Alert.query.filter_by(user_id=user_id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'success': True})


# ========== Scheduler Routes ==========

@dashboard_bp.route('/scheduler')
@login_required
def scheduler():
    user_id = session['user_id']
    scheduled_scans = ScheduledScan.query.filter_by(user_id=user_id, is_active=True).all()
    return render_template('scheduler.html', scheduled_scans=scheduled_scans)

@scanner_bp.route('/scheduled-scans', methods=['GET'])
@login_required
def api_get_scheduled_scans():
    user_id = session['user_id']
    scans = ScheduledScan.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': s.id,
        'target': s.target,
        'scan_type': s.scan_type,
        'interval': s.interval,
        'interval_minutes': s.interval_minutes,
        'is_active': s.is_active,
        'last_run': s.last_run.isoformat() if s.last_run else None,
        'next_run': s.next_run.isoformat() if s.next_run else None
    } for s in scans])

@scanner_bp.route('/scheduled-scans', methods=['POST'])
@login_required
def api_create_scheduled_scan():
    user_id = session['user_id']
    data = request.get_json()
    
    target = data.get('target')
    scan_type = data.get('scan_type', 'quick')
    interval = data.get('interval', 'hourly')
    
    
    existing = ScheduledScan.query.filter_by(user_id=user_id, target=target).first()
    if existing:
        return jsonify({'error': 'A scheduled scan for this target already exists'}), 400
    
    
    # Convert interval to minutes
    interval_map = {
        'minute': 1,
        '5minutes': 5,
        '15minutes': 15,
        '30minutes': 30,
        'hourly': 60,
        'daily': 1440,
        'weekly': 10080
    }
    
    interval_minutes = interval_map.get(interval, 60)
    
    from datetime import timedelta
    scheduled = ScheduledScan(
        user_id=user_id,
        target=target,
        scan_type=scan_type,
        interval=interval,
        interval_minutes=interval_minutes,
        next_run=datetime.utcnow() + timedelta(minutes=interval_minutes)
    )
    db.session.add(scheduled)
    db.session.commit()
    
    return jsonify({'success': True, 'id': scheduled.id})

@scanner_bp.route('/scheduled-scans/<int:scan_id>', methods=['DELETE'])
@login_required
def api_delete_scheduled_scan(scan_id):
    user_id = session['user_id']
    scheduled = ScheduledScan.query.get(scan_id)
    if not scheduled or scheduled.user_id != user_id:
        return jsonify({'error': 'Not found'}), 404
    
    db.session.delete(scheduled)
    db.session.commit()
    return jsonify({'success': True})

@scanner_bp.route('/scheduled-scans/<int:scan_id>/toggle', methods=['POST'])
@login_required
def api_toggle_scheduled_scan(scan_id):
    user_id = session['user_id']
    scheduled = ScheduledScan.query.get(scan_id)
    if not scheduled or scheduled.user_id != user_id:
        return jsonify({'error': 'Not found'}), 404
    
    scheduled.is_active = not scheduled.is_active
    db.session.commit()
    return jsonify({'success': True, 'is_active': scheduled.is_active})

# ========== Email Settings Routes ==========

@dashboard_bp.route('/email-settings')
@login_required
def email_settings():
    user_id = session['user_id']
    settings = UserEmailSettings.query.filter_by(user_id=user_id).first()
    return render_template('email_settings.html', settings=settings)

@scanner_bp.route('/email-settings', methods=['GET'])
@login_required
def api_get_email_settings():
    user_id = session['user_id']
    settings = UserEmailSettings.query.filter_by(user_id=user_id).first()
    if not settings:
        return jsonify({'email': '', 'enable_email_alerts': False, 'notify_critical_only': True})
    return jsonify({
        'email': settings.email,
        'enable_email_alerts': settings.enable_email_alerts,
        'notify_critical_only': settings.notify_critical_only
    })

@scanner_bp.route('/email-settings', methods=['POST'])
@login_required
def api_save_email_settings():
    user_id = session['user_id']
    data = request.get_json()
    
    settings = UserEmailSettings.query.filter_by(user_id=user_id).first()
    if not settings:
        settings = UserEmailSettings(user_id=user_id)
        db.session.add(settings)
    
    settings.email = data.get('email', '')
    settings.enable_email_alerts = data.get('enable_email_alerts', False)
    settings.notify_critical_only = data.get('notify_critical_only', True)
    db.session.commit()
    
    return jsonify({'success': True})

@scanner_bp.route('/test-email', methods=['POST'])
@login_required
def api_test_email():
    user_id = session['user_id']
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    from app.email_sender import send_test_email
    result = send_test_email(user_id, email)
    
    if result.get('success'):
        return jsonify({'success': True, 'message': 'Test email sent!'})
    else:
        return jsonify({'error': result.get('error', 'Failed to send email')}), 500
    

# Change Password Routes 

@dashboard_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        user_id = session['user_id']
        user = User.query.get(user_id)
        
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Vérifier le mot de passe actuel
        if not check_password_hash(user.password_hash, current_password):
            return render_template('change_password.html', error='Current password is incorrect')
        
        # Vérifier que les nouveaux mots de passe correspondent
        if new_password != confirm_password:
            return render_template('change_password.html', error='New passwords do not match')
        
        # Vérifier que le nouveau mot de passe n'est pas vide
        if len(new_password) < 4:
            return render_template('change_password.html', error='Password must be at least 4 characters')
        
        # Changer le mot de passe
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return render_template('change_password.html', success='Password changed successfully!')
    
    return render_template('change_password.html')


    # ========== Auto Discover Routes ==========
import socket
import requests

def get_public_ip():
    """Get public IP address"""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text
    except:
        return None

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return '127.0.0.1'

@scanner_bp.route('/my-ip', methods=['GET'])
@login_required
def api_get_my_ip():
    user_id = session['user_id']
    
    return jsonify({
        'public_ip': get_public_ip(),
        'local_ip': get_local_ip()
    })