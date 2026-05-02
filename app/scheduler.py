import threading
import time
from datetime import datetime, timedelta
from flask import current_app
from app import db
from app.models import ScheduledScan, Scan, Port, Alert
from app.scanner import create_scan, create_range_scan

def compare_and_alert(user_id, old_scan, new_scan, target):
    """Compare scans and create alerts for changes"""
    old_ports = {(p.port_number, p.protocol): p for p in old_scan.ports}
    new_ports = {(p.port_number, p.protocol): p for p in new_scan.ports}
    
    # New ports
    for key, port in new_ports.items():
        if key not in old_ports:
            alert = Alert(
                user_id=user_id,
                scan_id=new_scan.id,
                alert_type='new_port_detected',
                message=f'New port {port.port_number}/{port.protocol} ({port.service or "unknown"}) opened on {target}',
                severity='high'
            )
            db.session.add(alert)
    
    # Closed ports
    for key, port in old_ports.items():
        if key not in new_ports:
            alert = Alert(
                user_id=user_id,
                scan_id=new_scan.id,
                alert_type='port_closed',
                message=f'Port {port.port_number}/{port.protocol} ({port.service or "unknown"}) closed on {target}',
                severity='medium'
            )
            db.session.add(alert)
    
    # Service changes
    for key, new_port in new_ports.items():
        if key in old_ports:
            old_port = old_ports[key]
            if old_port.service != new_port.service:
                alert = Alert(
                    user_id=user_id,
                    scan_id=new_scan.id,
                    alert_type='service_changed',
                    message=f'Service on port {new_port.port_number}/{new_port.protocol} changed from {old_port.service or "unknown"} to {new_port.service or "unknown"} on {target}',
                    severity='medium'
                )
                db.session.add(alert)
    
    db.session.commit()
    
    # Send email for critical ports
    critical_ports = [p for p in new_scan.ports if p.risk_level == 'critical']
    if critical_ports:
        try:
            from app.email_sender import send_critical_alert_email
            send_critical_alert_email(user_id, target, critical_ports)
            print(f"📧 Email sent for {len(critical_ports)} critical ports on {target}")
        except Exception as e:
            print(f"❌ Email error: {e}")

def scheduler_loop(app):
    """Main scheduler loop running in background"""
    print("🔄 Scheduler loop started")
    
    while True:
        try:
            with app.app_context():
                now = datetime.utcnow()
                print(f"⏰ Checking scheduled scans at {now}")
                
                # Get scans that need to run
                scheduled_scans = ScheduledScan.query.filter(
                    ScheduledScan.is_active == True,
                    ScheduledScan.next_run <= now
                ).all()
                
                if scheduled_scans:
                    print(f"📋 Found {len(scheduled_scans)} scans to run")
                
                for scheduled in scheduled_scans:
                    print(f"▶️ Running scheduled scan for {scheduled.target}")
                    
                    # Get last scan for comparison
                    last_scan = Scan.query.filter_by(
                        user_id=scheduled.user_id,
                        target=scheduled.target
                    ).order_by(Scan.start_time.desc()).first()
                    
                    # Run the scan
                    is_range = '-' in scheduled.target or '/' in scheduled.target
                    if is_range:
                        result = create_range_scan(scheduled.user_id, scheduled.target, scheduled.scan_type)
                    else:
                        result = create_scan(scheduled.user_id, scheduled.target, scheduled.scan_type)
                    
                    print(f"📊 Scan result: {result}")
                    
                    # Compare with previous scan and create alerts if changes detected
                    if result.get('success') and last_scan and result.get('scan_id'):
                        new_scan = Scan.query.get(result['scan_id'])
                        if new_scan:
                            compare_and_alert(scheduled.user_id, last_scan, new_scan, scheduled.target)
                    elif result.get('success') and result.get('scan_id'):
                        # First scan ever - just check for critical ports
                        new_scan = Scan.query.get(result['scan_id'])
                        if new_scan:
                            critical_ports = [p for p in new_scan.ports if p.risk_level == 'critical']
                            if critical_ports:
                                try:
                                    from app.email_sender import send_critical_alert_email
                                    send_critical_alert_email(scheduled.user_id, scheduled.target, critical_ports)
                                    print(f"📧 Email sent for {len(critical_ports)} critical ports on {scheduled.target}")
                                except Exception as e:
                                    print(f"❌ Email error: {e}")
                    
                    # Update next run time
                    scheduled.last_run = now
                    scheduled.next_run = now + timedelta(minutes=scheduled.interval_minutes)
                    db.session.commit()
                    
                    print(f"✅ Completed scheduled scan for {scheduled.target}")
                    print(f"⏩ Next run at: {scheduled.next_run}")
                
        except Exception as e:
            print(f"❌ Scheduler error: {e}")
            import traceback
            traceback.print_exc()
        
        time.sleep(30)  # Check every 30 seconds

def start_scheduler(app):
    """Start the scheduler in a background thread"""
    print("🚀 Starting scheduler...")
    thread = threading.Thread(target=scheduler_loop, args=(app,), daemon=True)
    thread.start()
    print("✅ Scheduler started successfully")