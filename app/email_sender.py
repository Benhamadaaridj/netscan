import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app
from app.models import User, UserEmailSettings

def send_email(to_email, subject, body_html):
    """Send email using SMTP"""
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = current_app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to_email
        
        # HTML content
        part = MIMEText(body_html, 'html')
        msg.attach(part)
        
        # Send email
        with smtplib.SMTP(current_app.config['MAIL_SERVER'], current_app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(current_app.config['MAIL_USERNAME'], current_app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        
        return {'success': True}
    except Exception as e:
        print(f"Email error: {e}")
        return {'error': str(e)}

def send_critical_alert_email(user_id, scan_target, critical_ports):
    """Send email alert for critical ports"""
    settings = UserEmailSettings.query.filter_by(user_id=user_id).first()
    
    if not settings or not settings.enable_email_alerts or not settings.email:
        return None
    
    
    
    subject = f"🔴 CRITICAL ALERT: {len(critical_ports)} unsafe ports found on {scan_target}"
    
    # Build HTML table for ports
    ports_html = ""
    for port in critical_ports:
        ports_html += f"""
        <tr style="border-bottom: 1px solid #ddd;">
            <td style="padding: 8px; background-color: #fff3f3;">{port.port_number}</td>
            <td style="padding: 8px;">{port.protocol.upper()}</td>
            <td style="padding: 8px;">{port.service or 'Unknown'}</td>
            <td style="padding: 8px; background-color: #ffebee;">
                <span style="background-color: #dc2626; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px;">CRITICAL</span>
            </td>
        </tr>
        """
    
    body_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f9fafb; padding: 20px; border-radius: 0 0 10px 10px; }}
            .critical-box {{ background: #fee2e2; border-left: 4px solid #dc2626; padding: 15px; margin: 20px 0; border-radius: 8px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
            th {{ background: #4f46e5; color: white; padding: 10px; text-align: left; }}
            td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
            .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔴 NetScan Critical Alert</h1>
            </div>
            <div class="content">
                <div class="critical-box">
                    <strong>⚠️ IMPORTANT:</strong> Critical ports detected on <strong>{scan_target}</strong>
                </div>
                
                <h3>📋 Detected Critical Ports:</h3>
                <table>
                    <thead>
                        <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Risk</th></tr>
                    </thead>
                    <tbody>
                        {ports_html}
                    </tbody>
                </table>
                
                <p>Please take immediate action to secure these ports!</p>
                <p><a href="http://localhost:5000/scan/{scan_target}" style="background: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 8px;">View Scan Details →</a></p>
            </div>
            <div class="footer">
                <p>NetScan - Advanced Network Port Monitoring System</p>
                <p>This is an automated alert. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(settings.email, subject, body_html)

def send_test_email(user_id, email):
    """Send a test email to verify configuration"""
    subject = "✅ NetScan Email Test - Configuration Successful"
    body_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9fafb; padding: 20px; border-radius: 0 0 10px 10px; text-align: center; }
            .success { background: #dcfce7; border-left: 4px solid #22c55e; padding: 15px; margin: 20px 0; border-radius: 8px; }
            .footer { text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>✅ NetScan Email Test</h1>
            </div>
            <div class="content">
                <div class="success">
                    <strong>🎉 Congratulations!</strong><br>
                    Your email configuration is working perfectly!
                </div>
                <p>You will now receive email alerts when critical ports are detected during scheduled scans.</p>
            </div>
            <div class="footer">
                <p>NetScan - Advanced Network Port Monitoring System</p>
            </div>
        </div>
    </body>
    </html>
    """
    return send_email(email, subject, body_html)

def send_port_changes_email(user_id, scan_target, new_ports, closed_ports, changed_services):
    """Send email for port changes"""
    settings = UserEmailSettings.query.filter_by(user_id=user_id).first()
    
    if not settings or not settings.enable_email_alerts or not settings.email:
        return None
    
    subject = f"📊 Network Changes Detected on {scan_target}"
    
    # Build changes summary
    changes_html = ""
    
    if new_ports:
        changes_html += "<h3>🆕 New Open Ports:</h3><ul>"
        for port in new_ports[:10]:
            changes_html += f"<li>Port {port.port_number}/{port.protocol} - {port.service or 'Unknown'}</li>"
        changes_html += "</ul>"
    
    if closed_ports:
        changes_html += "<h3>🔴 Closed Ports:</h3><ul>"
        for port in closed_ports[:10]:
            changes_html += f"<li>Port {port.port_number}/{port.protocol} - {port.service or 'Unknown'}</li>"
        changes_html += "</ul>"
    
    if changed_services:
        changes_html += "<h3>⚡ Service Changes:</h3><ul>"
        for change in changed_services[:10]:
            changes_html += f"<li>Port {change['port']}: {change['old_service']} → {change['new_service']}</li>"
        changes_html += "</ul>"
    
    body_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0; }}
            .content {{ background: #f9fafb; padding: 20px; border-radius: 0 0 10px 10px; }}
            .changes {{ background: #e0e7ff; padding: 15px; margin: 20px 0; border-radius: 8px; }}
            .footer {{ text-align: center; padding: 20px; color: #6b7280; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📊 Network Changes Detected</h1>
            </div>
            <div class="content">
                <p>Changes have been detected on <strong>{scan_target}</strong> during the scheduled scan.</p>
                <div class="changes">
                    {changes_html}
                </div>
                <p><a href="http://localhost:5000/scans" style="background: #4f46e5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 8px;">View All Scans →</a></p>
            </div>
            <div class="footer">
                <p>NetScan - Advanced Network Port Monitoring System</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(settings.email, subject, body_html)