import nmap
import re
import os
from datetime import datetime
import json
from app.models import db, Port, Scan, Alert, ScanComparison

# ========== إضافة حل مشكلة PATH ==========
# تحديد مسار Nmap مباشرة
NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
]

# البحث عن Nmap وإضافته إلى PATH
nmap_found = False
for path in NMAP_PATHS:
    if os.path.exists(path):
        if path.endswith('nmap.exe'):
            nmap_dir = os.path.dirname(path)
        else:
            nmap_dir = path
        os.environ['PATH'] = nmap_dir + os.pathsep + os.environ.get('PATH', '')
        nmap_found = True
        print(f"✅ Found Nmap at: {nmap_dir}")
        break

if not nmap_found:
    print("⚠️ Nmap not found in standard locations. Make sure Nmap is installed.")
# ========================================

PORT_RISK_MAPPING = {
    20: 'high', 21: 'high', 22: 'medium', 23: 'critical',
    25: 'medium', 53: 'low', 80: 'low', 110: 'medium',
    143: 'medium', 389: 'medium', 443: 'low', 445: 'critical',
    3306: 'critical', 3389: 'critical', 5432: 'critical',
    5900: 'high', 8080: 'low', 8443: 'low'
}

SERVICE_VERSIONS = {
    'ssh': 'OpenSSH',
    'http': 'Apache/Nginx',
    'https': 'Apache/Nginx',
    'mysql': 'MySQL/MariaDB',
    'postgresql': 'PostgreSQL',
    'rdp': 'Windows RDP',
    'smb': 'Samba/Windows',
}

class NetworkScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            print("✅ Nmap PortScanner initialized successfully")
        except Exception as e:
            print(f"❌ Error initializing Nmap: {e}")
            raise
    
    def get_risk_level(self, port_number, state):
        """Determine risk level based on port number and state"""
        if state != 'open':
            return 'low'
        return PORT_RISK_MAPPING.get(port_number, 'medium')
    
    def sanitize_nmap_output(self, output):
        """Sanitize nmap output to prevent injection"""
        if not output:
            return None
        # Remove special characters and limit length
        sanitized = re.sub(r'[^a-zA-Z0-9\s\.\-/:]', '', output)
        return sanitized[:255] if sanitized else None
    
    def scan_ports(self, target, scan_type='quick'):
        """
        Perform port scan on target
        scan_type: 'quick' (top 100 ports) or 'full' (all ports)
        """
        try:
            # Validate target IP/hostname
            if not self._validate_target(target):
                return {'error': 'Invalid target format'}
            
            # Set nmap arguments based on scan type
            if scan_type == 'quick':
                arguments = '-Pn -sS --top-ports 100 -T4'
            else:
                arguments = '-Pn -sS --top-ports 1000 -T4'
            
            print(f"🔍 Scanning {target} with arguments: {arguments}")
            self.nm.scan(hosts=target, arguments=arguments)
            
            ports_data = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port].get('name', '')
                        
                        ports_data.append({
                            'port': port,
                            'protocol': proto,
                            'state': state,
                            'service': self.sanitize_nmap_output(service),
                            'version': None,
                            'risk_level': self.get_risk_level(port, state)
                        })
            
            return {
                'success': True,
                'target': target,
                'ports': ports_data
            }
        except Exception as e:
            print(f"❌ Scan error: {e}")
            return {'error': str(e)}
    
    def _validate_target(self, target):
        """Validate target IP address or hostname"""
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d+)?$'
        hostname_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
        
        if re.match(ip_pattern, target) or re.match(hostname_pattern, target.lower()):
            return True
        return False

def create_scan(user_id, target, scan_type='quick'):
    """Create and execute a new scan"""
    try:
        scanner = NetworkScanner()
        start_time = datetime.utcnow()
        
        # Create scan record
        scan = Scan(user_id=user_id, target=target, scan_type=scan_type, status='running')
        db.session.add(scan)
        db.session.commit()
        
        # Run scan
        result = scanner.scan_ports(target, scan_type)
        
        if 'error' in result:
            scan.status = 'failed'
            db.session.commit()
            return {'error': result['error']}
        
        # Store port data
        for port_data in result['ports']:
            port = Port(
                scan_id=scan.id,
                port_number=port_data['port'],
                protocol=port_data['protocol'],
                state=port_data['state'],
                service=port_data['service'],
                version=port_data['version'],
                risk_level=port_data['risk_level']
            )
            db.session.add(port)
        
        # Update scan
        end_time = datetime.utcnow()
        scan.status = 'completed'
        scan.end_time = end_time
        scan.duration = (end_time - start_time).total_seconds()
        db.session.commit()
        
        # Generate alerts for critical ports
        generate_alerts(scan)
        
        return {'success': True, 'scan_id': scan.id}
    except Exception as e:
        if 'scan' in locals():
            scan.status = 'failed'
            db.session.commit()
        return {'error': str(e)}

def generate_alerts(scan):
    """Generate alerts based on scan results"""
    critical_ports = Port.query.filter_by(scan_id=scan.id, risk_level='critical').all()
    
    for port in critical_ports:
        alert = Alert(
            user_id=scan.user_id,
            scan_id=scan.id,
            alert_type='critical_port_open',
            message=f'Critical port {port.port_number}/{port.protocol} ({port.service}) is open',
            severity='critical'
        )
        db.session.add(alert)
    
    db.session.commit()

def compare_scans(scan1_id, scan2_id, user_id):
    """Compare two scans and detect changes"""
    try:
        scan1 = Scan.query.get(scan1_id)
        scan2 = Scan.query.get(scan2_id)
        
        if not scan1 or not scan2 or scan1.user_id != user_id or scan2.user_id != user_id:
            return {'error': 'Invalid scans'}
        
        ports1 = {(p.port_number, p.protocol): p for p in scan1.ports}
        ports2 = {(p.port_number, p.protocol): p for p in scan2.ports}
        
        new_ports = []
        closed_ports = []
        modified_services = []
        
        # Find new ports
        for key, port in ports2.items():
            if key not in ports1:
                new_ports.append(port.to_dict())
            elif port.state != ports1[key].state:
                if port.state == 'open':
                    new_ports.append(port.to_dict())
                else:
                    closed_ports.append(ports1[key].to_dict())
            elif port.service != ports1[key].service:
                modified_services.append({
                    'port': port.port_number,
                    'old_service': ports1[key].service,
                    'new_service': port.service
                })
        
        # Find closed ports
        for key, port in ports1.items():
            if key not in ports2 or (key in ports2 and ports2[key].state == 'closed' and port.state == 'open'):
                if key not in ports2:
                    closed_ports.append(port.to_dict())
        
        comparison = ScanComparison(
            user_id=user_id,
            previous_scan_id=scan1_id,
            current_scan_id=scan2_id,
            new_ports=new_ports,
            closed_ports=closed_ports,
            modified_services=modified_services
        )
        db.session.add(comparison)
        db.session.commit()
        
        return {
            'success': True,
            'comparison_id': comparison.id,
            'new_ports': len(new_ports),
            'closed_ports': len(closed_ports),
            'modified_services': len(modified_services)
        }
    except Exception as e:
        return {'error': str(e)}