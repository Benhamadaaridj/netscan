from fpdf import FPDF
from datetime import datetime
import os

class ScanReport(FPDF):
    def __init__(self):
        super().__init__()
        self.WIDTH = 210
        self.HEIGHT = 297
    
    def header(self):
        self.set_font('Arial', 'B', 20)
        self.set_text_color(31, 78, 121)
        self.cell(0, 10, 'Network Port Scan Report', 0, 1, 'C')
        self.set_font('Arial', '', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(5)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
    
    def add_section_title(self, title):
        self.set_font('Arial', 'B', 14)
        self.set_text_color(31, 78, 121)
        self.cell(0, 10, title, 0, 1)
        self.set_text_color(0, 0, 0)
        self.ln(2)
    
    def add_scan_summary(self, scan):
        self.add_section_title('Scan Summary')
        self.set_font('Arial', '', 10)
        
        summary_data = [
            ('Target', scan.target),
            ('Scan Type', scan.scan_type.upper()),
            ('Status', scan.status),
            ('Start Time', scan.start_time.strftime("%Y-%m-%d %H:%M:%S")),
            ('Duration', f'{scan.duration:.2f}s' if scan.duration else 'N/A'),
        ]
        
        for label, value in summary_data:
            self.set_font('Arial', 'B', 10)
            self.cell(50, 7, label + ':')
            self.set_font('Arial', '', 10)
            self.cell(0, 7, str(value), 0, 1)
        
        self.ln(5)
    
    def add_ports_table(self, ports):
        self.add_section_title('Open Ports')
        self.set_font('Arial', '', 9)
        
        # Table header
        self.set_fill_color(31, 78, 121)
        self.set_text_color(255, 255, 255)
        self.set_font('Arial', 'B', 9)
        
        self.cell(25, 8, 'Port', 1, 0, 'C', True)
        self.cell(20, 8, 'Proto', 1, 0, 'C', True)
        self.cell(30, 8, 'Service', 1, 0, 'C', True)
        self.cell(40, 8, 'Risk', 1, 0, 'C', True)
        self.cell(45, 8, 'State', 1, 1, 'C', True)
        
        # Table rows
        self.set_text_color(0, 0, 0)
        self.set_font('Arial', '', 9)
        
        for port in ports:
            if port.state == 'open':
                self.cell(25, 7, str(port.port_number), 1)
                self.cell(20, 7, port.protocol, 1)
                self.cell(30, 7, port.service or 'Unknown', 1)
                self.cell(40, 7, port.risk_level.upper(), 1)
                self.cell(45, 7, port.state, 1, 1)
        
        self.ln(5)
    
    def add_risk_summary(self, ports):
        self.add_section_title('Risk Analysis')
        self.set_font('Arial', '', 10)
        
        risk_levels = {}
        for port in ports:
            if port.state == 'open':
                level = port.risk_level
                risk_levels[level] = risk_levels.get(level, 0) + 1
        
        for level in ['critical', 'high', 'medium', 'low']:
            count = risk_levels.get(level, 0)
            self.set_font('Arial', 'B', 10)
            self.cell(30, 7, f'{level.upper()}:')
            self.set_font('Arial', '', 10)
            self.cell(0, 7, str(count), 0, 1)

def export_scan_to_pdf(scan):
    """Export a scan to PDF"""
    from app.models import Port
    
    ports = Port.query.filter_by(scan_id=scan.id).all()
    
    pdf = ScanReport()
    pdf.add_page()
    
    pdf.add_scan_summary(scan)
    pdf.add_ports_table(ports)
    pdf.add_risk_summary(ports)
    
    # إنشاء مجلد downloads في المسار الصحيح
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    downloads_dir = os.path.join(base_dir, 'downloads')
    
    if not os.path.exists(downloads_dir):
        os.makedirs(downloads_dir)
    
    filename = f'scan_{scan.id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    filepath = os.path.join(downloads_dir, filename)
    
    pdf.output(filepath)
    
    return filename