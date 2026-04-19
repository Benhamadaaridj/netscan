# 🔍 NetScan - Smart Network Port Monitoring & Security Analysis System

A comprehensive Flask-based network port scanning and security monitoring application with real-time alerts, scan comparisons, and PDF reporting.

## Features

✨ **Core Capabilities:**
- **Port Scanning**: Quick (top 100 ports) and Full (top 1000 ports) scan modes
- **Service Detection**: Identify services running on open ports
- **Risk Analysis**: Automatic risk level assessment for discovered ports
- **Real-time Alerts**: Get notified about critical ports and security changes
- **Scan Comparison**: Track port changes between scans over time
- **PDF Reports**: Export comprehensive scan reports as PDF documents
- **User Management**: Secure authentication with session management
- **Responsive Dashboard**: Monitor network security from any device

## Tech Stack

- **Backend**: Flask 3.1.3
- **Database**: SQLite with SQLAlchemy ORM
- **Port Scanning**: python-nmap
- **Scheduling**: APScheduler (for automated scans)
- **PDF Generation**: FPDF2
- **Frontend**: Tailwind CSS + Jinja2 Templates
- **Security**: Werkzeug password hashing

## Installation & Setup

### Prerequisites
- Python 3.10+
- nmap installed on system (`sudo apt-get install nmap` on Linux)

### Quick Start

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Initialize database**
   ```bash
   python init_db.py
   ```

3. **Run the application**
   ```bash
   python run.py
   ```

4. **Access the app**
   - Open browser: `http://localhost:5000`
   - Login with: `admin` / `password`

## Project Structure

```
netscan/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── models.py            # Database models
│   ├── routes.py            # API and page routes
│   ├── scanner.py           # Port scanning logic
│   └── pdf_exporter.py      # PDF report generation
├── templates/
│   ├── base.html            # Base template
│   ├── login.html           # Login page
│   ├── register.html        # Registration page
│   ├── dashboard.html       # Main dashboard
│   ├── scan_detail.html     # Scan results detail
│   ├── scans.html           # All scans list
│   ├── alerts.html          # Security alerts
│   └── comparisons.html     # Scan comparisons
├── run.py                   # Application entry point
├── init_db.py               # Database initialization
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Database Schema

### Users
- Store user accounts with hashed passwords
- Track user's scans and alerts

### Scans
- Record of each port scan executed
- Target, type (quick/full), status, duration
- Linked port results and alerts

### Ports
- Individual port results from scans
- Port number, protocol, state, service, risk level

### Alerts
- Security alerts generated from scans
- Alert type, severity, read status

### Comparisons
- Historical scan comparisons
- Track new/closed ports and service changes

## Usage Guide

### 1. Running Scans
- Go to Dashboard
- Enter target (IP address or domain)
- Choose scan type:
  - **Quick**: Scans top 100 common ports (~30 seconds)
  - **Full**: Scans top 1000 ports (~5-10 minutes)
- Click "Start Scan"
- View real-time progress and results

### 2. Reviewing Results
- Click "View Details" on any completed scan
- See detailed port information:
  - Port number and protocol
  - Service name and version
  - Current state (open/closed/filtered)
  - Risk level (critical/high/medium/low)

### 3. Managing Alerts
- Check "Alerts" section for security findings
- Critical ports automatically generate alerts
- Mark alerts as read
- View alert history and patterns

### 4. Comparing Scans
- Use "Comparisons" section to track changes
- Select two scans to compare
- View:
  - New ports that opened
  - Ports that closed
  - Service version changes
  - Useful for monitoring infrastructure changes

### 5. Exporting Reports
- Open any completed scan
- Click "Export PDF" button
- Download professional scan report
- Includes summary, port list, and risk analysis

## Risk Level Assessment

Ports are automatically categorized by risk:

| Level | Examples | Action |
|-------|----------|--------|
| **Critical** | 23 (Telnet), 445 (SMB), 3306 (MySQL), 3389 (RDP) | Immediate review |
| **High** | 21 (FTP), 20 (FTP Data), 5900 (VNC) | Schedule review |
| **Medium** | 22 (SSH), 25 (SMTP), 143 (IMAP) | Monitor |
| **Low** | 80 (HTTP), 443 (HTTPS), 53 (DNS) | Baseline |

## API Endpoints

### Authentication
- `POST /auth/login` - Login user
- `POST /auth/register` - Register new account
- `GET /auth/logout` - Logout

### Scanning
- `POST /api/scan` - Start new scan
- `GET /api/scan/<id>/results` - Get scan results
- `POST /api/compare` - Compare two scans

### Alerts
- `POST /api/alerts/mark-read/<id>` - Mark alert as read
- `GET /api/scan/<id>/export-pdf` - Export scan to PDF

## Security Considerations

⚠️ **Important**: 
- Change default demo credentials before production use
- Use HTTPS in production
- Secure your SECRET_KEY environment variable
- Implement proper nmap privilege requirements (may need root for certain scans)
- Validate all user inputs (currently implemented)
- Use environment variables for sensitive config

## Future Enhancements

🚀 Planned features:
- Scheduled automated scans with APScheduler
- Email alerts for critical findings
- Vulnerability database integration (CVE lookup)
- Team collaboration features
- Advanced filtering and search
- IP range and subnet scanning
- OS fingerprinting
- Service version matching against known vulnerabilities

## Troubleshooting

### Nmap not found
```bash
# Linux
sudo apt-get install nmap

# macOS
brew install nmap

# Windows
Download from https://nmap.org/download.html
```

### Port already in use
```bash
# Use different port
python run.py --port 5001
```

### Database locked
- Delete `network_scanner.db` and reinitialize
- Check for running processes using the database

## License

This project is provided as-is for educational and authorized security testing purposes only.

## Support

For issues, questions, or feature requests, please check the application logs and ensure all dependencies are properly installed.

---

**Happy scanning! 🔍**
