# NetScan - Network Monitoring & Protection System

NetScan is an advanced web application built with the Flask framework, designed for automated periodic network port monitoring and vulnerability scanning. The project aims to provide an easy-to-use tool for network administrators to track port status and receive instant alerts when suspicious changes occur.

##  Key Features
*   **Port Scanning:** Fast and comprehensive port scanning using the Nmap library.
*   **Scheduled Scans:** Ability to set up automatic scans (hourly, daily, etc.).
*   **Alert System:** Real-time notifications within the application and email alerts when critical ports are detected.
*   **Result Comparison:** Analyze differences between current and previous scans to detect changes.
*   **PDF Reports:** Export scan results in professional, well-organized reports.
*   **Email Management:** Send critical alerts directly to the user's email.

##  Technologies Used
*   **Backend:** Python (Flask), SQLAlchemy.
*   **Database:** SQLite.
*   **Security Tools:** Nmap (python-nmap).
*   **Frontend:** Tailwind CSS, JavaScript.
*   **Reporting:** FPDF2.
*   **Scheduling:** APScheduler.

##  How to Run
1.  **Install dependencies:**
    
    pip install -r requirements.txt
    
2.  **Install Nmap:** Make sure Nmap is installed on your system.
3.  **Run the application:**
    
    python run.py
    
4.  **Access the application:** Open your browser at `http://localhost:5000`.

## 📂 Project Structure
*   `app/`: Contains the application logic (routes, models, scanner).
*   `templates/`: User interface templates (HTML).
*   `static/`: Static files (CSS, JS).
*   `instance/`: Local database.
*   `run.py`: Application entry point.


Note:This project is intended for educational and security purposes. Please use it responsibly and only on networks you have permission to scan.

