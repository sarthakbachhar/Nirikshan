# Nirikshan - GRC Security Audit Platform

A comprehensive Governance, Risk, and Compliance (GRC) security auditing platform for automated compliance checking against industry standards.

---

## Overview

**Nirikshan** (meaning "inspection" in Nepali) is a web-based security audit platform designed to automate compliance assessments for IT infrastructure. It supports both live server audits via SSH and offline configuration file analysis.

### Key Features

- **Automated Compliance Auditing** - Run security audits against CIS Benchmarks, NRB IT Guidelines, and NTA Cyber Byelaw 2020
- **Online & Offline Audits** - Audit live servers via SSH or analyze uploaded configuration files
- **Firewall Auditing** - Unique OPNsense/pfSense firewall configuration auditing capability
- **Professional Reports** - Generate detailed HTML and PDF compliance reports
- **Multi-User Support** - Role-based access control (Administrator/Staff)
- **Dashboard Analytics** - Visual KPIs and compliance statistics
- **Activity Logging** - Complete audit trail of all user actions
- **Report Comparison** - Compare audit results over time to track compliance improvements

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Web Browser (Frontend)                   │
│                        web_ui.html                          │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTP/REST API
┌─────────────────────────▼───────────────────────────────────┐
│                    Flask Web API Layer                       │
│                       web_api.py                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Auth       │  │   Activity   │  │    PDF       │      │
│  │   Module     │  │   Logger     │  │  Generator   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                   Core Audit Engine                          │
│                        api.py                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Online Audits          │  Offline Config Audits     │  │
│  │  (Ansible Runner)       │  (YAML Playbook Parser)    │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                   Compliance Playbooks                       │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────┐ │
│  │ CIS L1/L2  │ │ NRB IT     │ │ NRB Cyber  │ │ NTA      │ │
│  │ Benchmarks │ │ Guidelines │ │ Resilience │ │ Byelaw   │ │
│  └────────────┘ └────────────┘ └────────────┘ └──────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.10 or higher
- MySQL Server
- SSH access to target servers (for online audits)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/sarthakbachhar/Nirikshan.git
   cd Nirikshan
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Setup MySQL Database**
   ```sql
   CREATE DATABASE auditor;
   CREATE USER 'admin'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON auditor.* TO 'admin'@'localhost';
   
   USE auditor;
   CREATE TABLE users (
       id INT AUTO_INCREMENT PRIMARY KEY,
       username VARCHAR(50) UNIQUE NOT NULL,
       password_hash VARCHAR(255) NOT NULL,
       role VARCHAR(20) DEFAULT 'Staff',
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
   ```

5. **Update database credentials in `auth.py`**

6. **Run the application**
   ```bash
   python web_api.py
   ```

7. **Access the dashboard**
   - Open browser: `http://localhost:5000`
   - Register a new account or login

---

## Project Structure

```
Nirikshan/
├── api.py                 # Core audit engine
├── web_api.py             # Flask REST API
├── auth.py                # User authentication (MySQL)
├── activity_logger.py     # Activity logging system
├── audit_storage.py       # Persistent audit storage
├── pdf_generator.py       # PDF report generation
├── web_ui.html            # Main dashboard UI
├── login.html             # Login page
├── register.html          # Registration page
├── user_management.html   # Admin user management
├── requirements.txt       # Python dependencies
├── playbooks/             # Compliance check definitions
│   ├── cis_audit_level1.yml
│   ├── cis_audit_level2.yml
│   ├── nrb_it_guidelines.yml
│   ├── nrb_cyber_resilience.yml
│   ├── nta_cyber_byelaw_2020.yml
│   └── nta_firewall_opnsense.yml
└── templates/             # Report templates
    ├── report_template.html
    └── report_template_offline.html
```

---

## Supported Compliance Frameworks

| Framework | Description | Check Count |
|-----------|-------------|-------------|
| **CIS Benchmark Level 1** | Basic security hardening for Ubuntu/Linux | 85+ checks |
| **CIS Benchmark Level 2** | Advanced security hardening | 50+ checks |
| **NRB IT Guidelines** | Nepal Rastra Bank IT security requirements | 45+ checks |
| **NRB Cyber Resilience** | NRB cyber resilience framework | 60+ checks |
| **NTA Cyber Byelaw 2020** | Nepal Telecom Authority regulations | 40+ checks |
| **NTA Firewall (OPNsense)** | Firewall security compliance | 35+ checks |

---

## Usage

### Running an Online Audit

1. Navigate to **Run Audit** section
2. Enter target server details:
   - IP Address
   - Username
   - SSH Key Path
   - Operating System
   - Compliance Level
3. Click **Start Audit**
4. View results and generate reports

### Running an Offline Config Audit

1. Navigate to **Offline Config Audit** section
2. Select compliance framework (NRB/NTA/CIS)
3. Upload configuration file(s):
   - For Linux: Upload `sshd_config` or tar.gz archive
   - For Firewall: Upload OPNsense XML backup
4. Click **Run Offline Audit**
5. View results and download reports

---

## Screenshots

### Dashboard
The main dashboard displays active audits, compliance statistics, and quick actions.

### Audit Results
Detailed view of each compliance check with pass/fail status and remediation guidance.

### Professional Reports
Generate branded HTML/PDF reports suitable for stakeholder presentations.

---

## Technologies Used

- **Backend:** Python 3, Flask, Ansible Runner
- **Database:** MySQL
- **Authentication:** Werkzeug (password hashing)
- **PDF Generation:** WeasyPrint, ReportLab
- **Frontend:** HTML5, CSS3, JavaScript
- **Templating:** Jinja2

---

## Author

**Sarthak Bachhar**

- GitHub: [@sarthakbachhar](https://github.com/sarthakbachhar)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- CIS (Center for Internet Security) for benchmark standards
- Nepal Rastra Bank for IT Guidelines and Cyber Resilience framework
- Nepal Telecom Authority for Cyber Security Byelaw 2020

---

Made for Final Year Project
