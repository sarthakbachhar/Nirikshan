#!/usr/bin/env python3
"""
Nirikshan Web API
This is my Flask-based REST API that powers the web interface.
I built this to handle all the HTTP requests from the frontend
and also make it possible to integrate with mobile apps if needed.

Author: Me
Project: Nirikshan (Final Year Project)
"""

from flask import Flask, request, jsonify, send_file, send_from_directory, session, redirect
from flask_cors import CORS
from functools import wraps
from auth import create_user, validate_login, get_all_users, delete_user
import os
import tempfile
import threading
import time
import json
import uuid
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import logging
import subprocess
import sys

# Import all the functions I need from my core audit engine
from api import (run_audit_batch, get_audit_results, generate_report_html, 
                generate_report_pdf, audit_results_storage, storage_lock, 
                AuditTarget, run_audit_single, save_audit_to_storage, compare_reports)

# Import my activity logging system to track what users are doing
from activity_logger import (
    logger as activity_logger,
    log_login, log_logout, log_audit_start, log_audit_complete,
    log_user_created, log_user_deleted, log_report_generated,
    log_batch_audit, log_schedule_created
)

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests for web and mobile apps

app.secret_key = "testpassword"

def login_required(f):
    """
    I use this decorator to protect routes that need authentication.
    If the user isn't logged in, they get a 401 error.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    """
    This decorator is for admin-only routes like user management.
    Only administrators can access these endpoints.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        if session.get('role') != 'Administrator':
            return jsonify({'error': 'Admin access required'}), 403

        return f(*args, **kwargs)
    return wrapper

# Set up logging so I can track what's happening
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration settings for file uploads
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB should be enough for config files
ALLOWED_EXTENSIONS = {'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Create necessary folders if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# For now I'm using in-memory storage for scheduled audits
# In a production app, I'd use a proper database for this
scheduled_audits = {}
schedule_lock = threading.Lock()

# I track whether PDF generation is available
pdf_capability = None

def check_pdf_dependencies():
    """
    I use this to check if all the PDF libraries are installed properly.
    PDF generation is a nice-to-have feature, so the app works without it too.
    """
    global pdf_capability
    
    if pdf_capability is not None:
        return pdf_capability
    
    try:
        # Try importing reportlab - it's what I use for PDF generation
        import reportlab
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate
        
        logger.info(f"ReportLab found - version: {reportlab.Version}")
        
        # Also check if my custom pdf_generator module is available
        current_dir = os.path.dirname(os.path.abspath(__file__))
        pdf_generator_path = os.path.join(current_dir, 'pdf_generator.py')
        
        if os.path.exists(pdf_generator_path):
            try:
                import pdf_generator
                if hasattr(pdf_generator, 'generate_pdf_report'):
                    logger.info("PDF generation fully available (reportlab + pdf_generator)")
                    pdf_capability = {'status': 'full', 'message': 'Full PDF generation available'}
                else:
                    logger.warning("pdf_generator.py exists but missing generate_pdf_report function")
                    pdf_capability = {'status': 'basic', 'message': 'Basic PDF generation available'}
            except ImportError as e:
                logger.warning(f"pdf_generator.py exists but import failed: {e}")
                pdf_capability = {'status': 'basic', 'message': 'Basic PDF generation available'}
        else:
            logger.warning("pdf_generator.py not found, using basic PDF generation")
            pdf_capability = {'status': 'basic', 'message': 'Basic PDF generation available'}
            
    except ImportError as e:
        logger.error(f"ReportLab not available: {e}")
        pdf_capability = {'status': 'none', 'message': f'PDF generation not available: {str(e)}'}
    
    return pdf_capability

def install_reportlab():
    """
    This tries to auto-install reportlab if it's missing.
    It's a convenience feature so users don't have to do it manually.
    """
    try:
        logger.info("Attempting to install reportlab...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab"])
        logger.info("ReportLab installed successfully")
        # Need to recheck now that it's installed
        global pdf_capability
        pdf_capability = None
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install reportlab: {e}")
        return False
    except Exception as e:
        logger.error(f"Error during reportlab installation: {e}")
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# API Endpoints

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint with PDF capability status"""
    pdf_status = check_pdf_dependencies()
    
    return jsonify({
        'status': 'healthy',
        'version': '2.1.0',
        'message': 'CIS Auditor API is running',
        'capabilities': {
            'pdf_generation': pdf_status
        }
    })

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role")
    
    # Get IP address
    ip_address = request.remote_addr

    # Validate with MySQL
    if validate_login(username, password, role):
        session["user"] = username
        session["role"] = role
        
        # Log successful login
        log_login(username, success=True, ip_address=ip_address)
        
        return jsonify({"success": True, "message": "Login successful"})
    
    # Record failed login attempts too - helps with security auditing
    log_login(username, success=False, ip_address=ip_address)

    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route('/api/register', methods=['POST'])
def register():
    """Creates a new user account - called from the registration page."""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "Staff")

    result = create_user(username, password, role)
    
    # Log when admins create new users
    if result["success"]:
        admin_user = session.get("user", "System")
        log_user_created(admin_user, username, role)

    status = 200 if result.get("success") else 400
    return jsonify(result), status

@app.route('/api/get-role', methods=['GET'])
@login_required
def get_role():
    """Returns the current user's role - used by the frontend for permissions."""
    return jsonify({"role": session.get("role")})

@app.route('/api/user-info', methods=['GET'])
@login_required
def user_info():
    """Gets info about the currently logged in user."""
    return jsonify({
        "username": session.get("user"),
        "role": session.get("role")
    })

@app.route('/api/users', methods=['GET'])
def api_users():
    """Returns list of all users - only admins can access this."""
    if "role" not in session or session["role"] != "Administrator":
        return jsonify({"error": "Admin access required"}), 403

    users = get_all_users()
    return jsonify(users)

@app.route('/api/delete-user', methods=['POST'])
def api_delete_user():
    """Deletes a user account - admin only."""
    if "role" not in session or session["role"] != "Administrator":
        return jsonify({"error": "Admin access required"}), 403

    data = request.get_json()
    username_to_delete = data.get("username")

    # Don't let admins accidentally delete themselves!
    if username_to_delete == session.get("user"):
        return jsonify({"success": False, "message": "You cannot delete your own account"}), 400

    result = delete_user(username_to_delete)
    
    # Record who deleted whom for accountability
    if result["success"]:
        admin_user = session.get("user")
        log_user_deleted(admin_user, username_to_delete)
    
    status = 200 if result["success"] else 400
    return jsonify(result), status

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Logs the user out and clears their session."""
    username = session.get("user")
    
    # Record the logout in the activity log
    if username:
        log_logout(username)
    
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out'})

@app.route('/api/pdf-status', methods=['GET'])
def pdf_status():
    """Checks if PDF generation is working - useful for troubleshooting."""
    pdf_status = check_pdf_dependencies()
    
    recommendations = []
    if pdf_status['status'] == 'none':
        recommendations.append("Install reportlab: pip install reportlab")
    elif pdf_status['status'] == 'basic':
        recommendations.append("For enhanced PDF reports, ensure pdf_generator.py is present")
    
    return jsonify({
        'pdf_capability': pdf_status,
        'recommendations': recommendations
    })

@app.route('/api/install-pdf', methods=['POST'])
def install_pdf_dependencies():
    """Tries to auto-install PDF dependencies if they're missing."""
    if request.json and request.json.get('confirm') == True:
        success = install_reportlab()
        if success:
            # Check if it worked
            pdf_status = check_pdf_dependencies()
            return jsonify({
                'success': True,
                'message': 'PDF dependencies installed successfully',
                'new_capability': pdf_status
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to install PDF dependencies. Please install manually: pip install reportlab'
            }), 500
    else:
        return jsonify({
            'error': 'Installation confirmation required',
            'required_payload': {'confirm': True}
        }), 400

@app.route('/api/audit/run', methods=['POST'])
@admin_required
def audit_single():
    """
    Starts an audit on a single server.
    This is the main endpoint the frontend calls when running an audit.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        required_fields = ['ip', 'username', 'key', 'os']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Convert the frontend OS names to what my backend expects
        os_type = data['os'].lower()
        if os_type == 'linux':
            os_type = 'ubuntu'  # Default Linux to ubuntu
        
        # Also normalize the audit level
        level = data.get('level', 'L1')
        if level == 'Level 1':
            level = 'level1'
        elif level == 'Level 2':
            level = 'level2'
        elif level == 'L1':
            level = 'level1'
        elif level == 'L2':
            level = 'level2'
        
        # Create the audit target object
        target = AuditTarget(
            ip=data['ip'],
            username=data['username'],
            key_path=data['key'],
            os=os_type,
            level=level
        )
        
        # Log that we're starting an audit
        current_user = session.get('user', 'Unknown')
        log_audit_start(current_user, data['ip'], os_type, level)
        
        # Run the audit in a separate thread so we don't block the API
        def run_audit_async():
            run_audit_single(target)
        
        thread = threading.Thread(target=run_audit_async)
        thread.start()
        
        return jsonify({
            'success': True,
            'audit': {
                'id': target.audit_id,
                'ip': target.ip,
                'os': target.os,
                'level': target.level,
                'status': 'running'
            }
        })
        
    except Exception as e:
        logger.error(f"Single audit error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/audit/batch', methods=['POST'])
@admin_required
def audit_batch():
    """Run batch audit from uploaded targets file"""
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only .txt files allowed'}), 400
        
        # Get optional parameters
        max_workers = request.form.get('workers', 5, type=int)
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        logger.info(f"Starting batch audit from file: {unique_filename}")
        
        # Count targets in file
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                target_count = len([line for line in content.split('\n') if line.strip() and not line.startswith('#')])
        except:
            target_count = 0
        
        # Log batch audit start
        current_user = session.get('user', 'Unknown')
        log_batch_audit(current_user, filename, target_count)
        
        # Run batch audit in background
        def run_batch_async():
            result = run_audit_batch(filepath, max_workers=max_workers)
            # Cleanup uploaded file
            try:
                os.remove(filepath)
            except:
                pass
        
        thread = threading.Thread(target=run_batch_async)
        thread.start()
        
        return jsonify({
            'success': True,
            'batch_file': filename,
            'total_created': 'Processing...',
            'message': 'Batch audit started successfully'
        })
            
    except Exception as e:
        logger.error(f"Batch audit error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/offline_audit/launch', methods=['POST'])
@login_required
def offline_audit_launch():
    """Launch offline configuration audit"""
    try:
        # Import offline config checker from api module
        from api import check_offline_config
        
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Get parameters
        compliance_type = request.form.get('compliance_type', '')
        target_name = request.form.get('target_name', '')
        
        if not compliance_type:
            return jsonify({'success': False, 'message': 'Compliance type not specified'}), 400
        
        # Generate target name if not provided
        if not target_name:
            if compliance_type == 'ubuntu_sshd':
                target_name = f"SSH_Config_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            elif compliance_type == 'nrb_rhel':
                target_name = f"NRB_RHEL_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            elif compliance_type == 'nrb_cyber_resilience':
                target_name = f"NRB_CyberResilience_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            elif compliance_type == 'nta_cyber_byelaw_2020':
                target_name = f"NTA_CyberByelaw2020_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            elif compliance_type == 'nta_firewall_opnsense':
                target_name = f"NTA_Firewall_OPNsense_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            else:
                target_name = f"Offline_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Handle different file types
        file_content = None
        archive_path = None
        
        if compliance_type in ['nrb_rhel', 'nrb_cyber_resilience', 'nta_cyber_byelaw_2020']:
            # For NRB and NTA compliance types, expect a tar.gz file
            if not file.filename.endswith(('.tar.gz', '.tgz')):
                return jsonify({'success': False, 'message': 'This compliance type requires a .tar.gz archive'}), 400
            
            # Save the uploaded archive temporarily
            import uuid as uuid_lib
            unique_filename = f"{uuid_lib.uuid4()}_{file.filename}"
            archive_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(archive_path)
        elif compliance_type == 'nta_firewall_opnsense':
            # For OPNsense firewall audit, expect an XML file
            if not file.filename.endswith('.xml'):
                return jsonify({'success': False, 'message': 'NTA Firewall OPNsense audit requires an .xml configuration file'}), 400
            
            # Read the XML content
            try:
                file_content = file.read().decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'message': 'File encoding error. Please upload a valid UTF-8 XML file'}), 400
        else:
            # For single file checks (like SSH), read as text
            try:
                file_content = file.read().decode('utf-8')
            except UnicodeDecodeError:
                return jsonify({'success': False, 'message': 'File encoding error. Please upload a UTF-8 text file'}), 400
        
        # Create audit entry
        audit_id = str(uuid.uuid4())
        
        # Log audit start
        current_user = session.get('user', 'Unknown')
        log_audit_start(current_user, target_name, 'Offline Config', compliance_type)
        
        # Run audit in background thread
        def run_offline_audit_async():
            try:
                # Create a pseudo-target object for offline audits
                from api import AuditTarget
                target = AuditTarget(
                    ip=target_name,
                    username='offline',
                    key_path='N/A',
                    os='offline_config',
                    level=compliance_type
                )
                target.audit_id = audit_id
                target.status = 'running'
                target.start_time = datetime.now()
                
                # Store in memory
                with storage_lock:
                    audit_results_storage[audit_id] = target
                    save_audit_to_storage(audit_id, {
                        'audit_id': audit_id,
                        'ip': target_name,
                        'username': 'offline',
                        'key_path': 'N/A',
                        'os': 'offline_config',
                        'level': compliance_type,
                        'status': 'running',
                        'start_time': target.start_time.isoformat(),
                        'end_time': None,
                        'results': [],
                        'error_message': None,
                        'audit_type': 'offline_config'
                    })
                
                # Perform the check
                check_result = check_offline_config(
                    file_content=file_content,
                    compliance_type=compliance_type,
                    archive_path=archive_path
                )
                
                if check_result.get('success'):
                    # Convert checks to audit results format
                    results = []
                    for check in check_result.get('checks', []):
                        results.append({
                            'check': f"{check.get('id', 'N/A')} - {check.get('name', 'Unnamed')}",
                            'status': check['status'],
                            'description': check.get('description', ''),
                            'expected': check.get('expected', check.get('remediation', '')),
                            'actual': check.get('actual', ''),
                            'remediation': check.get('remediation', ''),
                            'severity': check.get('severity', 'MEDIUM')
                        })
                    
                    target.results = results
                    target.status = 'completed'
                else:
                    target.results = [{
                        'check': 'Offline Config Check',
                        'status': 'FAILED',
                        'remediation': check_result.get('error', 'Unknown error occurred')
                    }]
                    target.status = 'failed'
                    target.error_message = check_result.get('error', 'Unknown error')
                
                target.end_time = datetime.now()
                
                # Update storage
                with storage_lock:
                    audit_results_storage[audit_id] = target
                    save_audit_to_storage(audit_id, {
                        'audit_id': audit_id,
                        'ip': target_name,
                        'username': 'offline',
                        'key_path': 'N/A',
                        'os': 'offline_config',
                        'level': compliance_type,
                        'status': target.status,
                        'start_time': target.start_time.isoformat(),
                        'end_time': target.end_time.isoformat(),
                        'results': target.results,
                        'error_message': target.error_message,
                        'audit_type': 'offline_config'
                    })
                
                # Log completion
                passed = len([r for r in target.results if 'PASS' in r.get('status', '')])
                failed = len([r for r in target.results if 'FAIL' in r.get('status', '')])
                success = target.status == 'completed'
                log_audit_complete(current_user, target_name, success)
                
                logger.info(f"Offline audit {audit_id} completed for {target_name} - Passed: {passed}, Failed: {failed}")
                
            except Exception as e:
                logger.error(f"Error in offline audit {audit_id}: {str(e)}")
                target.status = 'failed'
                target.error_message = str(e)
                target.end_time = datetime.now()
                target.results = [{
                    'check': 'Offline Audit Error',
                    'status': 'FAILED',
                    'remediation': f'Error: {str(e)}'
                }]
                
                with storage_lock:
                    audit_results_storage[audit_id] = target
                    save_audit_to_storage(audit_id, {
                        'audit_id': audit_id,
                        'ip': target_name,
                        'username': 'offline',
                        'key_path': 'N/A',
                        'os': 'offline_config',
                        'level': compliance_type,
                        'status': 'failed',
                        'start_time': target.start_time.isoformat() if target.start_time else None,
                        'end_time': target.end_time.isoformat() if target.end_time else None,
                        'results': target.results,
                        'error_message': str(e),
                        'audit_type': 'offline_config'
                    })
            
            finally:
                # Cleanup archive file if it was created
                if archive_path and os.path.exists(archive_path):
                    try:
                        os.remove(archive_path)
                        logger.info(f"Cleaned up archive file: {archive_path}")
                    except Exception as cleanup_error:
                        logger.warning(f"Failed to cleanup archive: {cleanup_error}")
        
        # Start the audit thread
        thread = threading.Thread(target=run_offline_audit_async)
        thread.start()
        
        return jsonify({
            'success': True,
            'audit_id': audit_id,
            'target_name': target_name,
            'compliance_type': compliance_type,
            'message': 'Offline audit started successfully'
        })
        
    except Exception as e:
        logger.error(f"Offline audit launch error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Internal server error: {str(e)}'
        }), 500

@app.route('/api/offline_audit/compliances', methods=['GET'])
@login_required
def list_offline_compliances():
    """List available offline compliance standards"""
    try:
        compliances = [
            {
                'id': 'ubuntu_sshd',
                'name': 'CIS Ubuntu - SSH Server Configuration',
                'description': 'CIS Benchmark controls for OpenSSH server configuration (sshd_config)',
                'file_type': 'sshd_config',
                'file_format': 'text',
                'typical_location': '/etc/ssh/sshd_config'
            },
            {
                'id': 'nrb_rhel',
                'name': 'NRB IT Guidelines - RHEL Configuration',
                'description': 'Nepal Rastra Bank IT Guidelines compliance checks for RHEL/CentOS systems. Upload tar.gz archive containing extracted configuration files.',
                'file_type': 'archive',
                'file_format': 'tar.gz',
                'required_files': [
                    'etc/pam.d/system-auth',
                    'etc/pam.d/password-auth',
                    'etc/login.defs',
                    'etc/ssh/sshd_config',
                    'etc/sudoers',
                    'etc/sysctl.conf',
                    'etc/selinux/config',
                    'etc/audit/auditd.conf',
                    'etc/audit/rules.d/audit.rules',
                    'etc/rsyslog.conf',
                    'etc/logrotate.conf',
                    'os-release.txt',
                    'users-list.txt'
                ],
                'instructions': 'Extract configuration files from your RHEL system and create a tar.gz archive with the directory structure intact.'
            },
            {
                'id': 'nrb_cyber_resilience',
                'name': 'NRB Cyber Resilience Guidelines - RHEL Configuration',
                'description': 'Nepal Rastra Bank Cyber Resilience Guidelines compliance checks for RHEL/CentOS systems. Upload tar.gz archive containing extracted configuration files.',
                'file_type': 'archive',
                'file_format': 'tar.gz',
                'required_files': [
                    'etc/pam.d/system-auth',
                    'etc/pam.d/password-auth',
                    'etc/login.defs',
                    'etc/security/pwquality.conf',
                    'etc/shadow',
                    'etc/ssh/sshd_config',
                    'etc/sudoers',
                    'etc/sysctl.conf',
                    'etc/selinux/config',
                    'etc/modprobe.d/CIS.conf',
                    'etc/audit/auditd.conf',
                    'etc/audit/rules.d/audit.rules',
                    'etc/rsyslog.conf',
                    'etc/rsyslog.d/',
                    'var/log/secure',
                    'etc/firewalld/zones/public.xml',
                    'etc/hosts.allow',
                    'etc/hosts.deny',
                    'etc/fstab',
                    'etc/crontab',
                    'etc/logrotate.conf',
                    'os-release.txt',
                    'users-list.txt'
                ],
                'instructions': 'Extract configuration files from your RHEL system and create a tar.gz archive with the directory structure intact.'
            },
            {
                'id': 'nta_cyber_byelaw_2020',
                'name': 'NTA Cyber Byelaw 2020 - RHEL Configuration',
                'description': 'Nepal Telecom Authority Cyber Security Byelaw 2020 compliance checks for RHEL/CentOS systems. Upload tar.gz archive containing extracted configuration files.',
                'file_type': 'archive',
                'file_format': 'tar.gz',
                'required_files': [
                    'etc/pam.d/system-auth',
                    'etc/login.defs',
                    'etc/security/pwquality.conf',
                    'etc/sudoers',
                    'etc/ssh/sshd_config',
                    'etc/sysctl.conf',
                    'etc/selinux/config',
                    'etc/firewalld/zones/public.xml',
                    'etc/resolv.conf',
                    'etc/audit/auditd.conf',
                    'etc/audit/rules.d/audit.rules',
                    'etc/rsyslog.conf',
                    'password_policy.txt',
                    'ipv6_status.txt',
                    'listening_services.txt',
                    'os_license_check.txt'
                ],
                'instructions': 'Extract configuration files from your RHEL system and create a tar.gz archive with the directory structure intact. Generate custom files with: echo "..." > password_policy.txt, sysctl net.ipv6.conf.all.disable_ipv6 > ipv6_status.txt, ss -tuln > listening_services.txt, subscription-manager status > os_license_check.txt'
            }
            # Future compliance types can be added here
        ]
        
        return jsonify({
            'success': True,
            'compliances': compliances
        })
    except Exception as e:
        logger.error(f"List compliances error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Internal server error: {str(e)}'
        }), 500

@app.route('/api/audits/active', methods=['GET'])
def list_active_audits():
    """List all audits with enhanced data for the web UI"""
    try:
        with storage_lock:
            audits = []
            for audit_id, target in audit_results_storage.items():
                # Check if this is an offline config audit
                is_offline = target.os == 'offline_config' or target.os.lower() == 'offline_config'
                
                # Calculate summary statistics
                # Offline audits use 'PASS', 'FAIL', 'WARNING'
                # Online audits use 'PASSED', 'FAILED'
                if is_offline:
                    passed_checks = len([r for r in target.results if r.get('status', '').upper() == 'PASS'])
                    failed_checks = len([r for r in target.results if r.get('status', '').upper() == 'FAIL'])
                    warning_checks = len([r for r in target.results if r.get('status', '').upper() == 'WARNING'])
                else:
                    passed_checks = len([r for r in target.results if 'PASSED' in r.get('status', '')])
                    failed_checks = len([r for r in target.results if 'FAILED' in r.get('status', '')])
                    warning_checks = 0
                
                # Calculate duration
                duration = "N/A"
                if target.start_time:
                    if target.end_time:
                        duration_delta = target.end_time - target.start_time
                        duration = str(duration_delta).split('.')[0]  # Remove microseconds
                    else:
                        duration_delta = datetime.now() - target.start_time
                        duration = f"{str(duration_delta).split('.')[0]} (running)"
                
                # Format start time
                start_time_str = target.start_time.strftime('%Y-%m-%d %H:%M:%S') if target.start_time else 'N/A'
                
                # Determine audit category
                if is_offline:
                    audit_category = 'Offline Config Audit'
                else:
                    audit_category = 'Online Machine Audit'
                
                # Calculate compliance percentage
                total_checks = len(target.results)
                compliance_percentage = round((passed_checks / total_checks * 100), 2) if total_checks > 0 else 0
                
                audit_data = {
                    'id': audit_id,
                    'audit_id': audit_id,  # Add for backward compatibility
                    'target': target.ip,
                    'ip': target.ip,  # Add for backward compatibility
                    'os': target.os.title(),  # Capitalize for display
                    'level': target.level.upper() if target.level != 'default' else 'Default',
                    'status': target.status,
                    'start_time': start_time_str,
                    'duration': duration,
                    'category': audit_category,
                    'is_offline': is_offline,
                    'playbook_used': target.playbook_used,  # Add playbook info
                    'compliance_percentage': compliance_percentage,  # Add compliance percentage
                    'summary': {
                        'passed': passed_checks,
                        'failed': failed_checks,
                        'warnings': warning_checks,
                        'total': len(target.results)
                    }
                }
                audits.append(audit_data)
        
        # Sort by start time, newest first
        audits.sort(key=lambda x: x.get('start_time', ''), reverse=True)
        
        return jsonify({'audits': audits})
        
    except Exception as e:
        logger.error(f"List active audits error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/audit/<audit_id>/status', methods=['GET'])
def get_audit_status(audit_id):
    """Get status and results of a specific audit"""
    try:
        result = get_audit_results(audit_id)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 404
            
    except Exception as e:
        logger.error(f"Get audit status error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/audit/<audit_id>/report', methods=['GET'])
@admin_required
def generate_audit_report(audit_id):
    """Generate and serve HTML/PDF report for a specific audit"""
    try:
        logger.info(f"Report requested for audit ID: {audit_id}")
        
        # First check if audit exists in storage
        with storage_lock:
            target = audit_results_storage.get(audit_id)
        
        if not target:
            logger.error(f"Audit {audit_id} not found in storage")
            return jsonify({'error': 'Audit not found'}), 404
        
        if target.status not in ['completed', 'failed']:
            logger.warning(f"Audit {audit_id} is not completed (status: {target.status})")
            return jsonify({'error': 'Audit is not yet completed'}), 400
        
        # Check if we want PDF format
        format_type = request.args.get('format', 'html')
        
        if format_type.lower() == 'pdf':
            # Check PDF capability first
            pdf_status = check_pdf_dependencies()
            
            if pdf_status['status'] == 'none':
                return jsonify({
                    'error': 'PDF generation not available', 
                    'details': pdf_status['message'],
                    'solution': 'Install reportlab: pip install reportlab'
                }), 501  # Not Implemented
            
            # Generate PDF report
            try:
                pdf_path = generate_report_pdf(audit_id)
                
                if pdf_path and os.path.exists(pdf_path):
                    logger.info(f"PDF report generated successfully at: {pdf_path}")
                    
                    # Log report generation
                    current_user = session.get('user', 'Unknown')
                    log_report_generated(current_user, target.ip, 'pdf')
                    
                    # Check if download is requested (default is inline preview)
                    download_mode = request.args.get('download', 'false').lower() == 'true'
                    
                    # Return PDF file for inline viewing or download
                    return send_file(pdf_path, 
                                   as_attachment=download_mode,  # false = inline preview, true = download
                                   download_name=f"audit_report_{target.ip}_{audit_id[:8]}.pdf",
                                   mimetype='application/pdf')
                else:
                    # PDF generation failed, but we can offer alternatives
                    error_response = {
                        'error': 'PDF report generation failed',
                        'pdf_status': pdf_status,
                        'alternatives': {
                            'html_report': f'/api/audit/{audit_id}/report?format=html'
                        }
                    }
                    
                    if pdf_status['status'] == 'basic':
                        error_response['suggestion'] = 'PDF generation may be limited. Consider adding pdf_generator.py for enhanced reports.'
                    
                    return jsonify(error_response), 500
                    
            except Exception as pdf_error:
                logger.error(f"PDF generation exception: {str(pdf_error)}")
                return jsonify({
                    'error': 'PDF generation encountered an error',
                    'details': str(pdf_error),
                    'pdf_status': pdf_status,
                    'alternatives': {
                        'html_report': f'/api/audit/{audit_id}/report?format=html'
                    }
                }), 500
        
        else:
            # Generate HTML report (this should always work)
            try:
                html_path = generate_report_html(audit_id)
                
                if html_path and os.path.exists(html_path):
                    logger.info(f"HTML report generated successfully at: {html_path}")
                    
                    # Log report generation
                    current_user = session.get('user', 'Unknown')
                    log_report_generated(current_user, target.ip, 'html')
                    
                    # Return HTML for viewing in browser
                    return send_file(html_path, as_attachment=False,
                                   mimetype='text/html')
                else:
                    logger.error(f"HTML report generation failed for audit {audit_id}")
                    return jsonify({'error': 'HTML report generation failed'}), 500
                    
            except Exception as html_error:
                logger.error(f"HTML generation exception: {str(html_error)}")
                return jsonify({
                    'error': 'HTML report generation failed',
                    'details': str(html_error)
                }), 500
            
    except Exception as e:
        logger.error(f"Generate report error: {str(e)}", exc_info=True)
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/schedule', methods=['POST'])
@admin_required
def create_schedule():
    """Schedule an audit for later execution"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        date = request.form.get('date')
        time_str = request.form.get('time')
        
        if not date or not time_str:
            return jsonify({'error': 'Date and time are required'}), 400
        
        # Validate and parse datetime
        try:
            schedule_datetime = datetime.strptime(f"{date} {time_str}", "%Y-%m-%d %H:%M")
        except ValueError:
            return jsonify({'error': 'Invalid date or time format'}), 400
        
        # Check if the scheduled time is in the future
        if schedule_datetime <= datetime.now():
            return jsonify({'error': 'Scheduled time must be in the future'}), 400
        
        # Save the uploaded file
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        unique_filename = f"scheduled_{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        # Create schedule entry
        schedule_id = f"schedule_{timestamp}"
        with schedule_lock:
            scheduled_audits[schedule_id] = {
                'id': schedule_id,
                'target': filename,
                'file_path': filepath,
                'date': date,
                'time': time_str,
                'datetime': schedule_datetime,
                'status': 'scheduled',
                'created_at': datetime.now()
            }
        
        # Log schedule creation
        current_user = session.get('user', 'Unknown')
        scheduled_time = f"{date} {time_str}"
        log_schedule_created(current_user, filename, scheduled_time)
        
        return jsonify({
            'success': True,
            'created': {
                'id': schedule_id,
                'target': filename,
                'scheduled_for': schedule_datetime.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Create schedule error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/schedule', methods=['GET'])
def list_schedules():
    """List all scheduled audits"""
    try:
        with schedule_lock:
            schedules = []
            for schedule_id, schedule_data in scheduled_audits.items():
                schedules.append({
                    'id': schedule_data['id'],
                    'target': schedule_data['target'],
                    'date': schedule_data['date'],
                    'time': schedule_data['time'],
                    'status': schedule_data['status']
                })
        
        # Sort by scheduled datetime
        schedules.sort(key=lambda x: f"{x['date']} {x['time']}")
        
        return jsonify({'schedules': schedules})
        
    except Exception as e:
        logger.error(f"List schedules error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/schedule/<schedule_id>', methods=['DELETE'])
@admin_required
def delete_schedule(schedule_id):
    """Delete a scheduled audit"""
    try:
        with schedule_lock:
            if schedule_id in scheduled_audits:
                schedule_data = scheduled_audits[schedule_id]
                # Clean up the uploaded file
                try:
                    if os.path.exists(schedule_data['file_path']):
                        os.remove(schedule_data['file_path'])
                except:
                    pass
                
                del scheduled_audits[schedule_id]
                return jsonify({'deleted': True})
            else:
                return jsonify({'error': 'Schedule not found'}), 404
        
    except Exception as e:
        logger.error(f"Delete schedule error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/upload-test', methods=['POST'])
@admin_required
def upload_test():
    """Test endpoint for file upload functionality"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read and validate file content
        content = file.read().decode('utf-8')
        file.seek(0)  # Reset file pointer
        
        lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
        
        valid_targets = []
        invalid_lines = []
        
        for i, line in enumerate(lines, 1):
            parts = line.split()
            if len(parts) >= 4:  # Now requires OS field
                os_type = parts[3].lower()
                level = parts[4] if len(parts) > 4 else ('level1' if os_type != 'windows' else 'default')
                
                valid_targets.append({
                    'ip': parts[0],
                    'username': parts[1],
                    'key_path': parts[2],
                    'os': os_type,
                    'level': level
                })
            else:
                invalid_lines.append(f"Line {i}: {line}")
        
        return jsonify({
            'success': True,
            'valid_targets': len(valid_targets),
            'targets': valid_targets,
            'invalid_lines': invalid_lines
        })
        
    except Exception as e:
        return jsonify({'error': f'File processing error: {str(e)}'}), 400

# Activity Log Endpoints
@app.route('/api/activity-logs', methods=['GET'])
@admin_required
def get_activity_logs():
    """Get all activity logs (admin only)"""
    try:
        limit = request.args.get('limit', type=int)
        logs = activity_logger.get_all_logs(limit=limit)
        
        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs)
        })
    except Exception as e:
        logger.error(f"Error retrieving activity logs: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve activity logs',
            'message': str(e)
        }), 500

@app.route('/api/activity-logs/clear', methods=['DELETE'])
@admin_required
def clear_activity_logs():
    """Clear all activity logs (admin only, with backup)"""
    try:
        admin_user = session.get('user', 'Unknown')
        
        # Log this critical action before clearing
        activity_logger.log_activity(
            user=admin_user,
            action="Logs Cleared",
            details="Administrator cleared all activity logs",
            status="success"
        )
        
        # Clear the logs (backup is automatically created)
        success = activity_logger.clear_all_logs()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Activity logs cleared successfully. Backup has been created.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to clear activity logs'
            }), 500
            
    except Exception as e:
        logger.error(f"Error clearing activity logs: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to clear activity logs',
            'message': str(e)
        }), 500

@app.route('/api/activity-logs/stats', methods=['GET'])
@admin_required
def get_activity_stats():
    """Get activity log statistics (admin only)"""
    try:
        stats = activity_logger.get_statistics()
        return jsonify({
            'success': True,
            'statistics': stats
        })
    except Exception as e:
        logger.error(f"Error getting activity stats: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve statistics',
            'message': str(e)
        }), 500

@app.route('/api/audit/<audit_id>/delete', methods=['DELETE'])
@admin_required
def delete_audit(audit_id):
    """Delete a specific audit and its associated reports (admin only)"""
    try:
        from audit_storage import delete_audit_from_storage
        
        admin_user = session.get('user', 'Unknown')
        
        # Get audit info before deletion for logging
        with storage_lock:
            audit = audit_results_storage.get(audit_id)
            if not audit:
                return jsonify({
                    'success': False,
                    'message': 'Audit not found'
                }), 404
            
            audit_ip = audit.ip if hasattr(audit, 'ip') else 'Unknown'
        
        # Delete from persistent storage
        success = delete_audit_from_storage(audit_id)
        
        # Delete from memory storage
        with storage_lock:
            if audit_id in audit_results_storage:
                del audit_results_storage[audit_id]
        
        # Delete associated report files
        reports_dir = 'reports'
        if os.path.exists(reports_dir):
            # Find and delete report files for this audit
            for filename in os.listdir(reports_dir):
                if audit_id in filename or (audit and hasattr(audit, 'ip') and audit.ip.replace('.', '_') in filename):
                    try:
                        os.remove(os.path.join(reports_dir, filename))
                    except Exception as e:
                        logger.warning(f"Could not delete report file {filename}: {e}")
        
        # Log the deletion
        log_user_deleted(
            admin_user=admin_user,
            deleted_item=f"Audit for {audit_ip}",
            item_type="audit"
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Audit {audit_id} deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to delete audit from storage'
            }), 500
            
    except Exception as e:
        logger.error(f"Error deleting audit {audit_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete audit',
            'message': str(e)
        }), 500

@app.route('/api/audits/clear', methods=['DELETE'])
@admin_required
def clear_all_audits():
    """Clear all audits and reports (admin only, with backup)"""
    try:
        from audit_storage import clear_all_audits_from_storage
        
        admin_user = session.get('user', 'Unknown')
        
        # Get count before clearing
        audit_count = len(audit_results_storage)
        
        # Clear persistent storage (backup is automatically created)
        success = clear_all_audits_from_storage()
        
        # Clear memory storage
        with storage_lock:
            audit_results_storage.clear()
        
        # Clear all report files
        reports_dir = 'reports'
        if os.path.exists(reports_dir):
            try:
                for filename in os.listdir(reports_dir):
                    file_path = os.path.join(reports_dir, filename)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
            except Exception as e:
                logger.warning(f"Could not clear all report files: {e}")
        
        # Log this critical action
        activity_logger.log_activity(
            user=admin_user,
            action="Audits Cleared",
            details=f"Administrator cleared all {audit_count} audits and reports",
            status="success"
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': f'All audits cleared successfully ({audit_count} audits removed). Backup has been created.'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to clear audits from storage'
            }), 500
            
    except Exception as e:
        logger.error(f"Error clearing all audits: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to clear audits',
            'message': str(e)
        }), 500

@app.route('/login', methods=['GET'])
def login_page():
    return send_file('login.html')

@app.route('/register', methods=['GET'])
def register_page():
    return send_file('register.html')

# Web UI Route
@app.route('/manage-users')
@admin_required
def manage_users():
    return send_file('user_management.html')

@app.route('/', methods=['GET'])
def web_interface():
    # If user is not logged in → redirect to login page
    if 'user' not in session:
        return redirect('/login')

    # If logged in → show the UI
    try:
        return send_file('web_ui.html')
    except FileNotFoundError:
        return jsonify({'error': 'Web UI file not found'}), 404

# Static file serving for any additional assets
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

# Background scheduler to check for scheduled audits
def schedule_checker():
    """Background thread to check and execute scheduled audits"""
    while True:
        try:
            current_time = datetime.now()
            to_execute = []
            
            with schedule_lock:
                for schedule_id, schedule_data in scheduled_audits.items():
                    if (schedule_data['status'] == 'scheduled' and 
                        schedule_data['datetime'] <= current_time):
                        to_execute.append((schedule_id, schedule_data))
            
            # Execute scheduled audits
            for schedule_id, schedule_data in to_execute:
                try:
                    logger.info(f"Executing scheduled audit: {schedule_id}")
                    
                    # Update status
                    with schedule_lock:
                        scheduled_audits[schedule_id]['status'] = 'running'
                    
                    # Run the audit
                    result = run_audit_batch(schedule_data['file_path'], max_workers=3)
                    
                    # Update status and cleanup
                    with schedule_lock:
                        scheduled_audits[schedule_id]['status'] = 'completed'
                        # Clean up file
                        try:
                            os.remove(schedule_data['file_path'])
                        except:
                            pass
                    
                    logger.info(f"Scheduled audit completed: {schedule_id}")
                    
                except Exception as e:
                    logger.error(f"Error executing scheduled audit {schedule_id}: {str(e)}")
                    with schedule_lock:
                        scheduled_audits[schedule_id]['status'] = 'failed'
            
        except Exception as e:
            logger.error(f"Schedule checker error: {str(e)}")
        
        # Check every minute
        time.sleep(60)

# Start background scheduler
def start_scheduler():
    scheduler_thread = threading.Thread(target=schedule_checker, daemon=True)
    scheduler_thread.start()

# Error handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 16MB'}), 413

@app.errorhandler(404)
def not_found(e):
    # Check if it's an API request
    if request.path.startswith('/api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    else:
        return jsonify({'error': 'Page not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/compare_reports', methods=['POST'])
@login_required
def compare_audit_reports():
    """
    Compare two audit reports and return differences
    Request body should contain: {audit_id_1: str, audit_id_2: str}
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Request body is required'
            }), 400
        
        audit_id_1 = data.get('audit_id_1')
        audit_id_2 = data.get('audit_id_2')
        
        if not audit_id_1 or not audit_id_2:
            return jsonify({
                'success': False,
                'error': 'Both audit_id_1 and audit_id_2 are required'
            }), 400
        
        if audit_id_1 == audit_id_2:
            return jsonify({
                'success': False,
                'error': 'Cannot compare an audit with itself'
            }), 400
        
        # Call the comparison function
        result = compare_reports(audit_id_1, audit_id_2)
        
        if not result.get('success'):
            # Return error from comparison (e.g., playbook mismatch)
            status_code = 400 if 'playbook' in result.get('error', '').lower() else 404
            return jsonify(result), status_code
        
        logger.info(f"Successfully compared audits {audit_id_1} and {audit_id_2}")
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error comparing reports: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to compare reports: {str(e)}'
        }), 500


if __name__ == '__main__':
    # Ensure required directories exist
    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("templates", exist_ok=True)
    
    # Check PDF capabilities on startup
    print("Checking PDF generation capabilities...")
    pdf_status = check_pdf_dependencies()
    print(f"PDF Status: {pdf_status['message']}")
    
    # Start background scheduler
    start_scheduler()
    
    print("CIS Auditor Web API Starting...")
    print("API Endpoints:")
    print("  POST /api/audit/run - Run single target audit")
    print("  POST /api/audit/batch - Run batch audit from file")
    print("  GET  /api/audits/active - List all audits")
    print("  GET  /api/audit/<id>/status - Get audit status")
    print("  GET  /api/audit/<id>/report - Download HTML report")
    print("  GET  /api/audit/<id>/report?format=pdf - Download PDF report")
    print("  POST /api/compare_reports - Compare two audit reports")
    print("  POST /api/schedule - Schedule audit")
    print("  GET  /api/schedule - List scheduled audits")
    print("  DELETE /api/schedule/<id> - Delete scheduled audit")
    print("  GET  /api/health - Health check")
    print("  GET  /api/pdf-status - Check PDF capabilities")
    print("  POST /api/install-pdf - Install PDF dependencies")
    print("  POST /api/upload-test - Test file upload")
    print("")
    print("Web UI available at: http://localhost:5000")
    print("Use Ctrl+C to stop the server")
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
