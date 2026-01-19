#!/usr/bin/env python3
"""
Nirikshan - Core Audit Engine
I built this module as the heart of my GRC security audit platform.
It handles everything from running compliance checks to generating reports.

Author: Me
Project: Nirikshan (Final Year Project)
"""

import ansible_runner
import json
import os
import datetime
import shutil
import logging
from jinja2 import Environment, FileSystemLoader, Template
import concurrent.futures
import threading
from typing import List, Dict, Any
import uuid
from weasyprint import HTML
import yaml
import re

# I need to import my persistent storage module to keep audit data safe across restarts
from audit_storage import (
    audit_storage, 
    save_audit_to_storage,
    get_audit_from_storage,
    get_all_audits_from_storage,
    delete_audit_from_storage,
    clear_all_audits_from_storage
)

# Setting up logging so I can track what's happening and debug issues
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# I'm keeping this in memory storage for quick access during runtime
# But the actual data is backed by my persistent JSON storage so nothing gets lost
audit_results_storage = {}
storage_lock = threading.Lock()

class AuditTarget:
    """
    This class represents a server or device that I want to audit.
    It stores all the connection details and audit results for each target.
    """
    def __init__(self, ip: str, username: str, key_path: str, os: str = "ubuntu", level: str = "level1"):
        self.ip = ip
        self.username = username
        self.key_path = key_path
        self.os = os.lower()
        self.level = level if os.lower() != "windows" else "default"
        self.audit_id = str(uuid.uuid4())  # Generate a unique ID for each audit
        self.results = []
        self.status = "pending"
        self.start_time = None
        self.end_time = None
        self.error_message = None
        self.playbook_used = None  # I track which playbook was used so users know what was checked

# When the app starts, I load any previously saved audits from storage
def load_audits_from_storage():
    """This function loads saved audits from my JSON storage back into memory"""
    with storage_lock:
        stored_audits = get_all_audits_from_storage()
        for audit_id, audit_data in stored_audits.items():
            # I need to rebuild the AuditTarget objects from the saved JSON data
            if isinstance(audit_data, dict):
                target = AuditTarget(
                    ip=audit_data.get('ip', ''),
                    username=audit_data.get('username', ''),
                    key_path=audit_data.get('key_path', ''),
                    os=audit_data.get('os', 'ubuntu'),
                    level=audit_data.get('level', 'level1')
                )
                target.audit_id = audit_id
                target.status = audit_data.get('status', 'unknown')
                target.results = audit_data.get('results', [])
                target.error_message = audit_data.get('error_message')
                target.playbook_used = audit_data.get('playbook_used')  # Restore playbook info
                
                # I need to handle datetime parsing carefully since JSON stores dates as strings
                if audit_data.get('start_time'):
                    try:
                        target.start_time = datetime.datetime.fromisoformat(audit_data['start_time'])
                    except:
                        target.start_time = None
                
                if audit_data.get('end_time'):
                    try:
                        target.end_time = datetime.datetime.fromisoformat(audit_data['end_time'])
                    except:
                        target.end_time = None
                
                audit_results_storage[audit_id] = target

# Load any existing audits when the app starts up
try:
    load_audits_from_storage()
    logger.info(f"Loaded {len(audit_results_storage)} audits from persistent storage")
except Exception as e:
    logger.warning(f"Error loading audits from storage: {e}")

def parse_targets_file(file_path: str) -> List[AuditTarget]:
    """
    I use this to read the targets file which has all the servers to audit.
    Each line should have: IP USERNAME KEY_PATH OS [LEVEL]
    
    Example format:
    192.168.1.100 ubuntu /path/to/key ubuntu level1
    192.168.1.101 administrator /path/to/key windows
    """
    targets = []
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Targets file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            parts = line.split()
            if len(parts) < 4:  # I need at least 4 fields - IP, username, key, and OS
                logger.warning(f"Invalid line {line_num} in targets file: {line}")
                continue
                
            ip = parts[0]
            username = parts[1]
            key_path = parts[2]
            os_type = parts[3]
            level = parts[4] if len(parts) > 4 else ("level1" if os_type.lower() != "windows" else "default")
            
            targets.append(AuditTarget(ip, username, key_path, os_type, level))
    
    logger.info(f"Parsed {len(targets)} targets from {file_path}")
    return targets

def run_audit_single(target: AuditTarget) -> AuditTarget:
    """
    This is the main function that runs a CIS compliance audit on a single server.
    It uses Ansible to connect via SSH and run all the compliance checks.
    """
    logger.info(f"Starting audit for {target.ip} with OS {target.os} and level {target.level}")
    target.start_time = datetime.datetime.now()
    target.status = "running"
    
    # Save the initial status so users can see the audit is in progress
    with storage_lock:
        audit_results_storage[target.audit_id] = target
        save_audit_to_storage(target.audit_id, {
            'audit_id': target.audit_id,
            'ip': target.ip,
            'username': target.username,
            'key_path': target.key_path,
            'os': target.os,
            'level': target.level,
            'status': target.status,
            'start_time': target.start_time.isoformat() if target.start_time else None,
            'end_time': None,
            'results': [],
            'error_message': None,
            'playbook_used': None  # Will be set once I figure out which playbook to use
        })
    
    try:
        # Figure out where my playbooks are located
        base_dir = os.path.dirname(os.path.abspath(__file__))
        playbooks_dir = os.path.join(base_dir, 'playbooks')

        # Make sure the playbooks folder exists
        if not os.path.isdir(playbooks_dir):
            os.makedirs(playbooks_dir, exist_ok=True)
            logger.warning(f"Created playbooks directory: {playbooks_dir}")

        # Pick the right playbook based on what OS we're auditing
        if target.os.lower() == "windows":
            playbook_filename = 'cis_audit_windows.yml'
        else:  # For Ubuntu/Linux systems
            playbook_filename = f'cis_audit_{target.level}.yml'
        
        playbook_path = os.path.join(playbooks_dir, playbook_filename)

        # If playbook isn't in the playbooks folder, check the main directory
        if not os.path.isfile(playbook_path):
            current_dir_playbook = os.path.join(base_dir, playbook_filename)
            if os.path.isfile(current_dir_playbook):
                playbook_path = current_dir_playbook
            else:
                raise Exception(f"Playbook not found: {playbook_filename} (looked in {playbooks_dir} and {base_dir})")

        # Remember which playbook we used for this audit
        target.playbook_used = playbook_filename

        # Set up a temporary folder for Ansible to work in
        runner_dir = os.path.join(base_dir, f'runner_temp_{target.audit_id}')
        if os.path.exists(runner_dir):
            shutil.rmtree(runner_dir)
        os.makedirs(runner_dir, exist_ok=True)

        try:
            # Create the inventory file that tells Ansible which server to connect to
            inventory_dir = os.path.join(runner_dir, 'inventory')
            os.makedirs(inventory_dir, exist_ok=True)
            
            with open(os.path.join(inventory_dir, 'hosts'), 'w') as f:
                f.write(f"[servers]\n{target.ip}\n")

            # Set up the connection settings - Windows needs different settings
            if target.os.lower() == "windows":
                extravars = {
                    'ansible_user': target.username,
                    'ansible_ssh_private_key_file': target.key_path,
                    'ansible_host_key_checking': False,
                    'ansible_ssh_common_args': '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null',
                    'ansible_connection': 'ssh',  # Using SSH for Windows too (OpenSSH)
                    'ansible_shell_type': 'powershell'
                }
            else:
                extravars = {
                    'ansible_user': target.username,
                    'ansible_ssh_private_key_file': target.key_path,
                    'ansible_host_key_checking': False,
                    'ansible_ssh_common_args': '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
                }

            logger.info(f"Running Ansible playbook: {playbook_path}")
            
            # Now let's actually run the Ansible playbook
            r = ansible_runner.run(
                private_data_dir=runner_dir,
                playbook=playbook_path,
                extravars=extravars,
                quiet=False,
                verbosity=1
            )

            # Extract the results from what Ansible returned
            target.results = parse_ansible_results(r)
            
            # If the parser didn't find specific checks, at least report the overall status
            if not target.results:
                if r.status == 'successful':
                    target.results = [{
                        'check': 'Ansible Execution',
                        'status': 'PASSED',
                        'remediation': 'Playbook executed successfully but no specific CIS checks were detected'
                    }]
                elif r.status == 'failed':
                    target.results = [{
                        'check': 'Ansible Execution',
                        'status': 'FAILED',
                        'remediation': f'Playbook execution failed. Check logs for details.'
                    }]
                else:
                    target.results = [{
                        'check': 'Ansible Execution',
                        'status': 'FAILED',
                        'remediation': f'Playbook execution status: {r.status}'
                    }]
            
            target.status = "completed"
            target.end_time = datetime.datetime.now()
            
            logger.info(f"Audit completed for {target.ip} with {len(target.results)} checks")

        finally:
            # Clean up the temp folder so we don't fill up the disk
            if os.path.exists(runner_dir):
                try:
                    shutil.rmtree(runner_dir)
                except Exception as cleanup_error:
                    logger.warning(f"Could not cleanup temp directory: {cleanup_error}")

    except Exception as e:
        logger.error(f"Error during audit for {target.ip}: {str(e)}")
        target.status = "failed"
        target.error_message = str(e)
        target.end_time = datetime.datetime.now()
        target.results = [{
            'check': 'Execution Error',
            'status': 'FAILED',
            'remediation': f'Error: {str(e)}'
        }]
    
    # Save the final results to both memory and persistent storage
    with storage_lock:
        audit_results_storage[target.audit_id] = target
        save_audit_to_storage(target.audit_id, {
            'audit_id': target.audit_id,
            'ip': target.ip,
            'username': target.username,
            'key_path': target.key_path,
            'os': target.os,
            'level': target.level,
            'status': target.status,
            'start_time': target.start_time.isoformat() if target.start_time else None,
            'end_time': target.end_time.isoformat() if target.end_time else None,
            'results': target.results,
            'error_message': target.error_message,
            'playbook_used': target.playbook_used  # Keep track of which playbook was used
        })
    
    return target

def run_audit_batch(targets_file: str, max_workers: int = 5) -> Dict[str, Any]:
    """
    This function lets me audit multiple servers at the same time.
    It uses threading to run audits in parallel for better performance.
    """
    try:
        targets = parse_targets_file(targets_file)
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'targets': []
        }
    
    if not targets:
        return {
            'success': False,
            'error': 'No valid targets found',
            'targets': []
        }
    
    batch_id = str(uuid.uuid4())
    logger.info(f"Starting batch audit {batch_id} with {len(targets)} targets")
    
    # Run all audits at the same time using a thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(run_audit_single, target): target for target in targets}
        
        completed_targets = []
        for future in concurrent.futures.as_completed(future_to_target):
            try:
                target = future.result()
                completed_targets.append(target)
            except Exception as e:
                logger.error(f"Error in batch audit thread: {str(e)}")
                # If something went wrong, create a placeholder for the failed audit
                failed_target = AuditTarget("unknown", "unknown", "unknown")
                failed_target.status = "failed"
                failed_target.error_message = str(e)
                failed_target.results = [{
                    'check': 'Thread Execution Error',
                    'status': 'FAILED',
                    'remediation': f'Error: {str(e)}'
                }]
                completed_targets.append(failed_target)
    
    # Calculate a summary of how the batch audit went
    total_targets = len(completed_targets)
    successful_targets = len([t for t in completed_targets if t.status == "completed"])
    failed_targets = total_targets - successful_targets
    
    result = {
        'success': True,
        'batch_id': batch_id,
        'summary': {
            'total_targets': total_targets,
            'successful': successful_targets,
            'failed': failed_targets
        },
        'targets': []
    }
    
    # Include details for each target that was audited
    for target in completed_targets:
        target_info = {
            'audit_id': target.audit_id,
            'ip': target.ip,
            'username': target.username,
            'os': target.os,
            'level': target.level,
            'status': target.status,
            'start_time': target.start_time.isoformat() if target.start_time else None,
            'end_time': target.end_time.isoformat() if target.end_time else None,
            'duration': str(target.end_time - target.start_time) if target.start_time and target.end_time else None,
            'error_message': target.error_message,
            'results_count': len(target.results),
            'passed_checks': len([r for r in target.results if 'PASSED' in r['status']]),
            'failed_checks': len([r for r in target.results if 'FAILED' in r['status']])
        }
        result['targets'].append(target_info)
    
    logger.info(f"Batch audit {batch_id} completed: {successful_targets}/{total_targets} successful")
    return result

def get_audit_results(audit_id: str) -> Dict[str, Any]:
    """Fetches the results for a specific audit by its ID"""
    with storage_lock:
        target = audit_results_storage.get(audit_id)
    
    if not target:
        return {'success': False, 'error': 'Audit not found'}
    
    return {
        'success': True,
        'audit_id': audit_id,
        'ip': target.ip,
        'os': target.os,
        'status': target.status,
        'results': target.results,
        'summary': {
            'total_checks': len(target.results),
            'passed_checks': len([r for r in target.results if 'PASSED' in r['status']]),
            'failed_checks': len([r for r in target.results if 'FAILED' in r['status']])
        }
    }

def generate_report_html(audit_id: str) -> str:
    """
    Creates a nice HTML report for an audit.
    I use Jinja2 templates to make the reports look professional.
    Works for both online and offline config audits.
    """
    logger.info(f"Generating HTML report for audit ID: {audit_id}")
    
    with storage_lock:
        target = audit_results_storage.get(audit_id)
    
    if not target:
        logger.error(f"Audit {audit_id} not found in storage")
        return None
    
    if not target.results:
        logger.warning(f"No results available for audit {audit_id}")
        target.results = [{
            'check': 'No Results',
            'status': 'FAILED',
            'remediation': 'Audit completed but no results were captured'
        }]

    try:
        # Make sure the reports folder exists
        reports_dir = 'reports'
        os.makedirs(reports_dir, exist_ok=True)
        
        # I include the timestamp in the filename so each report is unique
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_ip = target.ip.replace('.', '_').replace(':', '_')
        report_filename = os.path.join(reports_dir, f"{safe_ip}_{timestamp}.html")
        
        # Figure out which template to use based on audit type
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Check if this is an offline config audit or a regular online audit
        is_offline = target.os.lower() == 'offline_config'
        
        if is_offline:
            template_file = os.path.join(current_dir, 'templates', 'report_template_offline.html')
        else:
            template_file = os.path.join(current_dir, 'templates', 'report_template.html')
        
        if not os.path.isfile(template_file):
            logger.warning(f"Template file not found at {template_file}, creating basic HTML report")
            html_content = generate_basic_html_report(target)
        else:
            logger.info(f"Using template file: {template_file}")
            with open(template_file, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            html_content = process_template(template_content, target, is_offline=is_offline)
        
        # Save the report to a file
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML report generated successfully: {report_filename}")
        return os.path.abspath(report_filename)

    except Exception as e:
        logger.error(f"Error generating HTML report for {audit_id}: {str(e)}")
        return None

def generate_report_pdf(audit_id: str) -> str:
    """
    Creates a PDF version of the audit report.
    I use WeasyPrint to convert my HTML template to a clean PDF.
    """
    logger.info(f"Generating PDF report (HTML-to-PDF) for audit ID: {audit_id}")
    
    try:
        # First get the audit data from storage
        with storage_lock:
            target = audit_results_storage.get(audit_id)
        
        if not target:
            logger.error(f"Audit {audit_id} not found in storage")
            return None
        
        if not target.results:
            logger.warning(f"No results available for audit {audit_id}")
            target.results = [{
                'check': 'No Results',
                'status': 'FAILED',
                'remediation': 'Audit completed but no results were captured'
            }]
        
        # Use different templates for online vs offline audits
        is_offline = target.os.lower() == 'offline_config'
        
        if is_offline:
            template_path = 'templates/report_template_offline.html'
        else:
            template_path = 'templates/report_template.html'
        
        if os.path.exists(template_path):
            logger.info(f"Using template file: {os.path.abspath(template_path)}")
            with open(template_path, 'r') as f:
                template_content = f.read()
            
            # Process template with Jinja2
            html_content = process_template(template_content, target, is_offline=is_offline)
        else:
            logger.warning(f"Template not found at {template_path}, using basic HTML generator")
            html_content = generate_basic_html_report(target)
        
        # Ensure reports directory exists
        reports_dir = 'reports'
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate PDF filename with datetime
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_ip = target.ip.replace('.', '_').replace(':', '_')
        pdf_filename = os.path.join(reports_dir, f"{safe_ip}_{timestamp}.pdf")
        
        # Convert HTML to PDF using WeasyPrint
        logger.info(f"Converting HTML to PDF: {pdf_filename}")
        HTML(string=html_content, base_url=os.path.abspath('.')).write_pdf(pdf_filename)
        
        logger.info(f"PDF report generated successfully from HTML: {pdf_filename}")
        return os.path.abspath(pdf_filename)
        
    except Exception as e:
        logger.error(f"Error generating PDF report for {audit_id}: {str(e)}")
        logger.error(f"Exception details: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return None


def generate_basic_html_report(target):
    """Generate a basic HTML report when template is not available"""
    total_checks = len(target.results)
    passed_checks = len([r for r in target.results if 'PASSED' in r['status']])
    failed_checks = total_checks - passed_checks
    compliance_pct = round((passed_checks / total_checks * 100), 1) if total_checks > 0 else 0
    
    results_html = ""
    for result in target.results:
        status_style = "color: #28a745;" if 'PASSED' in result['status'] else "color: #dc3545;"
        remediation = result.get('remediation', 'No remediation provided') if 'FAILED' in result['status'] else 'No action required'
        
        results_html += f"""
        <tr>
            <td>{result.get('check', 'Unknown Check')}</td>
            <td style="{status_style} font-weight: bold;">{result.get('status', 'UNKNOWN')}</td>
            <td>{remediation}</td>
        </tr>
        """
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Nirikshan Security Audit Report - {target.ip}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
            .summary-card {{ background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; text-align: center; flex: 1; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }}
            .progress {{ background: #e9ecef; height: 20px; border-radius: 10px; overflow: hidden; margin: 10px 0; }}
            .progress-bar {{ height: 100%; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); color: white; text-align: center; line-height: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Nirikshan Security Audit Report</h1>
            <p><strong>Target:</strong> {target.ip}</p>
            <p><strong>OS:</strong> {target.os}</p>
            <p><strong>Level:</strong> {target.level}</p>
            <p><strong>Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>{total_checks}</h3>
                <p>Total Checks</p>
            </div>
            <div class="summary-card">
                <h3>{passed_checks}</h3>
                <p>Passed</p>
            </div>
            <div class="summary-card">
                <h3>{failed_checks}</h3>
                <p>Failed</p>
            </div>
        </div>
        
        <div class="progress">
            <div class="progress-bar" style="width: {compliance_pct}%">{compliance_pct}% Compliant</div>
        </div>
        
        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {results_html}
            </tbody>
        </table>
        
        <div style="margin-top: 40px; text-align: center; color: #666;">
            <p>Generated by Nirikshan - GRC Audit Platform</p>
        </div>
    </body>
    </html>
    """

def process_template(template_content, target, is_offline=False):
    """Process the template with target data using Jinja2"""
    try:
        from jinja2 import Template
        
        # Calculate metrics
        total_checks = len(target.results)
        passed_checks = len([r for r in target.results if 'PASS' in r.get('status', '')])
        failed_checks = len([r for r in target.results if 'FAIL' in r.get('status', '')])
        warnings_checks = len([r for r in target.results if 'WARNING' in r.get('status', '')])
        skipped_checks = total_checks - passed_checks - failed_checks - warnings_checks
        
        # Calculate compliance percentage
        compliance_pct = round((passed_checks / total_checks * 100), 1) if total_checks > 0 else 0
        
        # Format duration
        duration_str = str(target.end_time - target.start_time).split('.')[0] if target.start_time and target.end_time else "N/A"
        
        # Format dates
        scan_date = target.start_time.strftime("%B %d, %Y") if target.start_time else "N/A"
        scan_time = target.start_time.strftime("%H:%M:%S") if target.start_time else "N/A"
        
        # Prepare template context based on audit type
        if is_offline:
            # Offline config audit context
            context = {
                'target_name': target.ip,  # For offline audits, ip field contains target name
                'compliance_type': target.level if target.level else 'Unknown',
                'scan_date': scan_date,
                'scan_time': scan_time,
                'duration': duration_str,
                'total_checks': total_checks,
                'passed_checks': passed_checks,
                'failed_checks': failed_checks,
                'warnings_checks': warnings_checks,
                'compliance_percentage': compliance_pct,
                'results': target.results,
                'audit_id': target.audit_id
            }
        else:
            # Regular audit context
            context = {
                'target_ip': target.ip,
                'os_type': target.os.upper(),
                'audit_level': target.level.upper() if target.level != 'default' else 'Default',
                'scan_date': scan_date,
                'scan_time': scan_time,
                'duration': duration_str,
                'total_checks': total_checks,
                'passed_checks': passed_checks,
                'failed_checks': failed_checks,
                'skipped_checks': skipped_checks,
                'compliance_percentage': compliance_pct,
                'results': target.results,
                'audit_id': target.audit_id
            }
        
        # Render template with Jinja2
        template = Template(template_content)
        html_output = template.render(**context)
        
        return html_output
        
    except ImportError:
        # Fallback to simple string replacement if Jinja2 not available
        logger.warning("Jinja2 not available, using simple string replacement")
        total_checks = len(target.results)
        passed_checks = len([r for r in target.results if 'PASS' in r['status']])
        failed_checks = total_checks - passed_checks
        duration_str = str(target.end_time - target.start_time).split('.')[0] if target.start_time and target.end_time else "N/A"
        compliance_pct = round((passed_checks / total_checks * 100), 1) if total_checks > 0 else 0
        
        # Replace template variables
        if is_offline:
            html_output = template_content.replace('{{ target_name }}', target.ip)
            html_output = html_output.replace('{{ compliance_type }}', target.level)
        else:
            html_output = template_content.replace('{{ target_ip }}', target.ip)
            html_output = html_output.replace('{{ audit_level }}', target.level.upper())
            html_output = html_output.replace('{{ os_type }}', target.os.upper())
        
        html_output = html_output.replace('{{ date_time }}', datetime.datetime.now().strftime("%B %d, %Y at %H:%M:%S"))
        html_output = html_output.replace('{{ duration }}', duration_str)
        html_output = html_output.replace('{{ total_checks }}', str(total_checks))
        html_output = html_output.replace('{{ passed_checks }}', str(passed_checks))
        html_output = html_output.replace('{{ failed_checks }}', str(failed_checks))
        html_output = html_output.replace('{{ compliance_percentage }}', str(compliance_pct))
        
        # Build results table rows with enhanced styling
        results_rows = ""
        for result in target.results:
            status_class = "result-failed" if 'FAIL' in result['status'] else "result-passed"
            badge_class = "status-failed" if 'FAIL' in result['status'] else "status-passed"
            
            # Enhanced check ID formatting
            check_content = f'<div class="check-id">{result.get("check", "Unknown Check")}</div>'
            
            # Enhanced remediation formatting
            if 'FAIL' in result['status'] and result.get('remediation'):
                remediation_html = f'<div class="remediation">{result.get("remediation", "")}</div>'
            else:
                remediation_html = '<div class="no-remediation">Control is compliant</div>'
            
            results_rows += f'''
                <tr class="result-row {status_class}">
                    <td>{check_content}</td>
                    <td><span class="status-badge {badge_class}">{result.get('status', 'UNKNOWN')}</span></td>
                    <td>{remediation_html}</td>
                </tr>
            '''
        
        # Replace the results_rows placeholder
        html_output = html_output.replace('{{ results_rows }}', results_rows)
        
        return html_output

def generate_batch_report(batch_result: Dict[str, Any]) -> str:
    """Generate a summary report for batch audit with datetime in filename"""
    try:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        batch_id = batch_result.get('batch_id', 'unknown')
        
        os.makedirs('reports', exist_ok=True)
        # Updated filename format: batch_batchid_datetime.html
        report_filename = f"reports/batch_{batch_id[:8]}_{timestamp}.html"
        
        # Create batch report HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Batch Audit Report - {timestamp}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #1a365d; color: white; padding: 20px; margin-bottom: 20px; }}
                .summary {{ background: #f0f0f0; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .target {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .success {{ border-left: 4px solid #38a169; background: #f0fff4; }}
                .failed {{ border-left: 4px solid #e53e3e; background: #fff5f5; }}
                .metadata {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 15px 0; }}
                .metadata-item {{ background: white; padding: 10px; border: 1px solid #e5e7eb; border-radius: 4px; }}
                .metadata-label {{ font-size: 0.875rem; color: #6b7280; text-transform: uppercase; }}
                .metadata-value {{ font-size: 1.125rem; font-weight: 600; color: #374151; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Batch Audit Report</h1>
                <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Batch ID: {batch_id}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <div class="metadata">
                    <div class="metadata-item">
                        <div class="metadata-label">Total Targets</div>
                        <div class="metadata-value">{batch_result['summary']['total_targets']}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Successful</div>
                        <div class="metadata-value">{batch_result['summary']['successful']}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Failed</div>
                        <div class="metadata-value">{batch_result['summary']['failed']}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Success Rate</div>
                        <div class="metadata-value">{round((batch_result['summary']['successful'] / batch_result['summary']['total_targets'] * 100), 1) if batch_result['summary']['total_targets'] > 0 else 0}%</div>
                    </div>
                </div>
            </div>
            
            <h2>Target Details</h2>
        """
        
        for target in batch_result['targets']:
            status_class = 'success' if target['status'] == 'completed' else 'failed'
            html_content += f"""
            <div class="target {status_class}">
                <h3>{target['ip']} ({target['os'].upper()})</h3>
                <div class="metadata">
                    <div class="metadata-item">
                        <div class="metadata-label">Status</div>
                        <div class="metadata-value">{target['status'].upper()}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Level</div>
                        <div class="metadata-value">{target['level'].upper()}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Duration</div>
                        <div class="metadata-value">{target.get('duration', 'N/A')}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Results</div>
                        <div class="metadata-value">✓ {target['passed_checks']} | ✗ {target['failed_checks']}</div>
                    </div>
                </div>
                {f"<p style='color: #e53e3e; font-weight: 600;'>Error: {target['error_message']}</p>" if target.get('error_message') else ""}
            </div>
            """
        
        html_content += """
            <div style="margin-top: 40px; text-align: center; padding: 20px; background: #f9fafb; border-radius: 5px;">
                <p style="color: #6b7280;">Generated by Nirikshan - GRC Audit Platform</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        logger.info(f"Batch report generated: {report_filename}")
        return report_filename
        
    except Exception as e:
        logger.error(f"Error generating batch report: {str(e)}")
        return None

def parse_ansible_results(ansible_run):
    """
    Parse Ansible runner results to extract CIS check outcomes
    """
    results = []
    current_check = None
    check_results = {}

    try:
        for event in ansible_run.events:
            event_type = event.get('event')
            event_data = event.get('event_data', {})
            task_name = event_data.get('task', '')

            # Detect CIS check tasks
            if 'CIS' in task_name and 'Check' in task_name and 'Result:' not in task_name:
                current_check = task_name
                check_results[current_check] = {'status': 'UNKNOWN', 'remediation': ''}
                continue

            # Process result tasks
            if current_check and 'CIS' in task_name and 'Result:' in task_name:
                if 'Pass' in task_name:
                    if event_type == 'runner_on_ok':
                        check_results[current_check] = {
                            'status': 'PASSED',
                            'remediation': ''
                        }
                elif 'Fail' in task_name:
                    if event_type == 'runner_on_failed':
                        remediation = event_data.get('res', {}).get('msg', 'No remediation provided')
                        check_results[current_check] = {
                            'status': 'FAILED',
                            'remediation': remediation
                        }

        # Convert to final results
        for check_name, result in check_results.items():
            if result['status'] != 'UNKNOWN':
                results.append({
                    'check': check_name,
                    'status': result['status'],
                    'remediation': result['remediation']
                })

        # Handle connection issues
        if ansible_run.status == 'unreachable':
            results.append({
                'check': 'Host Connectivity',
                'status': 'FAILED',
                'remediation': 'Could not connect to host. Check IP, SSH access, and key file.'
            })
        elif ansible_run.status == 'failed' and not results:
            # If the run failed but we didn't capture any specific checks
            results.append({
                'check': 'Playbook Execution',
                'status': 'FAILED',
                'remediation': f'Playbook failed to execute. Status: {ansible_run.status}'
            })

    except Exception as e:
        logger.error(f"Error parsing ansible results: {str(e)}")
        results.append({
            'check': 'Result Parsing Error',
            'status': 'FAILED',
            'remediation': f'Error parsing results: {str(e)}'
        })

    return results

# Legacy function for backward compatibility
def run_audit(host_ip, username, key_path, level, os_type="ubuntu"):
    """Legacy single audit function for backward compatibility"""
    target = AuditTarget(host_ip, username, key_path, os_type, level)
    completed_target = run_audit_single(target)
    return completed_target.results

# Keep global variable for backward compatibility
audit_results = []

def get_legacy_audit_results():
    """Return current audit results (legacy function)"""
    return audit_results


# ============================================================================
# OFFLINE CONFIGURATION COMPLIANCE CHECKER
# ============================================================================

class SSHDConfigChecker:
    """
    CIS Ubuntu SSH Server Configuration Checker
    Checks sshd_config against CIS Ubuntu Benchmark controls defined in playbook
    """
    
    def __init__(self, config_content: str, playbook_path: str = 'playbooks/cis_offline_ubuntu_sshd.yml'):
        self.config_content = config_content
        self.config_lines = [line.strip() for line in config_content.split('\n')]
        self.config_dict = self._parse_config()
        self.playbook_path = playbook_path
        self.checks_config = self._load_playbook()
        
    def _parse_config(self) -> Dict[str, str]:
        """Parse sshd_config into a dictionary"""
        config = {}
        for line in self.config_lines:
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse key-value pairs
            parts = line.split(None, 1)
            if len(parts) == 2:
                key, value = parts
                config[key.lower()] = value.lower()
        
        return config
    
    def _load_playbook(self) -> Dict[str, Any]:
        """Load check definitions from YAML playbook"""
        try:
            if os.path.exists(self.playbook_path):
                with open(self.playbook_path, 'r') as f:
                    playbook = yaml.safe_load(f)
                    return playbook.get('checks', [])
            else:
                logger.warning(f"Playbook not found: {self.playbook_path}")
                return []
        except Exception as e:
            logger.error(f"Error loading playbook: {str(e)}")
            return []
    
    def _get_config_value(self, key: str, default: str = None) -> str:
        """Get configuration value, case-insensitive"""
        return self.config_dict.get(key.lower(), default)
    
    def _evaluate_check(self, check_config: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a single check based on playbook configuration"""
        check_id = check_config.get('id', 'UNKNOWN')
        check_name = check_config.get('name', 'Unknown Check')
        description = check_config.get('description', '')
        severity = check_config.get('severity', 'MEDIUM')
        remediation = check_config.get('remediation', '')
        
        parameter = check_config.get('parameter', '').lower()
        expected_value = check_config.get('expected_value', '')
        check_type = check_config.get('check_type', 'exact_match')
        default_value = check_config.get('default_value', '')
        
        # Get actual value from config
        actual_value = self._get_config_value(parameter, default_value)
        
        # Evaluate based on check_type
        passed = False
        status = 'FAIL'
        
        if check_type == 'exact_match':
            passed = actual_value == expected_value.lower()
        elif check_type == 'exact_match_or_default':
            # Pass if value matches expected OR parameter is not in config (using default)
            passed = actual_value == expected_value.lower() or parameter not in self.config_dict
        elif check_type == 'in_list':
            expected_list = [v.lower() for v in expected_value.split(',')]
            passed = actual_value in expected_list
        elif check_type == 'not_in_list':
            forbidden_list = [v.lower() for v in expected_value.split(',')]
            passed = actual_value not in forbidden_list
        elif check_type == 'less_than_or_equal':
            try:
                passed = int(actual_value) <= int(expected_value)
            except ValueError:
                passed = False
        elif check_type == 'range':
            try:
                min_val, max_val = map(int, expected_value.split('-'))
                actual_int = int(actual_value)
                passed = min_val <= actual_int <= max_val
            except ValueError:
                passed = False
        elif check_type == 'no_weak_ciphers':
            weak_ciphers = expected_value.split(',')
            if not actual_value or actual_value == default_value:
                passed = True  # Using defaults
            else:
                passed = not any(weak in actual_value for weak in weak_ciphers)
        elif check_type == 'warning':
            # Warning type - always passes but flags for attention
            passed = actual_value == expected_value.lower()
            status = 'WARNING' if not passed else 'PASS'
        
        if check_type != 'warning':
            status = 'PASS' if passed else 'FAIL'
        
        # Format actual value display
        if parameter in self.config_dict:
            actual_display = f"{parameter.title()} {actual_value}"
        else:
            actual_display = f"{parameter.title()} {actual_value} (default)"
        
        return {
            'check_id': check_id,
            'check_name': check_name,
            'description': description,
            'expected': f"{parameter.title()} {expected_value}",
            'actual': actual_display,
            'status': status,
            'severity': severity,
            'remediation': remediation
        }
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Run all SSH configuration checks defined in playbook"""
        results = []
        
        if not self.checks_config:
            logger.error("No checks loaded from playbook")
            return [{
                'check_id': 'ERROR',
                'check_name': 'Playbook Load Error',
                'description': 'Failed to load checks from playbook',
                'expected': 'Valid playbook file',
                'actual': f'Playbook not found or invalid: {self.playbook_path}',
                'status': 'FAIL',
                'severity': 'HIGH',
                'remediation': 'Ensure playbook file exists and is valid YAML'
            }]
        
        for check_config in self.checks_config:
            try:
                result = self._evaluate_check(check_config)
                results.append(result)
            except Exception as e:
                logger.error(f"Error evaluating check {check_config.get('id', 'UNKNOWN')}: {str(e)}")
                results.append({
                    'check_id': check_config.get('id', 'ERROR'),
                    'check_name': check_config.get('name', 'Error'),
                    'description': f"Error during check: {str(e)}",
                    'expected': 'N/A',
                    'actual': 'Error',
                    'status': 'FAIL',
                    'severity': 'HIGH',
                    'remediation': f'Fix check configuration: {str(e)}'
                })
        
        return results


class NRBConfigChecker:
    """
    NRB IT Guidelines RHEL Configuration Checker
    Checks multiple RHEL config files against NRB IT Guidelines
    Supports tar.gz archives containing extracted configuration files
    """
    
    def __init__(self, archive_path: str = None, playbook_path: str = 'playbooks/nrb_it_guidelines.yml'):
        self.archive_path = archive_path
        self.playbook_path = playbook_path
        self.extracted_files = {}
        self.checks_config = self._load_playbook()
        
        if archive_path:
            self._extract_archive()
    
    def _extract_archive(self):
        """Extract tar.gz archive and load configuration files"""
        import tarfile
        import tempfile
        
        try:
            temp_dir = tempfile.mkdtemp()
            
            with tarfile.open(self.archive_path, 'r:gz') as tar:
                tar.extractall(path=temp_dir)
            
            # Map expected files to their content
            # Extended list for cyber resilience compliance
            expected_files = [
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
            ]
            
            for file_path in expected_files:
                full_path = os.path.join(temp_dir, file_path)
                
                # Handle directory files (like rsyslog.d/)
                if file_path.endswith('/'):
                    if os.path.isdir(full_path):
                        # Concatenate all files in directory
                        combined_content = ""
                        try:
                            for fname in os.listdir(full_path):
                                fpath = os.path.join(full_path, fname)
                                if os.path.isfile(fpath):
                                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                                        combined_content += f"### File: {fname} ###\n"
                                        combined_content += f.read()
                                        combined_content += "\n"
                            self.extracted_files[file_path] = combined_content
                            logger.info(f"Loaded directory: {file_path}")
                        except Exception as e:
                            logger.error(f"Error reading directory {file_path}: {e}")
                            self.extracted_files[file_path] = None
                    else:
                        logger.warning(f"Directory not found in archive: {file_path}")
                        self.extracted_files[file_path] = None
                else:
                    # Handle regular files
                    if os.path.exists(full_path):
                        try:
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                self.extracted_files[file_path] = f.read()
                            logger.info(f"Loaded file: {file_path}")
                        except Exception as e:
                            logger.error(f"Error reading file {file_path}: {e}")
                            self.extracted_files[file_path] = None
                    else:
                        logger.warning(f"File not found in archive: {file_path}")
                        self.extracted_files[file_path] = None
            
            # Cleanup temp directory
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            
        except Exception as e:
            logger.error(f"Error extracting archive: {e}")
            raise
    
    def _load_playbook(self) -> Dict[str, Any]:
        """Load check definitions from YAML playbook"""
        try:
            if os.path.exists(self.playbook_path):
                with open(self.playbook_path, 'r') as f:
                    playbook = yaml.safe_load(f)
                    return playbook
            else:
                logger.warning(f"Playbook not found: {self.playbook_path}")
                return {}
        except Exception as e:
            logger.error(f"Error loading playbook: {e}")
            return {}
    
    def _check_file_exists(self, file_path: str) -> bool:
        """Check if file exists in extracted files"""
        return file_path in self.extracted_files and self.extracted_files[file_path] is not None
    
    def _check_contains(self, file_path: str, pattern: str) -> bool:
        """Check if file contains pattern"""
        if not self._check_file_exists(file_path):
            return False
        
        import re
        content = self.extracted_files[file_path]
        
        # Support regex patterns
        try:
            return bool(re.search(pattern, content, re.IGNORECASE))
        except:
            # Fallback to simple string search
            return pattern.lower() in content.lower()
    
    def _check_not_contains(self, file_path: str, pattern: str) -> bool:
        """Check if file does NOT contain pattern"""
        if not self._check_file_exists(file_path):
            return True  # If file doesn't exist, it doesn't contain the pattern
        
        return not self._check_contains(file_path, pattern)
    
    def _check_parameter_set(self, file_path: str, parameter: str, expected_value: str, comparison: str = "==") -> bool:
        """Check if parameter is set to expected value"""
        if not self._check_file_exists(file_path):
            return False
        
        content = self.extracted_files[file_path]
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            # Skip comments
            if line.startswith('#') or not line:
                continue
            
            # Parse parameter lines (key = value or key value)
            parts = line.split(None, 1) if '=' not in line else line.split('=', 1)
            
            if len(parts) >= 2:
                key = parts[0].strip()
                value = parts[1].strip()
                
                if key.lower() == parameter.lower():
                    # Handle numeric comparisons
                    if comparison in ['<', '>', '<=', '>=']:
                        try:
                            actual_val = float(value)
                            expected_val = float(expected_value)
                            
                            if comparison == '<':
                                return actual_val < expected_val
                            elif comparison == '>':
                                return actual_val > expected_val
                            elif comparison == '<=':
                                return actual_val <= expected_val
                            elif comparison == '>=':
                                return actual_val >= expected_val
                        except:
                            return False
                    else:
                        # String comparison
                        return value.lower() == expected_value.lower()
        
        return False
    
    def _run_check(self, check: Dict[str, Any]) -> Dict[str, Any]:
        """Run a single check and return result"""
        check_id = check.get('id', 'UNKNOWN')
        name = check.get('name', 'Unnamed check')
        description = check.get('description', '')
        file_path = check.get('file', '')
        check_type = check.get('check_type', '')
        severity = check.get('severity', 'MEDIUM')
        remediation = check.get('remediation', 'No remediation provided')
        nrb_reference = check.get('nrb_reference', '')
        
        status = 'FAIL'
        message = ''
        
        try:
            if check_type == 'file_exists':
                if self._check_file_exists(file_path):
                    status = 'PASS'
                    message = f"File {file_path} exists"
                else:
                    status = 'FAIL'
                    message = f"File {file_path} not found in archive"
            
            elif check_type == 'contains':
                pattern = check.get('pattern', '')
                if self._check_contains(file_path, pattern):
                    status = 'PASS'
                    message = f"Pattern '{pattern}' found in {file_path}"
                else:
                    status = 'FAIL'
                    message = f"Pattern '{pattern}' not found in {file_path}"
            
            elif check_type == 'not_contains':
                pattern = check.get('pattern', '')
                if self._check_not_contains(file_path, pattern):
                    status = 'PASS'
                    message = f"Pattern '{pattern}' not present in {file_path}"
                else:
                    status = 'FAIL'
                    message = f"Unwanted pattern '{pattern}' found in {file_path}"
            
            elif check_type == 'parameter_set':
                parameter = check.get('parameter', '')
                expected_value = check.get('expected_value', '')
                comparison = check.get('comparison', '==')
                
                if self._check_parameter_set(file_path, parameter, expected_value, comparison):
                    status = 'PASS'
                    message = f"Parameter {parameter} correctly configured in {file_path}"
                else:
                    status = 'FAIL'
                    message = f"Parameter {parameter} not properly set in {file_path}"
            
            else:
                status = 'WARNING'
                message = f"Unknown check type: {check_type}"
        
        except Exception as e:
            status = 'ERROR'
            message = f"Error running check: {str(e)}"
            logger.error(f"Error in check {check_id}: {e}")
        
        return {
            'id': check_id,
            'name': name,
            'description': description,
            'status': status,
            'severity': severity,
            'message': message,
            'remediation': remediation,
            'nrb_reference': nrb_reference,
            'file': file_path
        }
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Run all checks defined in the playbook"""
        results = []
        
        # Process all check sections in the playbook
        check_sections = [
            'pam_checks',
            'login_defs_checks',
            'ssh_checks',
            'sudoers_checks',
            'sysctl_checks',
            'selinux_checks',
            'auditd_checks',
            'audit_rules_checks',
            'rsyslog_checks',
            'logrotate_checks',
            'system_info_checks',
            'users_checks'
        ]
        
        for section in check_sections:
            checks = self.checks_config.get(section, [])
            for check in checks:
                result = self._run_check(check)
                results.append(result)
        
        return results


class OPNsenseFirewallChecker:
    """
    NTA Firewall Security Compliance Checker for OPNsense/pfSense
    Parses OPNsense XML configuration and validates against NTA requirements
    """
    
    def __init__(self, xml_content: str = None, xml_path: str = None, 
                 playbook_path: str = 'playbooks/nta_firewall_opnsense.yml'):
        self.playbook_path = playbook_path
        self.xml_content = xml_content
        self.xml_path = xml_path
        self.xml_root = None
        self.checks_config = self._load_playbook()
        
        if xml_path:
            self._load_xml_file()
        elif xml_content:
            self._parse_xml_content()
    
    def _load_xml_file(self):
        """Load XML from file path"""
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(self.xml_path)
            self.xml_root = tree.getroot()
            logger.info(f"Loaded OPNsense config from: {self.xml_path}")
        except Exception as e:
            logger.error(f"Error loading XML file: {e}")
            raise
    
    def _parse_xml_content(self):
        """Parse XML from string content"""
        try:
            import xml.etree.ElementTree as ET
            self.xml_root = ET.fromstring(self.xml_content)
            logger.info("Parsed OPNsense config from content")
        except Exception as e:
            logger.error(f"Error parsing XML content: {e}")
            raise
    
    def _load_playbook(self) -> Dict[str, Any]:
        """Load check definitions from YAML playbook"""
        try:
            if os.path.exists(self.playbook_path):
                with open(self.playbook_path, 'r') as f:
                    playbook = yaml.safe_load(f)
                    return playbook
            else:
                logger.warning(f"Playbook not found: {self.playbook_path}")
                return {}
        except Exception as e:
            logger.error(f"Error loading playbook: {e}")
            return {}
    
    def _get_xml_value(self, path: str, default: str = None) -> str:
        """Get value from XML path (e.g., 'system/ssh/enabled')"""
        if self.xml_root is None:
            return default
        
        try:
            element = self.xml_root.find(path)
            if element is not None and element.text:
                return element.text.strip()
            return default
        except Exception as e:
            logger.error(f"Error getting XML path {path}: {e}")
            return default
    
    def _get_xml_element(self, path: str):
        """Get XML element at path"""
        if self.xml_root is None:
            return None
        try:
            return self.xml_root.find(path)
        except:
            return None
    
    def _get_all_xml_elements(self, path: str):
        """Get all XML elements matching path"""
        if self.xml_root is None:
            return []
        try:
            return self.xml_root.findall(path)
        except:
            return []
    
    def _check_value_equals(self, path: str, expected: str) -> tuple:
        """Check if XML value equals expected"""
        actual = self._get_xml_value(path)
        if actual is None:
            return False, "Not configured", expected
        passed = actual.lower() == expected.lower()
        return passed, actual, expected
    
    def _check_value_not_equals(self, path: str, forbidden: str) -> tuple:
        """Check if XML value does NOT equal forbidden value"""
        actual = self._get_xml_value(path)
        if actual is None:
            return True, "Not configured", f"Not '{forbidden}'"
        passed = actual.lower() != forbidden.lower()
        return passed, actual, f"Not '{forbidden}'"
    
    def _check_not_empty(self, path: str) -> tuple:
        """Check if XML value is not empty"""
        actual = self._get_xml_value(path)
        passed = actual is not None and actual.strip() != ''
        return passed, actual or "Empty/Not set", "Non-empty value"
    
    def _check_exists(self, path: str) -> tuple:
        """Check if XML element exists"""
        element = self._get_xml_element(path)
        passed = element is not None
        return passed, "Exists" if passed else "Not found", "Element should exist"
    
    def _check_numeric_compare(self, path: str, expected: str, comparison: str) -> tuple:
        """Compare numeric values"""
        actual = self._get_xml_value(path)
        if actual is None:
            return False, "Not configured", f"{comparison} {expected}"
        
        try:
            actual_val = float(actual)
            expected_val = float(expected)
            
            if comparison == '>=':
                passed = actual_val >= expected_val
            elif comparison == '<=':
                passed = actual_val <= expected_val
            elif comparison == '>':
                passed = actual_val > expected_val
            elif comparison == '<':
                passed = actual_val < expected_val
            elif comparison == '==':
                passed = actual_val == expected_val
            else:
                passed = False
            
            return passed, str(actual), f"{comparison} {expected}"
        except ValueError:
            return False, actual, f"{comparison} {expected}"
    
    def _check_contains_value(self, path: str, expected: str) -> tuple:
        """Check if XML value contains expected string"""
        actual = self._get_xml_value(path)
        if actual is None:
            return False, "Not configured", f"Contains '{expected}'"
        passed = expected.lower() in actual.lower()
        return passed, actual, f"Contains '{expected}'"
    
    def _check_value_in_list(self, path: str, expected_values: list) -> tuple:
        """Check if XML value is in expected list"""
        actual = self._get_xml_value(path)
        if actual is None:
            return False, "Not configured", f"One of: {expected_values}"
        passed = actual.lower() in [v.lower() for v in expected_values]
        return passed, actual, f"One of: {expected_values}"
    
    def _check_firewall_rules(self) -> tuple:
        """Evaluate firewall rules configuration"""
        rules = self._get_all_xml_elements('filter/rule')
        if not rules:
            return False, "No rules defined", "Firewall rules configured"
        return True, f"{len(rules)} rules defined", "Firewall rules configured"
    
    def _check_has_deny_rule(self) -> tuple:
        """Check if there's a deny/block rule"""
        rules = self._get_all_xml_elements('filter/rule')
        for rule in rules:
            rule_type = rule.find('type')
            if rule_type is not None and rule_type.text in ['block', 'reject']:
                return True, "Deny rule found", "Deny rule exists"
        # Also check OPNsense filter rules
        rules_opn = self._get_all_xml_elements('OPNsense/Firewall/Filter/rules/rule')
        for rule in rules_opn:
            action = rule.find('action')
            if action is not None and action.text in ['block', 'reject', 'drop']:
                return True, "Deny rule found", "Deny rule exists"
        return False, "No explicit deny rule", "Deny rule should exist"
    
    def _check_rules_have_descriptions(self) -> tuple:
        """Check if firewall rules have descriptions"""
        rules = self._get_all_xml_elements('filter/rule')
        total = len(rules)
        with_desc = 0
        for rule in rules:
            descr = rule.find('descr')
            if descr is not None and descr.text and descr.text.strip():
                with_desc += 1
        
        if total == 0:
            return False, "No rules defined", "All rules have descriptions"
        
        pct = (with_desc / total) * 100
        passed = pct >= 80  # At least 80% of rules should have descriptions
        return passed, f"{with_desc}/{total} rules have descriptions ({pct:.0f}%)", "All rules have descriptions"
    
    def _check_no_any_any_allow(self) -> tuple:
        """Check for overly permissive 'any to any' allow rules"""
        rules = self._get_all_xml_elements('filter/rule')
        overly_permissive = []
        
        for i, rule in enumerate(rules):
            rule_type = rule.find('type')
            if rule_type is None or rule_type.text != 'pass':
                continue
            
            source = rule.find('source')
            dest = rule.find('destination')
            
            source_any = False
            dest_any = False
            
            if source is not None:
                if source.find('any') is not None:
                    source_any = True
                network = source.find('network')
                if network is not None and network.text == 'any':
                    source_any = True
            
            if dest is not None:
                if dest.find('any') is not None:
                    dest_any = True
                network = dest.find('network')
                if network is not None and network.text == 'any':
                    dest_any = True
            
            if source_any and dest_any:
                descr = rule.find('descr')
                rule_desc = descr.text if descr is not None and descr.text else f"Rule {i+1}"
                overly_permissive.append(rule_desc)
        
        if overly_permissive:
            return False, f"Found {len(overly_permissive)} 'any to any' rules", "No 'any to any' allow rules"
        return True, "No 'any to any' allow rules", "No 'any to any' allow rules"
    
    def _check_group_exists(self, group_name: str) -> tuple:
        """Check if a specific group exists"""
        groups = self._get_all_xml_elements('system/group')
        for group in groups:
            name = group.find('name')
            if name is not None and name.text and name.text.lower() == group_name.lower():
                return True, f"Group '{group_name}' exists", f"Group '{group_name}' exists"
        return False, f"Group '{group_name}' not found", f"Group '{group_name}' exists"
    
    def _evaluate_ssh_enabled(self, path: str) -> tuple:
        """Evaluate SSH status - informational check"""
        actual = self._get_xml_value(path)
        if actual == 'enabled' or actual == '1':
            return True, "SSH is enabled (review access controls)", "SSH status evaluated"
        return True, "SSH is disabled", "SSH status evaluated"
    
    def _evaluate_ipv6(self, path: str) -> tuple:
        """Evaluate IPv6 configuration"""
        actual = self._get_xml_value(path)
        if actual == '1':
            return True, "IPv6 is enabled - ensure proper controls", "IPv6 configuration reviewed"
        return True, "IPv6 is disabled", "IPv6 configuration reviewed"
    
    def _evaluate_vpn_status(self, path: str) -> tuple:
        """Evaluate VPN configuration status"""
        actual = self._get_xml_value(path)
        if actual == '1' or actual == 'enabled':
            return True, "VPN is enabled - ensure proper configuration", "VPN status evaluated"
        return True, "VPN is disabled", "VPN status evaluated"
    
    def _evaluate_ha_config(self, path: str) -> tuple:
        """Evaluate High Availability configuration"""
        sync_ip = self._get_xml_value('hasync/synchronizetoip')
        if sync_ip and sync_ip.strip():
            verify_peer = self._get_xml_value(path)
            if verify_peer == '1':
                return True, "HA configured with peer verification", "HA security evaluated"
            return False, "HA configured without peer verification", "Enable peer verification"
        return True, "HA not configured", "HA configuration evaluated"
    
    def _evaluate_captive_portal(self, path: str) -> tuple:
        """Evaluate captive portal configuration"""
        zones = self._get_all_xml_elements('OPNsense/captiveportal/zones/zone')
        if zones:
            return True, f"{len(zones)} captive portal zone(s) configured", "Captive portal reviewed"
        return True, "No captive portal zones configured", "Captive portal reviewed"
    
    def _evaluate_traffic_shaping(self, path: str) -> tuple:
        """Evaluate traffic shaping configuration"""
        rules = self._get_all_xml_elements('OPNsense/TrafficShaper/rules/rule')
        pipes = self._get_all_xml_elements('OPNsense/TrafficShaper/pipes/pipe')
        if rules or pipes:
            return True, f"Traffic shaping configured ({len(rules)} rules, {len(pipes)} pipes)", "Traffic shaping reviewed"
        return True, "No traffic shaping configured", "Traffic shaping reviewed"
    
    def _run_check(self, check: Dict[str, Any]) -> Dict[str, Any]:
        """Run a single check and return result"""
        check_id = check.get('id', 'UNKNOWN')
        name = check.get('name', 'Unnamed check')
        description = check.get('description', '')
        xml_path = check.get('xml_path', '')
        check_type = check.get('check_type', '')
        severity = check.get('severity', 'MEDIUM')
        remediation = check.get('remediation', 'No remediation provided')
        nta_reference = check.get('nta_reference', '')
        
        passed = False
        actual = ''
        expected = ''
        status = 'FAIL'
        
        try:
            if check_type == 'value_equals':
                expected_value = check.get('expected_value', '')
                passed, actual, expected = self._check_value_equals(xml_path, expected_value)
            
            elif check_type == 'value_not_equals':
                forbidden_value = check.get('forbidden_value', '')
                passed, actual, expected = self._check_value_not_equals(xml_path, forbidden_value)
            
            elif check_type == 'not_empty':
                passed, actual, expected = self._check_not_empty(xml_path)
            
            elif check_type == 'not_empty_or_modern':
                passed, actual, expected = self._check_not_empty(xml_path)
                if not passed:
                    # If empty, check if using modern defaults (which is acceptable)
                    passed = True
                    actual = "Using modern defaults"
            
            elif check_type == 'exists':
                passed, actual, expected = self._check_exists(xml_path)
            
            elif check_type == 'numeric_compare':
                expected_value = check.get('expected_value', '')
                comparison = check.get('comparison', '>=')
                passed, actual, expected = self._check_numeric_compare(xml_path, expected_value, comparison)
            
            elif check_type == 'contains_value':
                expected_value = check.get('expected_value', '')
                passed, actual, expected = self._check_contains_value(xml_path, expected_value)
            
            elif check_type == 'value_in_list':
                expected_values = check.get('expected_values', [])
                passed, actual, expected = self._check_value_in_list(xml_path, expected_values)
            
            elif check_type == 'has_deny_rule':
                passed, actual, expected = self._check_has_deny_rule()
            
            elif check_type == 'rules_have_descriptions':
                passed, actual, expected = self._check_rules_have_descriptions()
            
            elif check_type == 'no_any_any_allow':
                passed, actual, expected = self._check_no_any_any_allow()
            
            elif check_type == 'group_exists':
                group_name = check.get('expected_value', 'admins')
                passed, actual, expected = self._check_group_exists(group_name)
            
            elif check_type == 'evaluate_ssh_enabled':
                passed, actual, expected = self._evaluate_ssh_enabled(xml_path)
            
            elif check_type == 'evaluate_ipv6':
                passed, actual, expected = self._evaluate_ipv6(xml_path)
            
            elif check_type == 'evaluate_vpn_status':
                passed, actual, expected = self._evaluate_vpn_status(xml_path)
            
            elif check_type == 'evaluate_ha_config':
                passed, actual, expected = self._evaluate_ha_config(xml_path)
            
            elif check_type == 'evaluate_captive_portal':
                passed, actual, expected = self._evaluate_captive_portal(xml_path)
            
            elif check_type == 'evaluate_traffic_shaping':
                passed, actual, expected = self._evaluate_traffic_shaping(xml_path)
            
            elif check_type == 'evaluate_user_accounts':
                # Informational check
                users = self._get_all_xml_elements('system/user')
                passed = True
                actual = f"{len(users)} user account(s) configured"
                expected = "User accounts reviewed"
            
            else:
                status = 'WARNING'
                actual = f"Unknown check type: {check_type}"
                expected = 'Valid check type'
            
            if status != 'WARNING':
                status = 'PASS' if passed else 'FAIL'
            
        except Exception as e:
            status = 'ERROR'
            actual = f"Error: {str(e)}"
            expected = 'Check should complete'
            logger.error(f"Error in check {check_id}: {e}")
        
        return {
            'id': check_id,
            'name': name,
            'description': description,
            'status': status,
            'severity': severity,
            'actual': actual,
            'expected': expected,
            'remediation': remediation,
            'nta_reference': nta_reference
        }
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        """Run all checks defined in the playbook"""
        results = []
        
        if self.xml_root is None:
            return [{
                'id': 'ERROR',
                'name': 'XML Parse Error',
                'description': 'Failed to parse OPNsense configuration XML',
                'status': 'FAIL',
                'severity': 'CRITICAL',
                'actual': 'Invalid or missing XML',
                'expected': 'Valid OPNsense XML configuration',
                'remediation': 'Ensure you uploaded a valid OPNsense configuration XML file'
            }]
        
        # Process all check sections in the playbook
        check_sections = [
            'management_access_checks',
            'ssh_checks',
            'snmp_checks',
            'ids_checks',
            'logging_checks',
            'firewall_rules_checks',
            'network_checks',
            'vpn_checks',
            'dns_checks',
            'user_checks',
            'hardening_checks',
            'time_checks',
            'ha_checks',
            'captive_portal_checks',
            'traffic_shaping_checks'
        ]
        
        for section in check_sections:
            checks = self.checks_config.get(section, [])
            for check in checks:
                result = self._run_check(check)
                results.append(result)
        
        return results


def check_offline_config(file_content: str = None, compliance_type: str = None, archive_path: str = None) -> Dict[str, Any]:
    """
    Main function to check offline configuration file
    
    Args:
        file_content: Content of the configuration file (for single file checks)
        compliance_type: Type of compliance check (e.g., 'ubuntu_sshd', 'nrb_rhel')
        archive_path: Path to tar.gz archive (for multi-file checks like NRB)
    
    Returns:
        Dictionary with check results in format compatible with audit_results_storage
    """
    
    if compliance_type == 'ubuntu_sshd':
        checker = SSHDConfigChecker(file_content)
        checks = checker.run_all_checks()
        
        # Calculate statistics
        total_checks = len(checks)
        passed_checks = len([c for c in checks if c['status'] == 'PASS'])
        failed_checks = len([c for c in checks if c['status'] == 'FAIL'])
        warning_checks = len([c for c in checks if c['status'] == 'WARNING'])
        
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        return {
            'success': True,
            'compliance_type': compliance_type,
            'total_checks': total_checks,
            'passed': passed_checks,
            'failed': failed_checks,
            'warnings': warning_checks,
            'compliance_percentage': round(compliance_percentage, 2),
            'checks': checks,
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    elif compliance_type == 'nrb_rhel':
        if not archive_path:
            return {
                'success': False,
                'error': 'Archive path is required for NRB RHEL compliance checks',
                'checks': []
            }
        
        checker = NRBConfigChecker(archive_path=archive_path)
        checks = checker.run_all_checks()
        
        # Calculate statistics
        total_checks = len(checks)
        passed_checks = len([c for c in checks if c['status'] == 'PASS'])
        failed_checks = len([c for c in checks if c['status'] == 'FAIL'])
        warning_checks = len([c for c in checks if c['status'] == 'WARNING'])
        error_checks = len([c for c in checks if c['status'] == 'ERROR'])
        
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        # Count by severity
        critical_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'CRITICAL'])
        high_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'HIGH'])
        medium_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'MEDIUM'])
        low_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'LOW'])
        
        return {
            'success': True,
            'compliance_type': compliance_type,
            'total_checks': total_checks,
            'passed': passed_checks,
            'failed': failed_checks,
            'warnings': warning_checks,
            'errors': error_checks,
            'compliance_percentage': round(compliance_percentage, 2),
            'severity_breakdown': {
                'critical': critical_fails,
                'high': high_fails,
                'medium': medium_fails,
                'low': low_fails
            },
            'checks': checks,
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    elif compliance_type == 'nrb_cyber_resilience':
        if not archive_path:
            return {
                'success': False,
                'error': 'Archive path is required for NRB Cyber Resilience compliance checks',
                'checks': []
            }
        
        checker = NRBConfigChecker(archive_path=archive_path, playbook_path='playbooks/nrb_cyber_resilience.yml')
        checks = checker.run_all_checks()
        
        # Calculate statistics
        total_checks = len(checks)
        passed_checks = len([c for c in checks if c['status'] == 'PASS'])
        failed_checks = len([c for c in checks if c['status'] == 'FAIL'])
        warning_checks = len([c for c in checks if c['status'] == 'WARNING'])
        error_checks = len([c for c in checks if c['status'] == 'ERROR'])
        
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        # Count by severity
        critical_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'CRITICAL'])
        high_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'HIGH'])
        medium_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'MEDIUM'])
        low_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'LOW'])
        
        return {
            'success': True,
            'compliance_type': compliance_type,
            'total_checks': total_checks,
            'passed': passed_checks,
            'failed': failed_checks,
            'warnings': warning_checks,
            'errors': error_checks,
            'compliance_percentage': round(compliance_percentage, 2),
            'severity_breakdown': {
                'critical': critical_fails,
                'high': high_fails,
                'medium': medium_fails,
                'low': low_fails
            },
            'checks': checks,
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    elif compliance_type == 'nta_cyber_byelaw_2020':
        if not archive_path:
            return {
                'success': False,
                'error': 'Archive path is required for NTA Cyber Byelaw 2020 compliance checks',
                'checks': []
            }
        
        checker = NRBConfigChecker(archive_path=archive_path, playbook_path='playbooks/nta_cyber_byelaw_2020.yml')
        checks = checker.run_all_checks()
        
        # Calculate statistics
        total_checks = len(checks)
        passed_checks = len([c for c in checks if c['status'] == 'PASS'])
        failed_checks = len([c for c in checks if c['status'] == 'FAIL'])
        warning_checks = len([c for c in checks if c['status'] == 'WARNING'])
        error_checks = len([c for c in checks if c['status'] == 'ERROR'])
        
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        # Count by severity
        critical_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'CRITICAL'])
        high_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'HIGH'])
        medium_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'MEDIUM'])
        low_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'LOW'])
        
        return {
            'success': True,
            'compliance_type': compliance_type,
            'total_checks': total_checks,
            'passed': passed_checks,
            'failed': failed_checks,
            'warnings': warning_checks,
            'errors': error_checks,
            'compliance_percentage': round(compliance_percentage, 2),
            'severity_breakdown': {
                'critical': critical_fails,
                'high': high_fails,
                'medium': medium_fails,
                'low': low_fails
            },
            'checks': checks,
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    elif compliance_type == 'nta_firewall_opnsense':
        # For OPNsense firewall, expect a single XML file
        if not file_content:
            return {
                'success': False,
                'error': 'XML file content is required for NTA Firewall OPNsense compliance checks',
                'checks': []
            }
        
        try:
            checker = OPNsenseFirewallChecker(
                xml_content=file_content, 
                playbook_path='playbooks/nta_firewall_opnsense.yml'
            )
            checks = checker.run_all_checks()
        except Exception as e:
            return {
                'success': False,
                'error': f'Error parsing OPNsense XML configuration: {str(e)}',
                'checks': []
            }
        
        # Calculate statistics
        total_checks = len(checks)
        passed_checks = len([c for c in checks if c['status'] == 'PASS'])
        failed_checks = len([c for c in checks if c['status'] == 'FAIL'])
        warning_checks = len([c for c in checks if c['status'] == 'WARNING'])
        error_checks = len([c for c in checks if c['status'] == 'ERROR'])
        
        compliance_percentage = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        # Count by severity
        critical_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'CRITICAL'])
        high_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'HIGH'])
        medium_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'MEDIUM'])
        low_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'LOW'])
        info_fails = len([c for c in checks if c['status'] == 'FAIL' and c.get('severity') == 'INFO'])
        
        return {
            'success': True,
            'compliance_type': compliance_type,
            'device_type': 'OPNsense/pfSense Firewall',
            'total_checks': total_checks,
            'passed': passed_checks,
            'failed': failed_checks,
            'warnings': warning_checks,
            'errors': error_checks,
            'compliance_percentage': round(compliance_percentage, 2),
            'severity_breakdown': {
                'critical': critical_fails,
                'high': high_fails,
                'medium': medium_fails,
                'low': low_fails,
                'info': info_fails
            },
            'checks': checks,
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    else:
        return {
            'success': False,
            'error': f'Unknown compliance type: {compliance_type}',
            'checks': []
        }


def compare_reports(audit_id_1: str, audit_id_2: str) -> Dict[str, Any]:
    """
    Compare two audit reports and return the differences
    
    Args:
        audit_id_1: First audit ID (baseline)
        audit_id_2: Second audit ID (comparison)
    
    Returns:
        Dictionary containing comparison results with differences, improvements, and regressions
    """
    logger.info(f"Comparing reports: {audit_id_1} vs {audit_id_2}")
    
    # Retrieve both audits
    with storage_lock:
        audit1 = audit_results_storage.get(audit_id_1)
        audit2 = audit_results_storage.get(audit_id_2)
    
    # Validate both audits exist
    if not audit1:
        return {
            'success': False,
            'error': f'Audit {audit_id_1} not found'
        }
    
    if not audit2:
        return {
            'success': False,
            'error': f'Audit {audit_id_2} not found'
        }
    
    # Validate both audits are completed
    if audit1.status != 'completed':
        return {
            'success': False,
            'error': f'Audit {audit_id_1} is not completed (status: {audit1.status})'
        }
    
    if audit2.status != 'completed':
        return {
            'success': False,
            'error': f'Audit {audit_id_2} is not completed (status: {audit2.status})'
        }
    
    # CRITICAL: Validate both audits use the same playbook
    playbook1 = audit1.playbook_used or f"cis_audit_{audit1.level}.yml"
    playbook2 = audit2.playbook_used or f"cis_audit_{audit2.level}.yml"
    
    if playbook1 != playbook2:
        return {
            'success': False,
            'error': 'Cannot compare reports generated from different playbooks',
            'details': {
                'audit1_playbook': playbook1,
                'audit2_playbook': playbook2,
                'message': 'Reports must be generated using the same compliance standard/playbook for meaningful comparison'
            }
        }
    
    # Calculate metrics for both audits
    def calculate_metrics(audit):
        total = len(audit.results)
        passed = len([r for r in audit.results if 'PASS' in r.get('status', '')])
        failed = len([r for r in audit.results if 'FAIL' in r.get('status', '')])
        warnings = len([r for r in audit.results if 'WARNING' in r.get('status', '')])
        compliance_pct = round((passed / total * 100), 2) if total > 0 else 0
        
        return {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'compliance_percentage': compliance_pct
        }
    
    metrics1 = calculate_metrics(audit1)
    metrics2 = calculate_metrics(audit2)
    
    # Create check lookup dictionaries
    checks1_dict = {r.get('check', ''): r for r in audit1.results}
    checks2_dict = {r.get('check', ''): r for r in audit2.results}
    
    # Find all unique checks
    all_checks = set(checks1_dict.keys()) | set(checks2_dict.keys())
    
    # Categorize differences
    improvements = []  # FAIL -> PASS or new PASS
    regressions = []   # PASS -> FAIL or new FAIL
    unchanged = []     # Same status
    new_checks = []    # Only in audit 2
    removed_checks = [] # Only in audit 1
    
    for check in sorted(all_checks):
        check1 = checks1_dict.get(check)
        check2 = checks2_dict.get(check)
        
        if not check1:
            # New check in audit 2
            new_checks.append({
                'check': check,
                'status': check2.get('status', 'UNKNOWN'),
                'remediation': check2.get('remediation', '')
            })
        elif not check2:
            # Check removed in audit 2
            removed_checks.append({
                'check': check,
                'status': check1.get('status', 'UNKNOWN'),
                'remediation': check1.get('remediation', '')
            })
        else:
            # Check exists in both - compare status
            status1 = check1.get('status', '')
            status2 = check2.get('status', '')
            
            if status1 == status2:
                unchanged.append({
                    'check': check,
                    'status': status1,
                    'remediation': check2.get('remediation', '')
                })
            else:
                # Status changed
                change_entry = {
                    'check': check,
                    'status_before': status1,
                    'status_after': status2,
                    'remediation': check2.get('remediation', '')
                }
                
                # Determine if improvement or regression
                is_improvement = (
                    ('FAIL' in status1 and 'PASS' in status2) or
                    ('WARNING' in status1 and 'PASS' in status2)
                )
                is_regression = (
                    ('PASS' in status1 and 'FAIL' in status2) or
                    ('PASS' in status1 and 'WARNING' in status2)
                )
                
                if is_improvement:
                    improvements.append(change_entry)
                elif is_regression:
                    regressions.append(change_entry)
                else:
                    unchanged.append(change_entry)
    
    # Calculate change metrics
    compliance_change = metrics2['compliance_percentage'] - metrics1['compliance_percentage']
    passed_change = metrics2['passed'] - metrics1['passed']
    failed_change = metrics2['failed'] - metrics1['failed']
    
    return {
        'success': True,
        'playbook': playbook1,
        'audit1': {
            'audit_id': audit_id_1,
            'ip': audit1.ip,
            'timestamp': audit1.start_time.isoformat() if audit1.start_time else None,
            'metrics': metrics1
        },
        'audit2': {
            'audit_id': audit_id_2,
            'ip': audit2.ip,
            'timestamp': audit2.start_time.isoformat() if audit2.start_time else None,
            'metrics': metrics2
        },
        'changes': {
            'compliance_change': compliance_change,
            'passed_change': passed_change,
            'failed_change': failed_change
        },
        'differences': {
            'improvements': improvements,
            'regressions': regressions,
            'unchanged': unchanged,
            'new_checks': new_checks,
            'removed_checks': removed_checks
        },
        'summary': {
            'total_improvements': len(improvements),
            'total_regressions': len(regressions),
            'total_unchanged': len(unchanged),
            'total_new_checks': len(new_checks),
            'total_removed_checks': len(removed_checks)
        }
    }
