#!/usr/bin/env python3
"""
Activity Logger for Nirikshan

I built this module to keep track of everything that happens in my GRC platform.
It logs user logins, audit activities, report generation - basically everything.
All logs are stored in JSON format which makes them easy to query and display.

Author: Me
Project: Nirikshan (Final Year Project)
"""

import json
import os
from datetime import datetime
from threading import Lock
from typing import Dict, List, Optional

# Where I store the activity logs
LOG_FILE = "logs/activity.json"
LOG_LOCK = Lock()

class ActivityLogger:
    """
    This class handles all the activity logging for my application.
    I made it thread-safe so multiple requests can log at the same time.
    """
    
    def __init__(self, log_file: str = LOG_FILE):
        self.log_file = log_file
        self.lock = LOG_LOCK
        self._ensure_log_file_exists()
    
    def _ensure_log_file_exists(self):
        """Make sure the log file and its directory exist before we try to write"""
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                json.dump([], f)
    
    def log_activity(
        self, 
        user: str, 
        action: str, 
        details: str = "", 
        status: str = "info",
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Records an activity to my JSON log file.
        
        I use this for tracking:
        - User logins/logouts
        - When audits start and complete
        - Report generation
        - User account changes
        
        Returns True if logging worked, False if something went wrong.
        """
        try:
            with self.lock:
                # Load existing logs from the file
                logs = self._read_logs()
                
                # Create the new log entry with timestamp
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "user": user,
                    "action": action,
                    "details": details,
                    "status": status,
                    "ip_address": ip_address
                }
                
                # Add it to the list and save
                logs.append(log_entry)
                
                with open(self.log_file, 'w') as f:
                    json.dump(logs, f, indent=2)
                
                return True
                
        except Exception as e:
            print(f"Error logging activity: {str(e)}")
            return False
    
    def _read_logs(self) -> List[Dict]:
        """Loads all the logs from my JSON file"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"Error reading logs: {str(e)}")
            return []
    
    def get_all_logs(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Retrieve all activity logs
        
        Args:
            limit: Optional limit on number of logs to return (most recent first)
        
        Returns:
            List of log entries
        """
        with self.lock:
            logs = self._read_logs()
            
            # Sort by timestamp (newest first)
            logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            if limit:
                logs = logs[:limit]
            
            return logs
    
    def get_logs_by_user(self, username: str) -> List[Dict]:
        """Get all logs for a specific user"""
        with self.lock:
            logs = self._read_logs()
            return [log for log in logs if log.get('user') == username]
    
    def get_logs_by_action(self, action: str) -> List[Dict]:
        """Get all logs for a specific action type"""
        with self.lock:
            logs = self._read_logs()
            return [log for log in logs if action.lower() in log.get('action', '').lower()]
    
    def get_logs_by_date_range(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Get logs within a date range"""
        with self.lock:
            logs = self._read_logs()
            filtered = []
            
            for log in logs:
                try:
                    log_date = datetime.fromisoformat(log.get('timestamp', ''))
                    if start_date <= log_date <= end_date:
                        filtered.append(log)
                except:
                    continue
            
            return filtered
    
    def clear_all_logs(self) -> bool:
        """
        Clear all activity logs (DANGEROUS - requires admin privileges)
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with self.lock:
                # Keep a backup before clearing
                logs = self._read_logs()
                if logs:
                    backup_file = f"logs/activity_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(backup_file, 'w') as f:
                        json.dump(logs, f, indent=2)
                    print(f"Backup created at: {backup_file}")
                
                # Clear the main log file
                with open(self.log_file, 'w') as f:
                    json.dump([], f)
                
                return True
                
        except Exception as e:
            print(f"Error clearing logs: {str(e)}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get statistics about the activity logs"""
        with self.lock:
            logs = self._read_logs()
            
            if not logs:
                return {
                    "total_activities": 0,
                    "unique_users": 0,
                    "action_breakdown": {},
                    "status_breakdown": {}
                }
            
            # Calculate statistics
            unique_users = set(log.get('user', 'Unknown') for log in logs)
            
            action_breakdown = {}
            status_breakdown = {}
            
            for log in logs:
                action = log.get('action', 'Unknown')
                status = log.get('status', 'info')
                
                action_breakdown[action] = action_breakdown.get(action, 0) + 1
                status_breakdown[status] = status_breakdown.get(status, 0) + 1
            
            return {
                "total_activities": len(logs),
                "unique_users": len(unique_users),
                "action_breakdown": action_breakdown,
                "status_breakdown": status_breakdown
            }


# Global logger instance
logger = ActivityLogger()


# Convenience functions for common logging actions
def log_login(username: str, success: bool = True, ip_address: str = None):
    """Log a login attempt"""
    status = "success" if success else "failed"
    action = "Login" if success else "Login Failed"
    details = f"User logged in successfully" if success else "Failed login attempt"
    logger.log_activity(username, action, details, status, ip_address)


def log_logout(username: str):
    """Log a logout"""
    logger.log_activity(username, "Logout", "User logged out", "info")


def log_audit_start(username: str, target_ip: str, os_type: str, level: str):
    """Log the start of an audit"""
    details = f"Started audit on {target_ip} (OS: {os_type}, Level: {level})"
    logger.log_activity(username, "Audit Started", details, "info", target_ip)


def log_audit_complete(username: str, target_ip: str, success: bool = True):
    """Log audit completion"""
    status = "success" if success else "failed"
    action = "Audit Completed" if success else "Audit Failed"
    details = f"Audit on {target_ip} {'completed successfully' if success else 'failed'}"
    logger.log_activity(username, action, details, status, target_ip)


def log_user_created(admin_user: str, new_user: str, role: str):
    """Log user creation"""
    details = f"Created new user '{new_user}' with role '{role}'"
    logger.log_activity(admin_user, "User Created", details, "success")


def log_user_deleted(admin_user: str, deleted_user: str):
    """Log user deletion"""
    details = f"Deleted user '{deleted_user}'"
    logger.log_activity(admin_user, "User Deleted", details, "success")


def log_report_generated(username: str, target_ip: str, format_type: str):
    """Log report generation"""
    details = f"Generated {format_type.upper()} report for {target_ip}"
    logger.log_activity(username, "Report Generated", details, "success", target_ip)


def log_batch_audit(username: str, file_name: str, target_count: int):
    """Log batch audit upload"""
    details = f"Uploaded batch file '{file_name}' with {target_count} targets"
    logger.log_activity(username, "Batch Audit Started", details, "info")


def log_schedule_created(username: str, file_name: str, scheduled_time: str):
    """Log scheduled audit creation"""
    details = f"Scheduled audit for '{file_name}' at {scheduled_time}"
    logger.log_activity(username, "Audit Scheduled", details, "success")


if __name__ == "__main__":
    # Test the logger
    print("Testing Activity Logger...")
    
    log_login("admin", True, "192.168.1.100")
    log_audit_start("admin", "192.168.1.50", "Linux", "Level 1")
    log_audit_complete("admin", "192.168.1.50", True)
    log_user_created("admin", "testuser", "Staff")
    
    print("\nAll logs:")
    logs = logger.get_all_logs()
    for log in logs:
        print(f"  {log['timestamp']} - {log['user']}: {log['action']} - {log['details']}")
    
    print(f"\nTotal logs: {len(logs)}")
    print("\nStatistics:")
    stats = logger.get_statistics()
    print(json.dumps(stats, indent=2))
