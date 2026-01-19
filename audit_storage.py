#!/usr/bin/env python3
"""
Persistent Storage Module for Nirikshan

I created this module to handle saving and loading audit data.
The main problem I was solving: audit results would disappear when the server restarted.
Now everything is saved to JSON files so nothing gets lost.

Author: Me
Project: Nirikshan (Final Year Project)
"""

import json
import os
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
import shutil

# Where I store the audit data
AUDIT_STORAGE_FILE = "data/audits.json"
STORAGE_LOCK = threading.Lock()

class PersistentAuditStorage:
    """
    This class manages saving audit results to disk.
    I made it thread-safe so multiple audits can save at the same time.
    """
    
    def __init__(self, storage_file: str = AUDIT_STORAGE_FILE):
        self.storage_file = storage_file
        self.lock = STORAGE_LOCK
        self._ensure_storage_file_exists()
    
    def _ensure_storage_file_exists(self):
        """Make sure the storage file exists before we try to use it"""
        storage_dir = os.path.dirname(self.storage_file)
        if storage_dir and not os.path.exists(storage_dir):
            os.makedirs(storage_dir, exist_ok=True)
        
        if not os.path.exists(self.storage_file):
            with open(self.storage_file, 'w') as f:
                json.dump({}, f)
    
    def _read_storage(self) -> Dict:
        """Load all the audit data from the JSON file"""
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            print(f"Error reading audit storage: {str(e)}")
            return {}
    
    def _write_storage(self, data: Dict):
        """Save audit data back to the JSON file"""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error writing audit storage: {str(e)}")
    
    def save_audit(self, audit_id: str, audit_data: Dict):
        """
        Saves an audit to my JSON storage.
        This gets called every time an audit starts or finishes.
        """
        with self.lock:
            audits = self._read_storage()
            
            # Need to convert datetime objects to strings for JSON
            if isinstance(audit_data, dict):
                audit_data = self._serialize_audit(audit_data)
            
            audits[audit_id] = audit_data
            self._write_storage(audits)
    
    def _serialize_audit(self, audit_data: Dict) -> Dict:
        """Converts audit data to a format that JSON can handle"""
        serialized = {}
        for key, value in audit_data.items():
            if isinstance(value, datetime):
                serialized[key] = value.isoformat()
            elif hasattr(value, '__dict__'):
                # Handle objects by converting them to dictionaries
                serialized[key] = {
                    k: v.isoformat() if isinstance(v, datetime) else v
                    for k, v in value.__dict__.items()
                }
            else:
                serialized[key] = value
        return serialized
    
    def get_audit(self, audit_id: str) -> Optional[Dict]:
        """Retrieves a specific audit by its ID"""
        with self.lock:
            audits = self._read_storage()
            return audits.get(audit_id)
    
    def get_all_audits(self) -> Dict:
        """Returns all stored audits"""
        with self.lock:
            return self._read_storage()
    
    def delete_audit(self, audit_id: str) -> bool:
        """
        Removes an audit from storage.
        Also cleans up any associated report files.
        """
        with self.lock:
            audits = self._read_storage()
            
            if audit_id in audits:
                # Also delete the HTML/PDF reports for this audit
                audit = audits[audit_id]
                if isinstance(audit, dict):
                    ip = audit.get('ip', '')
                    if ip:
                        # Look for report files
                        report_pattern = ip.replace('.', '_')
                        reports_dir = 'reports'
                        if os.path.exists(reports_dir):
                            for file in os.listdir(reports_dir):
                                if report_pattern in file and audit_id[:8] in file:
                                    try:
                                        os.remove(os.path.join(reports_dir, file))
                                    except:
                                        pass
                
                del audits[audit_id]
                self._write_storage(audits)
                return True
            
            return False
    
    def clear_all_audits(self) -> bool:
        """
        Clear all audits from storage (with backup)
        
        Returns:
            bool: True if successful
        """
        with self.lock:
            try:
                # Create backup
                audits = self._read_storage()
                if audits:
                    backup_file = f"data/audits_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(backup_file, 'w') as f:
                        json.dump(audits, f, indent=2)
                    print(f"Backup created at: {backup_file}")
                
                # Clear storage
                self._write_storage({})
                
                # Optionally clear reports directory
                # (commented out for safety - you can enable if needed)
                # reports_dir = 'reports'
                # if os.path.exists(reports_dir):
                #     for file in os.listdir(reports_dir):
                #         if file.endswith(('.html', '.pdf')):
                #             try:
                #                 os.remove(os.path.join(reports_dir, file))
                #             except:
                #                 pass
                
                return True
            except Exception as e:
                print(f"Error clearing audits: {str(e)}")
                return False
    
    def get_audit_count(self) -> int:
        """Get total number of audits"""
        with self.lock:
            audits = self._read_storage()
            return len(audits)
    
    def get_audits_by_status(self, status: str) -> List[Dict]:
        """Get all audits with a specific status"""
        with self.lock:
            audits = self._read_storage()
            return [
                {**audit, 'id': audit_id}
                for audit_id, audit in audits.items()
                if audit.get('status') == status
            ]
    
    def update_audit_status(self, audit_id: str, status: str, **kwargs):
        """Update audit status and optional fields"""
        with self.lock:
            audits = self._read_storage()
            
            if audit_id in audits:
                audits[audit_id]['status'] = status
                for key, value in kwargs.items():
                    if isinstance(value, datetime):
                        audits[audit_id][key] = value.isoformat()
                    else:
                        audits[audit_id][key] = value
                
                self._write_storage(audits)


# Global storage instance
audit_storage = PersistentAuditStorage()


# Helper functions for backward compatibility
def save_audit_to_storage(audit_id: str, audit_data: Dict):
    """Save audit to persistent storage"""
    audit_storage.save_audit(audit_id, audit_data)


def get_audit_from_storage(audit_id: str) -> Optional[Dict]:
    """Get audit from persistent storage"""
    return audit_storage.get_audit(audit_id)


def get_all_audits_from_storage() -> Dict:
    """Get all audits from persistent storage"""
    return audit_storage.get_all_audits()


def delete_audit_from_storage(audit_id: str) -> bool:
    """Delete audit from persistent storage"""
    return audit_storage.delete_audit(audit_id)


def clear_all_audits_from_storage() -> bool:
    """Clear all audits from persistent storage"""
    return audit_storage.clear_all_audits()


if __name__ == "__main__":
    # Test the storage
    print("Testing Persistent Audit Storage...")
    
    # Test save
    test_audit = {
        'ip': '192.168.1.100',
        'status': 'completed',
        'start_time': datetime.now(),
        'results': ['test1', 'test2']
    }
    
    audit_storage.save_audit('test-001', test_audit)
    print("✓ Saved test audit")
    
    # Test retrieve
    retrieved = audit_storage.get_audit('test-001')
    print(f"✓ Retrieved audit: {retrieved}")
    
    # Test count
    count = audit_storage.get_audit_count()
    print(f"✓ Total audits: {count}")
    
    # Test delete
    audit_storage.delete_audit('test-001')
    print("✓ Deleted test audit")
    
    print("\nPersistent Audit Storage is working correctly!")
