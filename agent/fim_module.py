#!/usr/bin/env python3
"""
File Integrity Monitoring (FIM) Module
Detects unauthorized file changes across the system
"""

import os
import hashlib
import json
import time
import socket
import stat
import pwd
import grp
from datetime import datetime

# ════════════════════════════════════════════════════════════
#  CONFIGURATION - CHANGE THIS!
# ════════════════════════════════════════════════════════════

# Load environment variables if .env exists
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    if os.path.exists(_env_path):
        load_dotenv(_env_path)
except ImportError:
    pass

SIEM_SERVER_IP = os.getenv("SIEM_SERVER_IP", "100.90.174.77")
SIEM_SERVER_PORT = int(os.getenv("SIEM_SERVER_PORT", "9999"))
AGENT_ID = os.getenv("AGENT_ID", "omen-kali")

# Files and directories to monitor
WATCH_PATHS = [
    "/etc/passwd",           # User accounts
    "/etc/shadow",           # Passwords
    "/etc/sudoers",          # Sudo permissions
    "/etc/hosts",            # Host mappings
    "/etc/ssh/sshd_config",  # SSH config
    "/etc/crontab",          # Scheduled tasks
    "/etc/group",            # Group accounts
    "/root/.ssh/",           # SSH keys
    "/home/",                # User home directories
    "/bin/",                 # System binaries
    "/sbin/",                # System binaries
    "/usr/bin/",             # User binaries
    "/usr/sbin/",            # User binaries
]

EXCLUDE_EXTENSIONS = ['.pyc', '.log', '.tmp', '.swp', '.cache', '.old', '.bak']
EXCLUDE_DIRS = ['/proc', '/sys', '/dev', '/run', '/tmp']

SCAN_INTERVAL = 60  # Seconds between scans
BASELINE_FILE = f"/tmp/fim_baseline_{AGENT_ID}.json"

# ════════════════════════════════════════════════════════════

def get_file_hash(filepath, algorithm="sha256"):
    try:
        h = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return "UNREADABLE"

def get_file_metadata(filepath):
    try:
        s = os.stat(filepath)
        return {
            "hash": get_file_hash(filepath),
            "size": s.st_size,
            "permissions": oct(stat.S_IMODE(s.st_mode)),
            "owner": pwd.getpwuid(s.st_uid).pw_name,
            "group": grp.getgrgid(s.st_gid).gr_name,
            "mtime": s.st_mtime,
            "ctime": s.st_ctime,
        }
    except Exception as e:
        return None

def is_excluded(path):
    for ex_dir in EXCLUDE_DIRS:
        if path.startswith(ex_dir):
            return True
    _, ext = os.path.splitext(path)
    return ext in EXCLUDE_EXTENSIONS

def scan_directory(base_path):
    file_data = {}
    
    if os.path.isfile(base_path):
        if not is_excluded(base_path):
            meta = get_file_metadata(base_path)
            if meta:
                file_data[base_path] = meta
        return file_data
    
    if not os.path.isdir(base_path):
        return file_data
    
    try:
        for root, dirs, files in os.walk(base_path, followlinks=False):
            dirs[:] = [d for d in dirs if not is_excluded(os.path.join(root, d))]
            for fname in files:
                fpath = os.path.join(root, fname)
                if is_excluded(fpath):
                    continue
                meta = get_file_metadata(fpath)
                if meta:
                    file_data[fpath] = meta
    except PermissionError:
        pass
    
    return file_data

def load_baseline():
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_baseline(baseline):
    try:
        with open(BASELINE_FILE, 'w') as f:
            json.dump(baseline, f, indent=2)
        return True
    except Exception as e:
        print(f"[FIM] Error saving baseline: {e}")
        return False

def compare_baselines(old_baseline, new_baseline):
    changes = []
    all_files = set(old_baseline.keys()) | set(new_baseline.keys())
    
    for fpath in all_files:
        old = old_baseline.get(fpath)
        new = new_baseline.get(fpath)
        
        if old is None and new is not None:
            changes.append(("CREATED", fpath, "", new.get("hash", ""), 
                          new.get("size", 0), new.get("permissions", ""), 
                          new.get("owner", ""), new.get("group", "")))
        elif old is not None and new is None:
            changes.append(("DELETED", fpath, old.get("hash", ""), "",
                          0, "", "", ""))
        elif old is not None and new is not None:
            if old.get("hash") != new.get("hash"):
                changes.append(("MODIFIED", fpath, old.get("hash", ""), new.get("hash", ""),
                              new.get("size", 0), new.get("permissions", ""),
                              new.get("owner", ""), new.get("group", "")))
            elif old.get("permissions") != new.get("permissions"):
                changes.append(("PERM_CHANGE", fpath, old.get("hash", ""), new.get("hash", ""),
                              new.get("size", 0), new.get("permissions", ""),
                              new.get("owner", ""), new.get("group", "")))
            elif old.get("owner") != new.get("owner"):
                changes.append(("OWNER_CHANGE", fpath, old.get("hash", ""), new.get("hash", ""),
                              new.get("size", 0), new.get("permissions", ""),
                              new.get("owner", ""), new.get("group", "")))
    
    return changes

def get_severity(filepath, event_type):
    critical_paths = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/"]
    for crit in critical_paths:
        if crit in filepath:
            return "CRITICAL"
    if event_type == "DELETED":
        return "CRITICAL"
    important_paths = ["/etc/", "/bin/", "/sbin/", "/usr/bin/", "/root/"]
    for imp in important_paths:
        if filepath.startswith(imp):
            return "HIGH"
    return "MEDIUM"

def send_fim_event(event_type, filepath, old_hash="", new_hash="",
                   size=0, permissions="", owner="", group=""):
    severity = get_severity(filepath, event_type)
    
    payload = {
        "data_type": "fim",
        "timestamp": datetime.utcnow().isoformat(),
        "agent_id": AGENT_ID,
        "event_type": event_type,
        "file_path": filepath,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "file_size": size,
        "permissions": permissions,
        "owner": owner,
        "group": group,
        "severity": severity
    }
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((SIEM_SERVER_IP, SIEM_SERVER_PORT))
            s.sendall(json.dumps(payload).encode() + b'\n')
        return True
    except Exception as e:
        print(f"[FIM] Error sending event: {e}")
        return False

def initial_baseline_scan():
    print(f"[FIM] Starting INITIAL baseline scan on {AGENT_ID}...")
    print(f"[FIM] Monitoring {len(WATCH_PATHS)} paths")
    
    baseline = {}
    total_files = 0
    
    for path in WATCH_PATHS:
        if os.path.exists(path):
            print(f"[FIM] Scanning: {path}")
            scan_data = scan_directory(path)
            baseline.update(scan_data)
            total_files += len(scan_data)
    
    save_baseline(baseline)
    print(f"[FIM] ✅ Baseline created: {total_files} files monitored")
    return baseline

def fim_scan_loop():
    print("╔════════════════════════════════════════════════════╗")
    print("║      🛡️  FILE INTEGRITY MONITORING (FIM)        ║")
    print("╠════════════════════════════════════════════════════╣")
    print(f"║  Agent:      {AGENT_ID}")
    print(f"║  Server:     {SIEM_SERVER_IP}:{SIEM_SERVER_PORT}")
    print(f"║  Scan Interval: {SCAN_INTERVAL}s")
    print(f"║  Watch Paths: {len(WATCH_PATHS)}")
    print("╚════════════════════════════════════════════════════╝")
    
    baseline = load_baseline()
    
    if not baseline:
        baseline = initial_baseline_scan()
    else:
        print(f"[FIM] Loaded existing baseline: {len(baseline)} files")
        print("[FIM] Running initial comparison...")
        
        current_scan = {}
        for path in WATCH_PATHS:
            if os.path.exists(path):
                current_scan.update(scan_directory(path))
        
        changes = compare_baselines(baseline, current_scan)
        
        if changes:
            print(f"[FIM] ⚠️  {len(changes)} changes detected!")
            for change in changes:
                event_type, fpath, old_h, new_h, size, perms, owner, group = change
                print(f"[FIM] {event_type}: {fpath}")
                send_fim_event(event_type, fpath, old_h, new_h, size, perms, owner, group)
        else:
            print("[FIM] ✅ No changes detected")
        
        baseline = current_scan
        save_baseline(baseline)
    
    print(f"\n[FIM] Starting continuous monitoring (every {SCAN_INTERVAL}s)...\n")
    
    while True:
        try:
            time.sleep(SCAN_INTERVAL)
            current_scan = {}
            for path in WATCH_PATHS:
                if os.path.exists(path):
                    current_scan.update(scan_directory(path))
            
            changes = compare_baselines(baseline, current_scan)
            
            if changes:
                print(f"\n[FIM] ⚠️  {len(changes)} changes detected at {datetime.now().strftime('%H:%M:%S')}")
                for change in changes:
                    event_type, fpath, old_h, new_h, size, perms, owner, group = change
                    print(f"[FIM]   {event_type}: {fpath}")
                    send_fim_event(event_type, fpath, old_h, new_h, size, perms, owner, group)
            
            baseline = current_scan
            save_baseline(baseline)
            
        except KeyboardInterrupt:
            print("\n[FIM] Stopped by user")
            break
        except Exception as e:
            print(f"[FIM] Error in scan loop: {e}")
            time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    fim_scan_loop()