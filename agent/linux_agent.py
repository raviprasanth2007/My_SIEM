#!/usr/bin/env python3
"""
SIEM Agent for Kali Linux - Log Collector
"""

import socket
import time
import json
import os
import platform
import subprocess
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
HOSTNAME = platform.node()
VERSION = "2.0.0"

LOG_FILES = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "/var/log/dpkg.log",
]

# ════════════════════════════════════════════════════════════

def get_last_n_lines(filepath, n=15):
    try:
        result = subprocess.run(["tail", f"-{n}", filepath], capture_output=True, text=True, timeout=5)
        return result.stdout.strip().split('\n')
    except:
        return []

def get_network_connections():
    try:
        result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=5)
        return result.stdout[:800]
    except:
        return ""

def get_running_processes():
    try:
        result = subprocess.run(["ps", "aux", "--sort=-%mem"], capture_output=True, text=True, timeout=5)
        return result.stdout[:500]
    except:
        return ""

def get_logged_in_users():
    try:
        result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        return result.stdout.strip()
    except:
        return ""

def send_heartbeat():
    """Send heartbeat to keep agent status alive"""
    payload = {
        "data_type": "heartbeat",
        "agent_id": AGENT_ID,
        "hostname": HOSTNAME,
        "os": "linux",
        "version": VERSION,
        "timestamp": datetime.utcnow().isoformat()
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((SIEM_SERVER_IP, SIEM_SERVER_PORT))
            s.sendall(json.dumps(payload).encode() + b'\n')
        return True
    except:
        return False

def send_logs(logs_payload):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((SIEM_SERVER_IP, SIEM_SERVER_PORT))
            data = json.dumps(logs_payload).encode('utf-8')
            s.sendall(data + b'\n')
        print(f"[+] Sent {len(logs_payload)} log entries")
        return True
    except Exception as e:
        print(f"[!] Failed to send logs: {e}")
        return False

def collect_logs():
    all_logs = []
    
    # 1. Collect from log files
    for log_file in LOG_FILES:
        if os.path.exists(log_file):
            lines = get_last_n_lines(log_file, n=10)
            for line in lines:
                if line.strip():
                    all_logs.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "agent_id": AGENT_ID,
                        "hostname": HOSTNAME,
                        "source": os.path.basename(log_file),
                        "log_type": "syslog",
                        "message": line.strip(),
                        "os": "linux"
                    })
    
    # 2. Collect network connections
    net_output = get_network_connections()
    if net_output:
        all_logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "source": "network",
            "log_type": "netstat",
            "message": net_output,
            "os": "linux"
        })
    
    # 3. Collect running processes
    proc_output = get_running_processes()
    if proc_output:
        all_logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "source": "processes",
            "log_type": "ps",
            "message": proc_output,
            "os": "linux"
        })
    
    # 4. Collect logged in users
    users = get_logged_in_users()
    if users:
        all_logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": AGENT_ID,
            "hostname": HOSTNAME,
            "source": "users",
            "log_type": "who",
            "message": users,
            "os": "linux"
        })
    
    return all_logs

def main():
    print("╔════════════════════════════════════════════════════╗")
    print("║         🛡️  SIEM AGENT - REAL DATA MODE          ║")
    print("╠════════════════════════════════════════════════════╣")
    print(f"║  Agent ID:   {AGENT_ID}")
    print(f"║  Hostname:   {HOSTNAME}")
    print(f"║  Server IP:  {SIEM_SERVER_IP}:{SIEM_SERVER_PORT}")
    print("╚════════════════════════════════════════════════════╝")
    
    print(f"\n[*] Agent started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] Collecting logs every 30 seconds...")
    
    heartbeat_counter = 0
    
    while True:
        try:
            # Send heartbeat every 5 minutes (10 cycles)
            heartbeat_counter += 1
            if heartbeat_counter >= 10:
                send_heartbeat()
                heartbeat_counter = 0
            
            logs = collect_logs()
            if logs:
                send_logs(logs)
            time.sleep(30)
            
        except KeyboardInterrupt:
            print("\n[*] Agent stopped by user")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(30)

if __name__ == "__main__":
    main()