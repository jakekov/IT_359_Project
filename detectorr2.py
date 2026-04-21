#!/usr/bin/env python3

# Imports
import os                # File/path operations
import re                # Regex for parsing logs
import time              # Time tracking for rate limiting + bans
import json              # Save/load state to file
import subprocess        # Run iptables + journalctl
import sys               # Exit handling
from collections import defaultdict  # Track attempts per IP easily


# Log File Locations (varies by Linux distro)
POSSIBLE_LOG_FILES = [
    "/var/log/auth.log",   # Debian/Ubuntu/Kali
    "/var/log/secure",     # RHEL/CentOS
    "/var/log/syslog",     # fallback
]


# Files for persistence + logging
STATE_FILE = "/var/log/defender_state.json"   # Stores blocked IPs
ALERT_LOG = "/var/log/defender_alerts.log"    # Stores alerts/events


# Detection thresholds
TIME_WINDOW = 120       # seconds to look back for attempts
BLOCK_THRESHOLD = 12    # attempts before blocking
ALERT_THRESHOLD = 3     # attempts before alerting

total_attempts = 0      # counter
unique_ips = set()      # unique ips used

# Progressive ban settings
BASE_BLOCK_DURATION = 300   # 5 minutes initial ban
MAX_BLOCK_DURATION = 3600   # max 1 hour ban


# Whitelist (never block these IPs)
WHITELIST = {"127.0.0.1"}  # add your attacker/test IP here


# Data structures

# Tracks failed login timestamps per IP
failed_attempts = defaultdict(list)

# Tracks blocked IPs with metadata:
# {
#   "ip": {
#       "blocked_at": timestamp,
#       "duration": seconds,
#       "offenses": int
#   }
# }
blocked_ips = {}

# Prevents duplicate alert spam
last_alert_count = {}


# Regex patterns for failed SSH logins
FAILED_RE = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
INVALID_RE = re.compile(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)")


# Find available log file
def find_log_file():
    for path in POSSIBLE_LOG_FILES:
        if os.path.exists(path):
            return path
    return None


# Log alerts to file + console
def log_alert(message: str):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(ALERT_LOG, "a") as f:
        f.write(line + "\n")


# Save blocked IP state (persistence)
def save_state():
    with open(STATE_FILE, "w") as f:
        json.dump(blocked_ips, f)


# Load blocked IP state
def load_state():
    global blocked_ips
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                blocked_ips = json.load(f)
        except Exception:
            blocked_ips = {}

# Check if firewall rule already exists
def iptables_rule_exists(ip):
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


# Block IP using iptables
def block_ip(ip):
    # Skip trusted IPs
    if ip in WHITELIST:
        log_alert(f"SKIPPED whitelist IP {ip}")
        return

    now = time.time()

    # Determine offense count
    if ip in blocked_ips:
        offenses = blocked_ips[ip]["offenses"] + 1
    else:
        offenses = 1

    # Progressive ban duration (doubles each time)
    duration = min(BASE_BLOCK_DURATION * (2 ** (offenses - 1)), MAX_BLOCK_DURATION)

    # Add firewall rule if not already present
    if not iptables_rule_exists(ip):
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            log_alert(f"ERROR blocking {ip}: {result.stderr.strip()}")
            return

    # Store block info
    blocked_ips[ip] = {
        "blocked_at": now,
        "duration": duration,
        "offenses": offenses
    }

    save_state()
    log_alert(f"BLOCKED {ip} for {duration}s (offense #{offenses})")


# Unblock IP (remove firewall rule)
def unblock_ip(ip):
    result = subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        log_alert(f"UNBLOCKED {ip}")
    else:
        log_alert(f"ERROR unblocking {ip}: {result.stderr.strip()}")


# Cleanup expired bans (AUTO-UNBLOCK)
def cleanup_blocked_ips():
    now = time.time()
    to_remove = []

    for ip, data in blocked_ips.items():
        # Check if ban expired
        if now - data["blocked_at"] >= data["duration"]:
            unblock_ip(ip)
            to_remove.append(ip)

    # Remove from memory
    for ip in to_remove:
        del blocked_ips[ip]

    if to_remove:
        save_state()


# Determine risk level
def risk_level(count):
    if count >= BLOCK_THRESHOLD:
        return "HIGH"
    if count >= ALERT_THRESHOLD:
        return "MEDIUM"
    return "LOW"


# Process a failed login attempt
def process_failure(ip):
    global total_attempts

    now = time.time()
    failed_attempts[ip].append(now)

    total_attempts += 1
    unique_ips.add(ip)

    # Keep only attempts within TIME_WINDOW
    failed_attempts[ip] = [
        t for t in failed_attempts[ip] if now - t <= TIME_WINDOW
    ]

    count = len(failed_attempts[ip])
    level = risk_level(count)

    # Alert on medium risk
    if level == "MEDIUM" and last_alert_count.get(ip) != count:
        log_alert(f"ALERT {ip} has {count} failed logins in {TIME_WINDOW}s")
        last_alert_count[ip] = count

    # Block on high risk
    if level == "HIGH":
    # Only block if not already blocked
    if ip not in blocked_ips:
        block_ip(ip)


# Displays stats
def print_stats():
    print(
        f"[STATS] Attempts: {total_attempts} | "
        f"Unique IPs: {len(unique_ips)} | "
        f"Active Blocks: {len(blocked_ips)}"
    )

def follow_log_file(log_file):
    log_alert(f"monitoring log file: {log_file}")

    last_stats_time = time.time()

    with open(log_file, "r") as f:
        f.seek(0, os.SEEK_END)

        while True:
            cleanup_blocked_ips()

            line = f.readline()

            if not line:
                time.sleep(0.5)
            else:
                parse_line(line)

            # Always runs (even if no logs)
            if time.time() - last_stats_time >= 5:
                print_stats()
                last_stats_time = time.time()
            
# Parse log line for failures
def parse_line(line):
    match = FAILED_RE.search(line) or INVALID_RE.search(line)
    if match:
        ip = match.group(1)
        process_failure(ip)


# Follow systemd journal
def follow_journal():
    log_alert("monitoring systemd journal")

    proc = subprocess.Popen(
        ["journalctl", "-f", "-n", "0"],
        stdout=subprocess.PIPE,
        text=True
    )

    last_stats_time = time.time()

    for line in proc.stdout:
        cleanup_blocked_ips()

        if time.time() - last_stats_time >= 5:
            print_stats()
            last_stats_time = time.time()

        parse_line(line)


# Main entry point
def main():
    # Must run as root (iptables + logs)
    if os.geteuid() != 0:
        print("Run as root: sudo python3 detector.py")
        sys.exit(1)

    load_state()
    log_alert("defender started")

    log_file = find_log_file()
    if log_file:
        follow_log_file(log_file)
    else:
        follow_journal()

# Start script
if __name__ == "__main__":
    main()
