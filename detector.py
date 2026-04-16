#!/usr/bin/env python3
import os
import re
import time
import json
import subprocess
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"
STATE_FILE = "/var/log/bf_defender_state.json"
ALERT_LOG = "/var/log/bf_defender_alerts.log"

TIME_WINDOW = 60
BLOCK_THRESHOLD = 6
ALERT_THRESHOLD = 3

failed_attempts = defaultdict(list)
blocked_ips = set()

FAILED_RE = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")
INVALID_RE = re.compile(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)")

def log_alert(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(ALERT_LOG, "a") as f:
        f.write(line + "\n")

def save_state() -> None:
    state = {"blocked_ips": list(blocked_ips)}
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def load_state() -> None:
    global blocked_ips
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                state = json.load(f)
                blocked_ips = set(state.get("blocked_ips", []))
        except Exception:
            blocked_ips = set()

def iptables_rule_exists(ip: str) -> bool:
    result = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0

def block_ip(ip: str) -> None:
    if ip in blocked_ips or iptables_rule_exists(ip):
        blocked_ips.add(ip)
        return

    result = subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        blocked_ips.add(ip)
        save_state()
        log_alert(f"BLOCKED {ip} after repeated failed logins")
    else:
        log_alert(f"ERROR blocking {ip}: {result.stderr.strip()}")

def risk_level(count: int) -> str:
    if count >= BLOCK_THRESHOLD:
        return "HIGH"
    if count >= ALERT_THRESHOLD:
        return "MEDIUM"
    return "LOW"

def process_failure(ip: str) -> None:
    now = time.time()
    failed_attempts[ip].append(now)

    failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t <= TIME_WINDOW]
    count = len(failed_attempts[ip])
    level = risk_level(count)

    if level == "MEDIUM":
        log_alert(f"ALERT {ip} has {count} failed logins in {TIME_WINDOW}s")

    if level == "HIGH":
        block_ip(ip)

def parse_line(line: str) -> None:
    match = FAILED_RE.search(line) or INVALID_RE.search(line)
    if match:
        ip = match.group(1)
        process_failure(ip)

def follow_log() -> None:
    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            parse_line(line)

def main() -> None:
    load_state()
    log_alert("bf_defender started")
    follow_log()

if __name__ == "__main__":
    main()
