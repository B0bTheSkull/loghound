"""
Auth log parser for /var/log/auth.log style logs.
Detects brute force, credential stuffing, privilege escalation, and off-hours logins.
"""

import re
from collections import defaultdict
from datetime import datetime


# Regex patterns for common auth.log events
PATTERNS = {
    "failed_ssh": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Failed password for (?:invalid user )?(\S+) from ([\d.]+) port"
    ),
    "accepted_ssh": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Accepted (?:password|publickey) for (\S+) from ([\d.]+) port"
    ),
    "invalid_user": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*Invalid user (\S+) from ([\d.]+)"
    ),
    "sudo_command": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*sudo:.*?(\w+).*COMMAND=(.*)"
    ),
    "useradd": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*useradd.*name=([^\s,]+)"
    ),
    "su_session": re.compile(
        r"(\w+\s+\d+\s[\d:]+).*su:.*session opened for user (\S+) by (\S+)"
    ),
}

BUSINESS_HOURS = (8, 18)  # 8am to 6pm


def parse_timestamp(ts_str, year=None):
    """Parse syslog-style timestamp like 'Jan 15 03:22:11'."""
    if year is None:
        year = datetime.now().year
    try:
        dt = datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        return dt
    except ValueError:
        return None


class AuthLogParser:
    def __init__(self, threshold=5, since=None):
        self.threshold = threshold
        self.since = since

    def analyze(self, log_path):
        findings = []
        failed_attempts = defaultdict(list)  # ip -> list of (timestamp, username)
        successful_logins = []
        lines_parsed = 0

        with open(log_path, "r", errors="replace") as f:
            for line in f:
                lines_parsed += 1
                line = line.strip()

                # Failed SSH login
                m = PATTERNS["failed_ssh"].search(line)
                if m:
                    ts = parse_timestamp(m.group(1))
                    if self.since and ts and ts < self.since:
                        continue
                    username, ip = m.group(2), m.group(3)
                    failed_attempts[ip].append({"time": ts, "username": username})
                    continue

                # Successful SSH login
                m = PATTERNS["accepted_ssh"].search(line)
                if m:
                    ts = parse_timestamp(m.group(1))
                    if self.since and ts and ts < self.since:
                        continue
                    username, ip = m.group(2), m.group(3)
                    successful_logins.append({"time": ts, "username": username, "ip": ip})

                    # Off-hours login check
                    if ts and not (BUSINESS_HOURS[0] <= ts.hour < BUSINESS_HOURS[1]):
                        findings.append({
                            "severity": "MEDIUM",
                            "type": "off_hours_login",
                            "timestamp": str(ts),
                            "source_ip": ip,
                            "username": username,
                            "detail": f"Successful SSH login at {ts.strftime('%H:%M')} (outside 08:00-18:00)"
                        })
                    continue

                # Sudo command
                m = PATTERNS["sudo_command"].search(line)
                if m:
                    ts = parse_timestamp(m.group(1))
                    if self.since and ts and ts < self.since:
                        continue
                    username, command = m.group(2), m.group(3).strip()
                    # Flag high-risk sudo commands
                    high_risk = any(cmd in command for cmd in [
                        "/bin/bash", "/bin/sh", "chmod 777", "passwd", "visudo",
                        "usermod", "userdel", "/etc/passwd", "/etc/shadow", "nc ", "ncat"
                    ])
                    if high_risk:
                        findings.append({
                            "severity": "HIGH",
                            "type": "suspicious_sudo",
                            "timestamp": str(ts),
                            "username": username,
                            "command": command,
                            "detail": f"High-risk sudo command executed by {username}"
                        })
                    continue

                # New user created
                m = PATTERNS["useradd"].search(line)
                if m:
                    ts = parse_timestamp(m.group(1))
                    if self.since and ts and ts < self.since:
                        continue
                    new_user = m.group(2)
                    findings.append({
                        "severity": "HIGH",
                        "type": "user_created",
                        "timestamp": str(ts),
                        "username": new_user,
                        "detail": f"New user account created: {new_user}"
                    })
                    continue

                # su session (lateral movement)
                m = PATTERNS["su_session"].search(line)
                if m:
                    ts = parse_timestamp(m.group(1))
                    if self.since and ts and ts < self.since:
                        continue
                    target_user, source_user = m.group(2), m.group(3).strip("()")
                    if target_user == "root":
                        findings.append({
                            "severity": "HIGH",
                            "type": "root_su",
                            "timestamp": str(ts),
                            "username": source_user,
                            "detail": f"User {source_user} switched to root via su"
                        })

        # Brute force detection
        for ip, attempts in failed_attempts.items():
            if len(attempts) >= self.threshold:
                findings.append({
                    "severity": "HIGH",
                    "type": "brute_force",
                    "source_ip": ip,
                    "attempt_count": len(attempts),
                    "usernames_tried": list(set(a["username"] for a in attempts)),
                    "first_seen": str(attempts[0]["time"]) if attempts[0]["time"] else "unknown",
                    "last_seen": str(attempts[-1]["time"]) if attempts[-1]["time"] else "unknown",
                    "detail": f"{len(attempts)} failed SSH login attempts from {ip}"
                })

                # Check if brute force was followed by a successful login
                for login in successful_logins:
                    if login["ip"] == ip:
                        findings.append({
                            "severity": "CRITICAL",
                            "type": "brute_force_success",
                            "source_ip": ip,
                            "username": login["username"],
                            "timestamp": str(login["time"]),
                            "failed_before": len(attempts),
                            "detail": f"SUCCESSFUL login from {ip} after {len(attempts)} failures — possible credential stuffing"
                        })

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 4))

        return findings
