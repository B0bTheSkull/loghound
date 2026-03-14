"""
Web log parser for nginx/apache combined access log format.
Detects scanner behavior, 404 spikes, and suspicious user agents.
"""

import re
from collections import defaultdict
from datetime import datetime


# Combined log format: IP - user [timestamp] "METHOD /path HTTP/x" status bytes "referer" "ua"
COMBINED_LOG = re.compile(
    r'([\d.]+) - \S+ \[([^\]]+)\] "(\w+) ([^\s"]+)[^"]*" (\d+) \d+ "[^"]*" "([^"]*)"'
)

SCANNER_UAS = [
    "sqlmap", "nikto", "nessus", "masscan", "zgrab", "nuclei", "dirbuster",
    "gobuster", "wfuzz", "burpsuite", "acunetix", "nmap", "python-requests/2.1",
    "curl/", "wget/", "go-http-client", "libwww-perl", "scrapy", "zgrab",
    "censys", "shodan", "semrush", "ahrefsbot", "mj12bot"
]

SENSITIVE_PATHS = [
    "/.env", "/.git", "/wp-config.php", "/phpinfo.php", "/config.php",
    "/backup", "/admin", "/.htaccess", "/etc/passwd", "/proc/self",
    "/shell", "/cmd", "/.ssh", "/id_rsa", "/.bash_history"
]


def parse_apache_ts(ts_str):
    """Parse Apache/nginx timestamp: '15/Jan/2024:03:22:11 +0000'"""
    try:
        return datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None


class WebLogParser:
    def __init__(self, threshold=50, since=None):
        self.threshold = threshold
        self.since = since

    def analyze(self, log_path):
        findings = []
        ip_requests = defaultdict(list)  # ip -> list of {ts, path, status, ua}
        ip_404s = defaultdict(int)
        ip_uas = defaultdict(set)

        with open(log_path, "r", errors="replace") as f:
            for line in f:
                m = COMBINED_LOG.match(line.strip())
                if not m:
                    continue

                ip, ts_str, method, path, status, ua = (
                    m.group(1), m.group(2), m.group(3),
                    m.group(4), int(m.group(5)), m.group(6)
                )

                ts = parse_apache_ts(ts_str)
                if self.since and ts and ts < self.since:
                    continue

                ip_requests[ip].append({"ts": ts, "path": path, "status": status, "ua": ua, "method": method})
                ip_uas[ip].add(ua)

                if status == 404:
                    ip_404s[ip] += 1

        # Brute-force / heavy scanner detection (too many requests)
        for ip, reqs in ip_requests.items():
            if len(reqs) >= self.threshold:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "high_request_volume",
                    "source_ip": ip,
                    "request_count": len(reqs),
                    "detail": f"{ip} made {len(reqs)} requests — possible automated scanning"
                })

        # 404 spike detection
        for ip, count in ip_404s.items():
            if count >= max(10, self.threshold // 5):
                findings.append({
                    "severity": "HIGH",
                    "type": "404_spike",
                    "source_ip": ip,
                    "count": count,
                    "detail": f"{ip} triggered {count} 404 errors — directory/file enumeration"
                })

        # Scanner User-Agent detection
        for ip, reqs in ip_requests.items():
            for req in reqs:
                ua_lower = req["ua"].lower()
                matched_ua = next((s for s in SCANNER_UAS if s in ua_lower), None)
                if matched_ua:
                    findings.append({
                        "severity": "HIGH",
                        "type": "scanner_user_agent",
                        "source_ip": ip,
                        "user_agent": req["ua"],
                        "matched": matched_ua,
                        "path": req["path"],
                        "detail": f"Known scanner UA detected from {ip}: '{matched_ua}'"
                    })
                    break  # one finding per IP

        # Sensitive path access
        sensitive_hits = defaultdict(list)
        for ip, reqs in ip_requests.items():
            for req in reqs:
                for sp in SENSITIVE_PATHS:
                    if req["path"].startswith(sp):
                        sensitive_hits[ip].append(req["path"])

        for ip, paths in sensitive_hits.items():
            findings.append({
                "severity": "HIGH",
                "type": "sensitive_path_access",
                "source_ip": ip,
                "paths": list(set(paths)),
                "detail": f"{ip} accessed {len(paths)} sensitive path(s): {', '.join(set(paths))[:120]}"
            })

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 4))
        return findings
