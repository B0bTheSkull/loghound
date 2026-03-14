# LogHound 🐾

> **CLI log anomaly detection for auth and web server logs.**
> Catch brute force attacks, credential stuffing, privilege escalation, and scanner behavior — before they become incidents.

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square)

---

## What It Does

LogHound parses raw log files and applies detection logic to surface suspicious patterns that often go unnoticed in the noise.

**Auth log detection (`/var/log/auth.log`):**
- 🔴 SSH brute force attacks (configurable threshold)
- 🔴 Successful logins following multiple failures (credential stuffing)
- 🔴 Privilege escalation via `sudo` and `su`
- 🔴 New user account creation
- 🟡 Off-hours logins (outside 08:00–18:00)

**Web log detection (nginx/apache access logs):**
- 🔴 Known scanner User-Agents (Nikto, sqlmap, nuclei, dirbuster, etc.)
- 🔴 Sensitive file/path probing (`.env`, `.git`, `wp-config.php`, etc.)
- 🔴 404 spike patterns (directory enumeration)
- 🟡 High request volume from single IPs

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/loghound.git
cd loghound
pip install -r requirements.txt
```

---

## Usage

```bash
# Analyze an auth log (SSH brute force, priv esc, etc.)
python loghound.py --log auth --file /var/log/auth.log

# Use sample files to test it out
python loghound.py --log auth --file samples/sample_auth.log

# Adjust brute force threshold (default: 5 failed attempts)
python loghound.py --log auth --file /var/log/auth.log --threshold 3

# Only look at the last 24 hours
python loghound.py --log auth --file /var/log/auth.log --since 24h

# Analyze nginx/apache access logs
python loghound.py --log web --file /var/log/nginx/access.log

# Write a JSON report
python loghound.py --log auth --file samples/sample_auth.log --output report.json

# No color output (for piping/scripting)
python loghound.py --log auth --file /var/log/auth.log --no-color | tee report.txt
```

---

## Example Output

```
╔══════════════════════════════════════╗
║         LogHound v1.0                ║
║   Log Anomaly Detection Engine       ║
╚══════════════════════════════════════╝

[*] Analyzed: samples/sample_auth.log
[*] Log type: AUTH
[*] Timestamp: 2024-01-15 14:32:01

[!] 5 finding(s) detected:
    [CRITICAL] 1
    [HIGH]     4

────────────────────────────────────────────────────────────

[CRITICAL] BRUTE FORCE SUCCESS
  Detail: SUCCESSFUL login from 185.220.101.45 after 8 failures — possible credential stuffing
  Source ip: 185.220.101.45
  Username: ubuntu
  Failed before: 8

[HIGH] BRUTE FORCE
  Detail: 8 failed SSH login attempts from 185.220.101.45
  Source ip: 185.220.101.45
  Attempt count: 8
  Usernames tried: root, admin, ubuntu

[HIGH] SUSPICIOUS SUDO
  Detail: High-risk sudo command executed by ubuntu
  Username: ubuntu
  Command: /bin/bash

[HIGH] USER CREATED
  Detail: New user account created: h4x0r
  Username: h4x0r

[HIGH] ROOT SU
  Detail: User ubuntu switched to root via su
  Username: ubuntu
```

---

## JSON Report

```json
{
  "generated_at": "2024-01-15T14:32:01",
  "log_type": "auth",
  "log_file": "samples/sample_auth.log",
  "threshold": 5,
  "total_findings": 5,
  "findings": [
    {
      "severity": "CRITICAL",
      "type": "brute_force_success",
      "source_ip": "185.220.101.45",
      "username": "ubuntu",
      "failed_before": 8,
      "detail": "SUCCESSFUL login from 185.220.101.45 after 8 failures"
    }
  ]
}
```

---

## Supported Log Formats

| Format | Example Path |
|--------|-------------|
| `auth.log` (Debian/Ubuntu) | `/var/log/auth.log` |
| `secure` (RHEL/CentOS) | `/var/log/secure` |
| nginx combined access log | `/var/log/nginx/access.log` |
| Apache combined access log | `/var/log/apache2/access.log` |

---

## Roadmap

- [ ] Windows Event Log (EVTX) support
- [ ] Syslog forwarding integration
- [ ] Slack/webhook alerting
- [ ] Watchmode (`--watch`) for real-time tailing
- [ ] MITRE ATT&CK technique tagging

---

## Contributing

Pull requests welcome. Please open an issue first for major changes.

## License

MIT — see [LICENSE](LICENSE)
