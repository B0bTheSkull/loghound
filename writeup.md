---
title: "Building LogHound: A Log Anomaly Detector for the Rest of Us"
date: 2024-03-22
tags: [blue-team, detection-engineering, python, syslog, soc]
excerpt: "Most breaches aren't quiet. They leave traces in auth logs, access logs, and syslog — if you know what to look for. Here's how I built a tool to find them automatically."
---

# Building LogHound: A Log Anomaly Detector for the Rest of Us

Most breaches aren't quiet. They leave traces — in `/var/log/auth.log`, in nginx access logs, in syslog entries that nobody's reading. The problem isn't a lack of data. It's that there's *too much* data, and the signal is buried in noise.

That's the core problem I wanted to solve with **LogHound**: a CLI tool that parses raw log files and surfaces anomalies worth investigating.

## Why Log Analysis Matters (And Why Most People Skip It)

When a threat actor targets a Linux server, the playbook is pretty consistent:

1. Enumerate the attack surface (port scan, service detection)
2. Brute-force common credentials on SSH
3. Get a foothold, escalate privileges
4. Establish persistence

Every one of those stages leaves log entries. The brute force shows up as a stream of `Failed password` lines in `auth.log`. The privilege escalation shows up as a `sudo` or `su` event. New persistence accounts show up as `useradd` entries.

The challenge is that on an active server, you're drowning in log data. A healthy server might have thousands of auth log lines per day — most of them completely benign. Without tooling, you're relying on eyeballing the logs or writing one-off grep commands during an incident.

That's where LogHound comes in.

## Detection Logic: What Does "Suspicious" Actually Look Like?

### Brute Force SSH

The signature is obvious in hindsight: a stream of `Failed password` entries from the same IP, targeting one or more usernames. The real signal is the *sequence* — five failures in a row from a single IP in a short window is not a user mistyping their password.

LogHound tracks failures per source IP and flags any IP that exceeds the threshold (configurable, default 5). More importantly, it then checks whether that same IP later achieved a *successful* login — the credential stuffing success indicator. That's the CRITICAL finding you actually want waking you up at 2am.

### Privilege Escalation

After initial access, attackers need root. The two most common paths in auth logs are:

- `sudo /bin/bash` — taking a full root shell via sudo
- `su` to root — switching user to root

LogHound flags both, with extra attention to high-risk sudo commands (`/bin/bash`, `passwd`, `visudo`, etc.). A `sudo apt update` is boring. A `sudo /bin/bash` is a different conversation.

### New Account Creation

`useradd` events in auth.log are rare on healthy systems. When one shows up unexpectedly — especially at 4am, after a suspicious login — it's almost always either persistence being established or a misconfigured automation tool.

### Off-Hours Logins

This one's context-dependent, but worth flagging. A successful SSH login at 3am from an IP you don't recognize is worth a second look. LogHound flags successful logins outside 08:00–18:00 as MEDIUM severity — low enough not to be noise, high enough to show up in a daily review.

## Web Log Analysis: Recognizing Scanner Behavior

Web access logs tell a different story. A human browsing your site has a rhythm: they hit your homepage, click a few links, submit a form. A scanner looks completely different.

LogHound's web log analysis catches three main patterns:

**Known Scanner User-Agents**: Tools like Nikto, sqlmap, dirbuster, and nuclei all have distinctive User-Agent strings. Flagging these is low-hanging fruit — they often don't bother to spoof.

**Sensitive Path Probing**: Any IP hitting `.env`, `.git/HEAD`, `wp-config.php`, or `phpinfo.php` is either automated or very specifically looking for something. LogHound tracks which sensitive paths were hit and by whom.

**404 Spikes**: A single IP generating dozens of 404 responses in a short window is running a wordlist against your server. This is classic directory/file enumeration and almost always automated.

## Running It

```bash
# Test it with the included sample logs
python loghound.py --log auth --file samples/sample_auth.log

# Point it at your real logs
sudo python loghound.py --log auth --file /var/log/auth.log --since 24h

# Generate a JSON report for further analysis
python loghound.py --log web --file /var/log/nginx/access.log --output report.json
```

The output is color-coded by severity: CRITICAL in red, HIGH in orange, MEDIUM in yellow. The JSON report gives you a machine-readable format for feeding into a SIEM or writing follow-up scripts.

## What I Learned

Building this forced me to actually read auth logs carefully — more carefully than I ever had before. The format is deceptively simple, but parsing it robustly requires handling edge cases: IPv6 addresses, invalid user attempts formatted slightly differently, timestamps without year information.

The biggest insight was how *noisy* a public-facing server actually is. Running the tool against real auth logs from a VPS exposed to the internet, there are hundreds of brute force attempts every single day — most from Tor exit nodes and known malicious IP ranges. The credential stuffing success indicator was the most valuable detection, because that's the one that actually means something went wrong.

## Limitations and What's Next

LogHound is intentionally simple. It doesn't:

- Do real-time tailing (yet — `--watch` mode is on the roadmap)
- Parse Windows Event Log (EVTX) format
- Correlate events across multiple log files
- Integrate with threat intelligence to check source IPs against known-bad lists

The last one is something I'm working on separately — it's the premise behind [ThreatPulse](../threatpulse), which I'll write about next.

For now, LogHound does one thing well: it takes a log file and tells you what's weird about it. Sometimes that's all you need.

---

*Code is on GitHub: [B0bTheSkull/loghound](https://github.com/B0bTheSkull/loghound)*
