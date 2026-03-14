#!/usr/bin/env python3
"""
LogHound - Log Anomaly Detection Tool
Detects suspicious patterns in auth and web server logs.
"""

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

from parsers.auth_parser import AuthLogParser
from parsers.web_parser import WebLogParser
from reporter import Reporter


def parse_since(since_str):
    """Convert '24h', '7d', '30m' to a datetime cutoff."""
    if not since_str:
        return None
    units = {"h": "hours", "d": "days", "m": "minutes"}
    unit = since_str[-1]
    if unit not in units:
        print(f"[!] Invalid --since format. Use e.g. 24h, 7d, 30m")
        sys.exit(1)
    value = int(since_str[:-1])
    return datetime.now() - timedelta(**{units[unit]: value})


def main():
    parser = argparse.ArgumentParser(
        description="LogHound - Detect anomalies in auth and web server logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python loghound.py --log auth --file /var/log/auth.log
  python loghound.py --log auth --file samples/sample_auth.log --threshold 3
  python loghound.py --log web --file /var/log/nginx/access.log --since 24h
  python loghound.py --log auth --file samples/sample_auth.log --output report.json
        """
    )
    parser.add_argument("--log", choices=["auth", "web"], required=True,
                        help="Log type to parse: 'auth' (auth.log) or 'web' (nginx/apache access log)")
    parser.add_argument("--file", required=True, help="Path to the log file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed login threshold for brute force detection (default: 5)")
    parser.add_argument("--since", help="Only analyze entries from last N hours/minutes/days (e.g. 24h, 7d)")
    parser.add_argument("--output", help="Write JSON report to this file")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    log_path = Path(args.file)
    if not log_path.exists():
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    since = parse_since(args.since)
    reporter = Reporter(no_color=args.no_color)

    reporter.banner()

    if args.log == "auth":
        p = AuthLogParser(threshold=args.threshold, since=since)
        findings = p.analyze(log_path)
    else:
        p = WebLogParser(threshold=args.threshold, since=since)
        findings = p.analyze(log_path)

    reporter.print_findings(findings, log_type=args.log, log_file=str(log_path))

    if args.output:
        report = {
            "generated_at": datetime.now().isoformat(),
            "log_type": args.log,
            "log_file": str(log_path),
            "threshold": args.threshold,
            "since": args.since,
            "total_findings": len(findings),
            "findings": findings
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        reporter.info(f"JSON report written to {args.output}")


if __name__ == "__main__":
    main()
