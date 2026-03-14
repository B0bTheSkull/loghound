"""
Terminal reporter with colored output for LogHound findings.
"""

from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH": "\033[31m",       # red
    "MEDIUM": "\033[33m",     # yellow
    "LOW": "\033[34m",        # blue
    "INFO": "\033[37m",       # white
}
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"


class Reporter:
    def __init__(self, no_color=False):
        self.no_color = no_color

    def _color(self, text, color_code):
        if self.no_color or not HAS_COLOR:
            return text
        return f"{color_code}{text}{RESET}"

    def banner(self):
        banner = f"""
{self._color('╔══════════════════════════════════════╗', CYAN)}
{self._color('║         LogHound v1.0                ║', CYAN)}
{self._color('║   Log Anomaly Detection Engine       ║', CYAN)}
{self._color('╚══════════════════════════════════════╝', CYAN)}
"""
        print(banner)

    def info(self, msg):
        print(f"{self._color('[*]', CYAN)} {msg}")

    def print_findings(self, findings, log_type, log_file):
        print(f"{self._color('[*]', CYAN)} Analyzed: {self._color(log_file, BOLD)}")
        print(f"{self._color('[*]', CYAN)} Log type: {log_type.upper()}")
        print(f"{self._color('[*]', CYAN)} Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        if not findings:
            print(self._color("[✓] No anomalies detected.", GREEN))
            return

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print(f"{self._color(f'[!] {len(findings)} finding(s) detected:', BOLD)}")
        for sev, count in sorted(severity_counts.items(), key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x[0]) if x[0] in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99):
            color = SEVERITY_COLORS.get(sev, "")
            print(f"    {self._color(f'[{sev}]', color)} {count}")
        print()
        print("─" * 60)

        for finding in findings:
            sev = finding.get("severity", "INFO")
            color = SEVERITY_COLORS.get(sev, "")
            sev_label = self._color(f"[{sev}]", color)
            ftype = finding.get("type", "unknown").replace("_", " ").upper()

            print(f"\n{sev_label} {self._color(ftype, BOLD)}")
            print(f"  Detail: {finding.get('detail', 'N/A')}")

            skip_keys = {"severity", "type", "detail"}
            for k, v in finding.items():
                if k in skip_keys:
                    continue
                if isinstance(v, list):
                    v = ", ".join(str(i) for i in v[:5]) + ("..." if len(v) > 5 else "")
                print(f"  {k.replace('_', ' ').capitalize()}: {v}")

        print("\n" + "─" * 60)
        print(f"{self._color('[*]', CYAN)} Scan complete.")
