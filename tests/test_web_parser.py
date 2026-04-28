import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parsers.web_parser import COMBINED_LOG, WebLogParser, parse_apache_ts


def test_parse_apache_ts_valid():
    ts = parse_apache_ts("15/Jan/2024:03:22:11 +0000")
    assert ts is not None
    assert ts.year == 2024
    assert ts.day == 15


def test_parse_apache_ts_invalid_returns_none():
    assert parse_apache_ts("not a timestamp") is None


def test_combined_log_matches_typical_line():
    line = '203.0.113.45 - - [15/Jan/2024:03:22:11 +0000] "GET /admin HTTP/1.1" 404 230 "-" "Mozilla/5.0"'
    m = COMBINED_LOG.match(line)
    assert m is not None
    assert m.group(1) == "203.0.113.45"
    assert m.group(3) == "GET"
    assert m.group(4) == "/admin"
    assert m.group(5) == "404"
    assert m.group(6) == "Mozilla/5.0"


def _write_web_log(tmp_path, lines):
    p = tmp_path / "access.log"
    p.write_text("\n".join(lines) + "\n")
    return p


def test_scanner_useragent_detected(tmp_path):
    lines = [
        '1.2.3.4 - - [15/Jan/2024:03:22:11 +0000] "GET /login HTTP/1.1" 200 100 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"',
    ]
    log = _write_web_log(tmp_path, lines)
    findings = WebLogParser().analyze(str(log))
    assert any(f["type"] == "scanner_user_agent" and f["matched"] == "nikto" for f in findings)


def test_normal_browser_not_flagged_as_scanner(tmp_path):
    lines = [
        '1.2.3.4 - - [15/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1000 "-" "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0"',
    ]
    log = _write_web_log(tmp_path, lines)
    findings = WebLogParser().analyze(str(log))
    assert not any(f["type"] == "scanner_user_agent" for f in findings)


def test_404_spike_detected(tmp_path):
    lines = [
        f'5.6.7.8 - - [15/Jan/2024:03:22:{i:02d} +0000] "GET /missing{i} HTTP/1.1" 404 230 "-" "curl/7.0"'
        for i in range(15)
    ]
    log = _write_web_log(tmp_path, lines)
    findings = WebLogParser().analyze(str(log))
    assert any(f["type"] == "404_spike" and f["source_ip"] == "5.6.7.8" for f in findings)


def test_sensitive_path_access_flagged(tmp_path):
    lines = [
        '9.9.9.9 - - [15/Jan/2024:03:22:11 +0000] "GET /.env HTTP/1.1" 404 230 "-" "Mozilla/5.0"',
        '9.9.9.9 - - [15/Jan/2024:03:22:12 +0000] "GET /.git/config HTTP/1.1" 404 230 "-" "Mozilla/5.0"',
        '9.9.9.9 - - [15/Jan/2024:03:22:13 +0000] "GET /wp-config.php HTTP/1.1" 404 230 "-" "Mozilla/5.0"',
    ]
    log = _write_web_log(tmp_path, lines)
    findings = WebLogParser().analyze(str(log))
    sensitive = [f for f in findings if f["type"] == "sensitive_path_access"]
    assert sensitive
    assert sensitive[0]["source_ip"] == "9.9.9.9"
    assert len(sensitive[0]["paths"]) >= 2


def test_high_request_volume_detected(tmp_path):
    lines = [
        f'10.10.10.10 - - [15/Jan/2024:03:22:{i % 60:02d} +0000] "GET /page{i} HTTP/1.1" 200 100 "-" "Mozilla/5.0"'
        for i in range(60)
    ]
    log = _write_web_log(tmp_path, lines)
    findings = WebLogParser(threshold=50).analyze(str(log))
    assert any(f["type"] == "high_request_volume" and f["source_ip"] == "10.10.10.10" for f in findings)


def test_findings_sorted_by_severity(tmp_path):
    lines = [
        '5.6.7.8 - - [15/Jan/2024:03:22:01 +0000] "GET /missing HTTP/1.1" 404 230 "-" "Mozilla/5.0"',
    ] * 15 + [
        '1.2.3.4 - - [15/Jan/2024:03:22:11 +0000] "GET /login HTTP/1.1" 200 100 "-" "sqlmap/1.7"',
    ]
    log = _write_web_log(tmp_path, lines)
    findings = WebLogParser().analyze(str(log))
    if len(findings) >= 2:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        levels = [order[f["severity"]] for f in findings]
        assert levels == sorted(levels)
