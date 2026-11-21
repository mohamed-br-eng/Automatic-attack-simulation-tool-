"""Reporting engine tests (P4): JSON + HTML, no target and no WeasyPrint."""
import json

from core import Finding, Severity
from reporting import ReportBuilder


def _sample_findings():
    return [
        Finding(category="A07:2025 Authentication Failures",
                title="Valid weak credentials: admin:password",
                severity=Severity.HIGH, cvss_score=8.7,
                cvss_vector="CVSS:4.0/AV:N/AC:L/...",
                evidence="admin:password accepted", recommendation="MFA + lockout",
                target="http://127.0.0.1/login", plugin="bruteforce"),
        Finding(category="A01:2025 Broken Access Control",
                title="IDOR on /api/user/{id}", severity=Severity.MEDIUM,
                cvss_score=5.3, evidence="id=2 accessible",
                recommendation="Server-side access control", plugin="access_control"),
        Finding(category="A05:2025 Injection", title="Informational note",
                severity=Severity.INFO, evidence="n/a", recommendation="None"),
    ]


def test_json_is_source_of_truth():
    rb = ReportBuilder(_sample_findings(), target="127.0.0.1", scan_id="abc")
    data = json.loads(rb.to_json())
    assert data["summary"]["total"] == 3
    assert data["summary"]["by_severity"]["HIGH"] == 1
    assert data["summary"]["posture"] == "HIGH"
    # Sorting: HIGH before MEDIUM before INFO.
    sevs = [f["severity"] for f in data["findings"]]
    assert sevs == ["HIGH", "MEDIUM", "INFO"]
    assert len(data["summary"]["top_risks"]) == 1  # only the HIGH


def test_html_renders():
    rb = ReportBuilder(_sample_findings(), target="127.0.0.1")
    html = rb.to_html()
    assert "<!doctype html>" in html.lower()
    assert "admin:password" in html
    assert "Executive Summary" in html
    assert "#ec835a" in html  # HIGH severity status color (brand-neutral palette)


def test_empty_report():
    rb = ReportBuilder([], target="127.0.0.1")
    data = json.loads(rb.to_json())
    assert data["summary"]["total"] == 0
    assert data["summary"]["posture"] == "INFO"
    assert "No findings" in rb.to_html()
