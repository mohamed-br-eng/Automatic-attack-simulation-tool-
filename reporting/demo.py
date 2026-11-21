"""
Generate a demonstration report (JSON + HTML) into reports/.
    python -m reporting.demo
Serves as a usage example of ReportBuilder and as a visual preview.
"""
from pathlib import Path

from core import Finding, Severity
from reporting import ReportBuilder

DEMO_FINDINGS = [
    Finding(
        category="A07:2025 Authentication Failures",
        title="Valid weak credentials: admin:password",
        severity=Severity.HIGH, cvss_score=8.7,
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        evidence="Login=admin / Password=password accepted.\nCSRF token handled: yes.",
        recommendation="Strong password policy, lockout after N failures, MFA.",
        target="http://127.0.0.1:8080/login.php", plugin="bruteforce",
        request="POST /login.php (username=..., password=...)",
        response="HTTP 302 -> /index.php, 0 bytes"),
    Finding(
        category="A01:2025 Broken Access Control",
        title="IDOR: access to /api/user/2 without authorization",
        severity=Severity.MEDIUM, cvss_score=5.3, epss=0.08,
        evidence="GET /api/user/2 returns another user's data.",
        recommendation="Server-side access control (ownership check).",
        target="http://127.0.0.1:8080/api/user/2", plugin="access_control"),
    Finding(
        category="A07:2025 Authentication Failures",
        title="Missing account lockout",
        severity=Severity.LOW, cvss_score=3.1,
        evidence="20 failed attempts with no lockout or delay.",
        recommendation="Rate-limiting + temporary lockout.",
        plugin="bruteforce"),
]


def main() -> None:
    out = Path("reports")
    out.mkdir(exist_ok=True)
    rb = ReportBuilder(DEMO_FINDINGS, target="127.0.0.1", scan_id="demo-001")
    rb.to_json(out / "demo.json")
    rb.to_html(out / "demo.html")
    print(f"Report generated: {out / 'demo.html'}  and  {out / 'demo.json'}")


if __name__ == "__main__":
    main()
