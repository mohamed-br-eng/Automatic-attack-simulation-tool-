"""Tests du moteur de rapport (P4) : JSON + HTML, sans cible ni WeasyPrint."""
import json

from core import Finding, Severity
from reporting import ReportBuilder


def _sample_findings():
    return [
        Finding(category="A07:2025 Authentication Failures",
                title="Identifiants faibles valides : admin:password",
                severity=Severity.HIGH, cvss_score=8.7,
                cvss_vector="CVSS:4.0/AV:N/AC:L/...",
                evidence="admin:password accepte", recommendation="MFA + lockout",
                target="http://127.0.0.1/login", plugin="bruteforce"),
        Finding(category="A01:2025 Broken Access Control",
                title="IDOR sur /api/user/{id}", severity=Severity.MEDIUM,
                cvss_score=5.3, evidence="id=2 accessible",
                recommendation="Controle d'acces cote serveur", plugin="access_control"),
        Finding(category="A05:2025 Injection", title="Note d'information",
                severity=Severity.INFO, evidence="n/a", recommendation="RAS"),
    ]


def test_json_is_source_of_truth():
    rb = ReportBuilder(_sample_findings(), target="127.0.0.1", scan_id="abc")
    data = json.loads(rb.to_json())
    assert data["summary"]["total"] == 3
    assert data["summary"]["by_severity"]["HIGH"] == 1
    assert data["summary"]["posture"] == "HIGH"
    # Tri : le HIGH doit venir avant le MEDIUM avant l'INFO.
    sevs = [f["severity"] for f in data["findings"]]
    assert sevs == ["HIGH", "MEDIUM", "INFO"]
    assert len(data["summary"]["top_risks"]) == 1  # seul le HIGH


def test_html_renders():
    rb = ReportBuilder(_sample_findings(), target="127.0.0.1")
    html = rb.to_html()
    assert "<!doctype html>" in html.lower()
    assert "admin:password" in html
    assert "Résumé exécutif" in html
    assert "border-left-color" in html


def test_empty_report():
    rb = ReportBuilder([], target="127.0.0.1")
    data = json.loads(rb.to_json())
    assert data["summary"]["total"] == 0
    assert data["summary"]["posture"] == "INFO"
    assert "Aucun finding" in rb.to_html()
