"""
Genere un rapport de demonstration (JSON + HTML) dans reports/.
    python -m reporting.demo
Sert d'exemple d'utilisation du ReportBuilder et de rendu visuel.
"""
from pathlib import Path

from core import Finding, Severity
from reporting import ReportBuilder

DEMO_FINDINGS = [
    Finding(
        category="A07:2025 Authentication Failures",
        title="Identifiants faibles valides : admin:password",
        severity=Severity.HIGH, cvss_score=8.7,
        cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
        evidence="Login=admin / Password=password accepte.\nToken CSRF gere: oui.",
        recommendation="Politique de mot de passe forte, verrouillage apres N echecs, MFA.",
        target="http://127.0.0.1:8080/login.php", plugin="bruteforce",
        request="POST /login.php (username=..., password=...)",
        response="HTTP 302 -> /index.php, 0 octet"),
    Finding(
        category="A01:2025 Broken Access Control",
        title="IDOR : acces a /api/user/2 sans autorisation",
        severity=Severity.MEDIUM, cvss_score=5.3, epss=0.08,
        evidence="GET /api/user/2 renvoie les donnees d'un autre utilisateur.",
        recommendation="Controle d'acces cote serveur (ownership check).",
        target="http://127.0.0.1:8080/api/user/2", plugin="access_control"),
    Finding(
        category="A07:2025 Authentication Failures",
        title="Absence de verrouillage de compte",
        severity=Severity.LOW, cvss_score=3.1,
        evidence="20 tentatives echouees sans blocage ni delai.",
        recommendation="Rate-limiting + lockout temporaire.",
        plugin="bruteforce"),
]


def main() -> None:
    out = Path("reports")
    out.mkdir(exist_ok=True)
    rb = ReportBuilder(DEMO_FINDINGS, target="127.0.0.1", scan_id="demo-001")
    rb.to_json(out / "demo.json")
    rb.to_html(out / "demo.html")
    print(f"Rapport genere : {out / 'demo.html'}  et  {out / 'demo.json'}")


if __name__ == "__main__":
    main()
