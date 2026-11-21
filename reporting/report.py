"""
P4 — Moteur de rapport.

Pipeline standard des scanners pro : JSON (source de verite) -> HTML (Jinja2,
theme sombre) -> PDF (WeasyPrint). Le JSON est le format le plus important :
il alimente la GUI (P5), l'API (P1), le diff avant/apres et le CI/CD.

Usage :
    builder = ReportBuilder(findings, target="127.0.0.1", scan_id="...")
    builder.to_json("reports/scan.json")
    builder.to_html("reports/scan.html")
    builder.to_pdf("reports/scan.pdf")   # necessite weasyprint
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core import Finding, Severity

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Ordre de tri et poids (du plus grave au moins grave).
SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}


@dataclass
class ReportMeta:
    target: str = ""
    scan_id: str = ""
    tool: str = "Automatic Attacks Simulation Tool"
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReportBuilder:
    """Construit un rapport multi-format a partir d'une liste de Finding."""

    def __init__(self, findings: list[Finding], target: str = "",
                 scan_id: str = "", meta: ReportMeta | None = None) -> None:
        self.findings = self._sort(findings)
        self.meta = meta or ReportMeta(target=target, scan_id=scan_id)

    @staticmethod
    def _sort(findings: list[Finding]) -> list[Finding]:
        return sorted(
            findings,
            key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), -f.cvss_score),
        )

    # --- Resume executif ----------------------------------------------------
    def summary(self) -> dict:
        counts = Counter(f.severity for f in self.findings)
        by_sev = {s.value: counts.get(s, 0) for s in SEVERITY_ORDER}
        # Posture globale = pire severite presente.
        worst = next((s for s in SEVERITY_ORDER if counts.get(s, 0)), Severity.INFO)
        top_risks = [
            {"title": f.title, "severity": f.severity.value,
             "cvss_score": f.cvss_score, "category": f.category}
            for f in self.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ][:5]
        return {
            "total": len(self.findings),
            "by_severity": by_sev,
            "posture": worst.value,
            "top_risks": top_risks,
        }

    # --- JSON (source de verite) -------------------------------------------
    def to_dict(self) -> dict:
        return {
            "meta": self.meta.__dict__,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, path: str | Path | None = None, indent: int = 2) -> str:
        text = json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
        if path:
            Path(path).write_text(text, encoding="utf-8")
        return text

    # --- HTML (Jinja2, theme sombre) ---------------------------------------
    def to_html(self, path: str | Path | None = None) -> str:
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        env.filters["sev_color"] = lambda s: SEVERITY_COLORS.get(
            Severity(s) if not isinstance(s, Severity) else s, "#6b7280")
        template = env.get_template("report.html.j2")
        html = template.render(
            meta=self.meta,
            summary=self.summary(),
            findings=[f.to_dict() for f in self.findings],
            severity_order=[s.value for s in SEVERITY_ORDER],
        )
        if path:
            Path(path).write_text(html, encoding="utf-8")
        return html

    # --- PDF (WeasyPrint, livrable executif) -------------------------------
    def to_pdf(self, path: str | Path) -> None:
        try:
            from weasyprint import HTML  # import tardif : dependance lourde
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "WeasyPrint non installe. `pip install weasyprint` "
                "(+ GTK sur Windows). Le HTML et le JSON restent disponibles."
            ) from e
        html = self.to_html()
        HTML(string=html).write_pdf(str(path))
