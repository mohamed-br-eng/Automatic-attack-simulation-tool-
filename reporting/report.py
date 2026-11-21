"""
P4 - Reporting engine.

Standard pipeline of professional scanners: JSON (source of truth) -> HTML
(Jinja2, dark theme) -> PDF (WeasyPrint). JSON is the most important format:
it feeds the GUI (P5), the API (P1), the before/after diff and CI/CD.

Usage:
    builder = ReportBuilder(findings, target="127.0.0.1", scan_id="...")
    builder.to_json("reports/scan.json")
    builder.to_html("reports/scan.html")
    builder.to_pdf("reports/scan.pdf")   # requires weasyprint

Severity colors follow the validated, brand-neutral status palette from the
`dataviz` skill (industry-standard security convention: red / orange / amber /
blue / grey), deliberately NOT a Claude/Anthropic brand palette.
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

# Sort order and weight (most to least severe).
SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
]
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# dataviz status palette (brand-neutral, validated >= 3:1 on dark surface).
SEVERITY_COLORS = {
    Severity.CRITICAL: "#d03b3b",   # critical
    Severity.HIGH: "#ec835a",       # serious
    Severity.MEDIUM: "#fab219",     # warning
    Severity.LOW: "#3987e5",        # series blue (dark step)
    Severity.INFO: "#898781",       # muted
}


@dataclass
class ReportMeta:
    target: str = ""
    scan_id: str = ""
    tool: str = "Automatic Attacks Simulation Tool"
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReportBuilder:
    """Builds a multi-format report from a list of Finding objects."""

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

    # --- Executive summary --------------------------------------------------
    def summary(self) -> dict:
        counts = Counter(f.severity for f in self.findings)
        by_sev = {s.value: counts.get(s, 0) for s in SEVERITY_ORDER}
        # Overall posture = worst severity present.
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

    # --- JSON (source of truth) --------------------------------------------
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

    # --- HTML (Jinja2, dark theme) -----------------------------------------
    def to_html(self, path: str | Path | None = None) -> str:
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        env.filters["sev_color"] = lambda s: SEVERITY_COLORS.get(
            Severity(s) if not isinstance(s, Severity) else s, "#898781")
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

    # --- PDF (WeasyPrint, executive deliverable) ---------------------------
    def to_pdf(self, path: str | Path) -> None:
        try:
            from weasyprint import HTML  # late import: heavy dependency
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "WeasyPrint not installed. `pip install weasyprint` "
                "(+ GTK on Windows). HTML and JSON remain available."
            ) from e
        html = self.to_html()
        HTML(string=html).write_pdf(str(path))
