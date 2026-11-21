"""
Modèle de données central : Finding.

⚠️ CONTRAT PARTAGÉ (appartient à P1 — Architecte/Noyau).
Cette version est une PROPOSITION de P4 pour pouvoir travailler et tester
en autonomie. À réconcilier avec P1 lors d'une revue croisée (PR).
Tant que la signature reste stable, les 5 modules restent parallélisables.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    """Sévérité qualitative dérivée du score CVSS 4.0 (voir scoring/cvss4.py)."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Finding:
    """
    La colonne vertébrale JSON -> rapport -> GUI.

    Un plugin d'attaque produit une liste de Finding. Le pipeline de reporting
    (P4) et le dashboard (P5) ne consomment QUE cette structure.
    """
    category: str                 # ex. "A07:2025 Authentication Failures"
    title: str                    # titre court lisible
    severity: Severity            # dérivée du CVSS
    evidence: str                 # payload + extrait requête/réponse
    recommendation: str           # remédiation actionnable
    cvss_vector: str = ""         # ex. "CVSS:4.0/AV:N/AC:L/..."
    cvss_score: float = 0.0       # score base 0.0 - 10.0
    epss: float | None = None     # probabilité d'exploitation (0-1), enrichissement
    target: str = ""              # cible concernée (host:port ou URL)
    plugin: str = ""              # nom du plugin émetteur
    request: str = ""             # requête HTTP brute (preuve)
    response: str = ""            # extrait de réponse (preuve)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=_now)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["timestamp"] = self.timestamp.isoformat()
        return d
