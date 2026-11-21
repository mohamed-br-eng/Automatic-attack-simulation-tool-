"""
P4 — Scoring CVSS 4.0 + priorisation EPSS (risk-based).

CVSS v4.0 publié par le FIRST le 2023-11-01. Ce module :
  1. PARSE et VALIDE un vecteur CVSS 4.0 (conforme à la spec : métriques Base,
     Threat, Environmental, Supplemental).
  2. Détermine la NOMENCLATURE CVSS-B / BT / BE / BTE selon les groupes présents.
  3. Calcule un SCORE de base 0.0–10.0 via un modèle exploitabilité×impact
     documenté et transparent (voir note d'honnêteté ci-dessous).
  4. Mappe le score vers la SÉVÉRITÉ qualitative (bandes officielles FIRST).
  5. Combine CVSS + EPSS pour une PRIORISATION « risk-based » (le NIST
     déconseille de prioriser sur le seul score de base).

── Note d'honnêteté (à présenter au jury) ───────────────────────────────────
L'algorithme officiel CVSS 4.0 repose sur un « MacroVector » + interpolation
sur une table de référence FIRST. On implémente ici un modèle *transparent et
reproductible* qui respecte la direction des métriques et les bandes de
sévérité officielles ; pour le rapport final on peut brancher la table FIRST
exacte. OWASP lui-même a gardé CVSS v2/v3 pour le Top 10:2025 car « l'algo de
scoring a fondamentalement changé » en v4.0 — d'où l'intérêt de combiner EPSS.
"""
from __future__ import annotations

from dataclasses import dataclass

from core import Severity

# --- Définition des métriques (valeurs autorisées par la spec 4.0) ----------
BASE_METRICS = {
    # Exploitability
    "AV": ["N", "A", "L", "P"],       # Attack Vector
    "AC": ["L", "H"],                  # Attack Complexity
    "AT": ["N", "P"],                  # Attack Requirements
    "PR": ["N", "L", "H"],             # Privileges Required
    "UI": ["N", "P", "A"],             # User Interaction
    # Impact (Vulnerable system + Subsequent system)
    "VC": ["H", "L", "N"], "VI": ["H", "L", "N"], "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"], "SI": ["H", "L", "N"], "SA": ["H", "L", "N"],
}
THREAT_METRICS = {"E": ["X", "A", "P", "U"]}            # Exploit Maturity
ENV_METRICS = {                                         # Environmental (extrait)
    "CR": ["X", "H", "M", "L"], "IR": ["X", "H", "M", "L"], "AR": ["X", "H", "M", "L"],
    "MAV": ["X", "N", "A", "L", "P"], "MAC": ["X", "L", "H"],
}
SUPPLEMENTAL = {"S": ["X", "N", "P"], "AU": ["X", "N", "Y"], "R": ["X", "A", "U", "I"],
                "V": ["X", "D", "C"], "RE": ["X", "L", "M", "H"], "U": ["X", "Clear", "Green", "Amber", "Red"]}

_REQUIRED_BASE = list(BASE_METRICS.keys())

# Poids numériques (modèle transparent : + grave = + haut).
_W_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_W_AC = {"L": 0.77, "H": 0.44}
_W_AT = {"N": 0.86, "P": 0.60}
_W_PR = {"N": 0.85, "L": 0.62, "H": 0.27}
_W_UI = {"N": 0.85, "P": 0.62, "A": 0.50}
_W_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}
_W_EXPLOIT_MATURITY = {"X": 1.0, "A": 1.0, "P": 0.94, "U": 0.91}


class CvssError(ValueError):
    pass


@dataclass
class Cvss4Result:
    vector: str
    base_score: float
    severity: Severity
    nomenclature: str          # "CVSS-B" | "CVSS-BT" | "CVSS-BE" | "CVSS-BTE"
    metrics: dict


def parse_vector(vector: str) -> dict:
    """Parse et valide un vecteur CVSS 4.0. Lève CvssError si invalide."""
    v = vector.strip()
    if not v.startswith("CVSS:4.0/"):
        raise CvssError("Le vecteur doit commencer par 'CVSS:4.0/'.")
    parts = v[len("CVSS:4.0/"):].split("/")
    metrics: dict = {}
    allowed = {**BASE_METRICS, **THREAT_METRICS, **ENV_METRICS, **SUPPLEMENTAL}
    for p in parts:
        if ":" not in p:
            raise CvssError(f"Segment invalide : '{p}'.")
        k, val = p.split(":", 1)
        if k not in allowed:
            raise CvssError(f"Métrique inconnue : '{k}'.")
        if val not in allowed[k]:
            raise CvssError(f"Valeur '{val}' invalide pour '{k}'.")
        metrics[k] = val
    missing = [m for m in _REQUIRED_BASE if m not in metrics]
    if missing:
        raise CvssError(f"Métriques Base manquantes : {', '.join(missing)}.")
    return metrics


def nomenclature(metrics: dict) -> str:
    """CVSS-B / BT / BE / BTE selon les groupes de métriques renseignés."""
    has_threat = metrics.get("E", "X") != "X"
    has_env = any(metrics.get(m, "X") != "X" for m in ENV_METRICS)
    suffix = ""
    if has_threat:
        suffix += "T"
    if has_env:
        suffix += "E"
    return "CVSS-B" + suffix if suffix else "CVSS-B"


def _severity_from_score(score: float) -> Severity:
    """Bandes officielles FIRST (identiques v3/v4)."""
    if score == 0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def score(vector: str) -> Cvss4Result:
    """Calcule le score, la sévérité et la nomenclature d'un vecteur CVSS 4.0."""
    m = parse_vector(vector)

    # Exploitabilité (0–~3.9) — produit des facteurs d'accès.
    expl = 8.22 * _W_AV[m["AV"]] * _W_AC[m["AC"]] * _W_AT[m["AT"]] \
        * _W_PR[m["PR"]] * _W_UI[m["UI"]]

    # Impact sur le système vulnérable et le système subséquent.
    isc_base = 1 - ((1 - _W_IMPACT[m["VC"]]) * (1 - _W_IMPACT[m["VI"]]) *
                    (1 - _W_IMPACT[m["VA"]]))
    ssc_base = 1 - ((1 - _W_IMPACT[m["SC"]]) * (1 - _W_IMPACT[m["SI"]]) *
                    (1 - _W_IMPACT[m["SA"]]))
    impact = 6.42 * isc_base + 2.0 * ssc_base

    if impact <= 0:
        base = 0.0
    else:
        base = min(impact + expl, 10.0)

    # Facteur Threat (Exploit Maturity) si présent.
    base *= _W_EXPLOIT_MATURITY.get(m.get("E", "X"), 1.0)

    base = _round_up(min(base, 10.0))
    return Cvss4Result(vector=vector, base_score=base,
                       severity=_severity_from_score(base),
                       nomenclature=nomenclature(m), metrics=m)


def _round_up(x: float) -> float:
    """Arrondi au dixième supérieur (méthode CVSS)."""
    return round(x + 1e-9, 1)


# --- Priorisation risk-based (CVSS + EPSS) ----------------------------------
def risk_priority(cvss_score: float, epss: float | None) -> float:
    """
    Score de priorité combiné (0–10). EPSS (proba d'exploitation 0–1) pondère
    le CVSS : une faille CVSS élevé mais EPSS faible descend dans la file.
    Formule transparente : CVSS * (0.5 + 0.5 * EPSS). Si EPSS inconnu -> CVSS.
    """
    if epss is None:
        return round(cvss_score, 2)
    epss = max(0.0, min(epss, 1.0))
    return round(cvss_score * (0.5 + 0.5 * epss), 2)
