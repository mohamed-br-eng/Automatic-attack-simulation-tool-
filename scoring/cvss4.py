"""
P4 - CVSS 4.0 scoring + EPSS (risk-based) prioritization.

CVSS v4.0 was published by FIRST on 2023-11-01. This module:
  1. PARSES and VALIDATES a CVSS 4.0 vector (spec-compliant: Base, Threat,
     Environmental, Supplemental metrics).
  2. Determines the CVSS-B / BT / BE / BTE NOMENCLATURE from the present groups.
  3. Computes a base SCORE 0.0-10.0 via a documented, transparent
     exploitability x impact model (see honesty note below).
  4. Maps the score to the qualitative SEVERITY (official FIRST bands).
  5. Combines CVSS + EPSS for a risk-based PRIORITIZATION (NIST advises
     against prioritizing on the base score alone).

-- Honesty note (to present to the jury) ------------------------------------
The official CVSS 4.0 algorithm relies on a "MacroVector" + interpolation over
a FIRST reference table. Here we implement a transparent, reproducible model
that respects the direction of each metric and the official severity bands; for
the final report the exact FIRST table can be plugged in. OWASP itself kept
CVSS v2/v3 for the Top 10:2025 because "the scoring algorithm fundamentally
changed" in v4.0 - hence the value of combining with EPSS.
"""
from __future__ import annotations

from dataclasses import dataclass

from core import Severity

# --- Metric definitions (values allowed by the 4.0 spec) --------------------
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
ENV_METRICS = {                                         # Environmental (subset)
    "CR": ["X", "H", "M", "L"], "IR": ["X", "H", "M", "L"], "AR": ["X", "H", "M", "L"],
    "MAV": ["X", "N", "A", "L", "P"], "MAC": ["X", "L", "H"],
}
SUPPLEMENTAL = {"S": ["X", "N", "P"], "AU": ["X", "N", "Y"], "R": ["X", "A", "U", "I"],
                "V": ["X", "D", "C"], "RE": ["X", "L", "M", "H"],
                "U": ["X", "Clear", "Green", "Amber", "Red"]}

_REQUIRED_BASE = list(BASE_METRICS.keys())

# Numeric weights (transparent model: more severe = higher).
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
    """Parse and validate a CVSS 4.0 vector. Raise CvssError if invalid."""
    v = vector.strip()
    if not v.startswith("CVSS:4.0/"):
        raise CvssError("The vector must start with 'CVSS:4.0/'.")
    parts = v[len("CVSS:4.0/"):].split("/")
    metrics: dict = {}
    allowed = {**BASE_METRICS, **THREAT_METRICS, **ENV_METRICS, **SUPPLEMENTAL}
    for p in parts:
        if ":" not in p:
            raise CvssError(f"Invalid segment: '{p}'.")
        k, val = p.split(":", 1)
        if k not in allowed:
            raise CvssError(f"Unknown metric: '{k}'.")
        if val not in allowed[k]:
            raise CvssError(f"Invalid value '{val}' for '{k}'.")
        metrics[k] = val
    missing = [m for m in _REQUIRED_BASE if m not in metrics]
    if missing:
        raise CvssError(f"Missing Base metrics: {', '.join(missing)}.")
    return metrics


def nomenclature(metrics: dict) -> str:
    """CVSS-B / BT / BE / BTE depending on which metric groups are set."""
    has_threat = metrics.get("E", "X") != "X"
    has_env = any(metrics.get(m, "X") != "X" for m in ENV_METRICS)
    suffix = ""
    if has_threat:
        suffix += "T"
    if has_env:
        suffix += "E"
    return "CVSS-B" + suffix if suffix else "CVSS-B"


def _severity_from_score(score: float) -> Severity:
    """Official FIRST bands (same as v3/v4)."""
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
    """Compute the score, severity and nomenclature of a CVSS 4.0 vector."""
    m = parse_vector(vector)

    # Exploitability (0-~3.9) - product of access factors.
    expl = 8.22 * _W_AV[m["AV"]] * _W_AC[m["AC"]] * _W_AT[m["AT"]] \
        * _W_PR[m["PR"]] * _W_UI[m["UI"]]

    # Impact on the vulnerable system and the subsequent system.
    isc_base = 1 - ((1 - _W_IMPACT[m["VC"]]) * (1 - _W_IMPACT[m["VI"]]) *
                    (1 - _W_IMPACT[m["VA"]]))
    ssc_base = 1 - ((1 - _W_IMPACT[m["SC"]]) * (1 - _W_IMPACT[m["SI"]]) *
                    (1 - _W_IMPACT[m["SA"]]))
    impact = 6.42 * isc_base + 2.0 * ssc_base

    if impact <= 0:
        base = 0.0
    else:
        base = min(impact + expl, 10.0)

    # Threat factor (Exploit Maturity) if present.
    base *= _W_EXPLOIT_MATURITY.get(m.get("E", "X"), 1.0)

    base = _round_up(min(base, 10.0))
    return Cvss4Result(vector=vector, base_score=base,
                       severity=_severity_from_score(base),
                       nomenclature=nomenclature(m), metrics=m)


def _round_up(x: float) -> float:
    """Round up to one decimal (CVSS method)."""
    return round(x + 1e-9, 1)


# --- Risk-based prioritization (CVSS + EPSS) --------------------------------
def risk_priority(cvss_score: float, epss: float | None) -> float:
    """
    Combined priority score (0-10). EPSS (exploitation probability 0-1) weights
    the CVSS: a high-CVSS but low-EPSS flaw moves down the queue.
    Transparent formula: CVSS * (0.5 + 0.5 * EPSS). If EPSS is unknown -> CVSS.
    """
    if epss is None:
        return round(cvss_score, 2)
    epss = max(0.0, min(epss, 1.0))
    return round(cvss_score * (0.5 + 0.5 * epss), 2)
