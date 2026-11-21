"""
Central data model: Finding.

WARNING - SHARED CONTRACT (owned by P1 - Architect/Core).
This version is a PROPOSAL by P4 so the module can be built and tested
independently. To be reconciled with P1 during peer review (PR).
As long as the signature stays stable, all 5 modules remain parallelizable.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    """Qualitative severity derived from the CVSS 4.0 score (see scoring/cvss4.py)."""
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
    The JSON -> report -> GUI backbone.

    An attack plugin produces a list of Finding objects. The reporting pipeline
    (P4) and the dashboard (P5) consume ONLY this structure.
    """
    category: str                 # e.g. "A07:2025 Authentication Failures"
    title: str                    # short human-readable title
    severity: Severity            # derived from CVSS
    evidence: str                 # payload + request/response excerpt
    recommendation: str           # actionable remediation
    cvss_vector: str = ""         # e.g. "CVSS:4.0/AV:N/AC:L/..."
    cvss_score: float = 0.0       # base score 0.0 - 10.0
    epss: float | None = None     # exploitation probability (0-1), enrichment
    target: str = ""              # affected target (host:port or URL)
    plugin: str = ""              # emitting plugin name
    request: str = ""             # raw HTTP request (evidence)
    response: str = ""            # response excerpt (evidence)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=_now)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["timestamp"] = self.timestamp.isoformat()
        return d
