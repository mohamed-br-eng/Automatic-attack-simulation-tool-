"""CVSS 4.0 scoring tests (P4)."""
import pytest

from core import Severity
from scoring.cvss4 import (
    CvssError, parse_vector, nomenclature, score, risk_priority,
)

# A full Base vector, CRITICAL severity expected.
V_CRIT = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
          "VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
# Low base (little impact, local access).
V_LOW = ("CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/"
         "VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")


def test_parse_valid():
    m = parse_vector(V_CRIT)
    assert m["AV"] == "N" and m["VC"] == "H"


def test_parse_rejects_bad_prefix():
    with pytest.raises(CvssError):
        parse_vector("CVSS:3.1/AV:N/AC:L")


def test_parse_rejects_unknown_metric():
    with pytest.raises(CvssError):
        parse_vector("CVSS:4.0/AV:N/ZZ:X")


def test_parse_rejects_missing_base():
    with pytest.raises(CvssError):
        parse_vector("CVSS:4.0/AV:N/AC:L")  # base incomplete


def test_score_bands():
    high = score(V_CRIT)
    assert high.base_score >= 9.0
    assert high.severity == Severity.CRITICAL
    low = score(V_LOW)
    assert low.base_score < high.base_score
    assert low.severity in (Severity.INFO, Severity.LOW, Severity.MEDIUM)


def test_score_monotonic_range():
    s = score(V_CRIT)
    assert 0.0 <= s.base_score <= 10.0


def test_nomenclature():
    assert nomenclature(parse_vector(V_CRIT)) == "CVSS-B"
    assert nomenclature(parse_vector(V_CRIT + "/E:A")) == "CVSS-BT"
    assert nomenclature(parse_vector(V_CRIT + "/CR:H")) == "CVSS-BE"
    assert nomenclature(parse_vector(V_CRIT + "/E:A/CR:H")) == "CVSS-BTE"


def test_risk_priority_epss():
    # Same CVSS, but higher EPSS => higher priority.
    assert risk_priority(9.0, 0.9) > risk_priority(9.0, 0.01)
    # Unknown EPSS => returns the CVSS.
    assert risk_priority(7.5, None) == 7.5
