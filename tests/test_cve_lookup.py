"""
P2 CVE-lookup tests. Offline mode is deterministic; online mode is exercised
against mocked NVD / EPSS / CISA-KEV endpoints with respx.
"""
import httpx
import pytest
import respx

from core import Context, Target
from plugins.p2_network.cve_lookup import (
    CveLookupPlugin, EPSS_API, KEV_FEED, NVD_API, match_offline, _le,
)

TARGET = Target(host="127.0.0.1")


def test_version_comparison():
    assert _le("2.4.49", "2.4.49")
    assert _le("2.4.1", "2.4.49")
    assert not _le("2.4.50", "2.4.49")


def test_match_offline_vsftpd_backdoor():
    hits = match_offline("vsftpd", "2.3.4")
    assert len(hits) == 1 and hits[0]["cve"] == "CVE-2011-2523"
    assert match_offline("vsftpd", "3.0.3") == []  # not the backdoored version


@pytest.mark.asyncio
async def test_cve_offline_flags_known_cve_and_kev():
    ctx = Context(authorized=True, extra={"services": [
        {"vendor": "vsftpd", "product": "vsftpd", "version": "2.3.4",
         "port": 21, "cpe": "cpe:2.3:a:vsftpd:vsftpd:2.3.4:*:*:*:*:*:*:*"}]})
    findings = await CveLookupPlugin().run(TARGET, ctx)
    hit = next(f for f in findings if "CVE-2011-2523" in f.title)
    assert hit.severity.value == "CRITICAL"
    assert hit.epss == 0.94
    assert "KEV" in hit.title


@pytest.mark.asyncio
async def test_cve_no_services():
    ctx = Context(authorized=True, extra={})
    findings = await CveLookupPlugin().run(TARGET, ctx)
    assert findings[0].severity.value == "INFO"


@pytest.mark.asyncio
async def test_cve_online_with_mocked_apis():
    nvd_payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2018-15473",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3}}]},
        "descriptions": [{"lang": "en", "value": "OpenSSH username enumeration."}],
    }}]}
    epss_payload = {"data": [{"cve": "CVE-2018-15473", "epss": "0.89"}]}
    kev_payload = {"vulnerabilities": [{"cveID": "CVE-2021-41773"}]}

    with respx.mock(assert_all_called=False) as mock:
        mock.get(NVD_API).mock(return_value=httpx.Response(200, json=nvd_payload))
        mock.get(EPSS_API).mock(return_value=httpx.Response(200, json=epss_payload))
        mock.get(KEV_FEED).mock(return_value=httpx.Response(200, json=kev_payload))

        ctx = Context(authorized=True, timeout=5.0, extra={
            "cve_online": True,
            "services": [{"vendor": "openbsd", "product": "openssh",
                          "version": "7.4", "port": 22,
                          "cpe": "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"}]})
        findings = await CveLookupPlugin().run(TARGET, ctx)

    hit = next(f for f in findings if "CVE-2018-15473" in f.title)
    assert hit.epss == 0.89
    assert hit.cvss_score == 5.3
