"""
P2 DoS tests. The point here is the SAFETY GUARDS: DoS must refuse unless
(authorized AND private AND enable_dos). The HTTP flood is exercised offline
via respx (no real traffic leaves the test).
"""
import httpx
import pytest
import respx

from core import Context, Target
from plugins.p2_network.dos import (
    HttpFloodPlugin, SlowlorisPlugin, SynFloodPlugin,
)

TARGET = Target(host="127.0.0.1", port=80)


@pytest.mark.asyncio
async def test_dos_refused_without_enable_flag():
    ctx = Context(authorized=True)  # authorized + private, but no enable_dos
    findings = await SlowlorisPlugin().run(TARGET, ctx)
    assert findings[0].severity.value == "INFO"
    assert "safety guard" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_dos_refused_without_authorization():
    ctx = Context(authorized=False, extra={"enable_dos": True})
    findings = await HttpFloodPlugin().run(TARGET, ctx)
    assert findings[0].severity.value == "INFO"
    assert "guard" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_dos_refused_on_public_target():
    ctx = Context(authorized=True, extra={"enable_dos": True})
    findings = await SynFloodPlugin().run(Target(host="8.8.8.8"), ctx)
    assert findings[0].severity.value == "INFO"


@pytest.mark.asyncio
async def test_http_flood_runs_and_measures_when_authorized():
    with respx.mock(assert_all_called=False) as mock:
        mock.get("http://127.0.0.1:80").mock(
            return_value=httpx.Response(200, text="ok"))
        ctx = Context(authorized=True, timeout=1.0, extra={
            "enable_dos": True, "dos_requests": 20,
            "dos_concurrency": 5, "dos_duration": 1.0})
        findings = await HttpFloodPlugin().run(TARGET, ctx)

    assert len(findings) == 1
    assert "http_flood" in findings[0].title
    assert "GET requests" in findings[0].evidence
