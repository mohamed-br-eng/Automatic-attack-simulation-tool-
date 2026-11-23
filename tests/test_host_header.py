"""
P2 web attack - Host header injection tests. Fake servers reflect the injected
host either into the Location header (HIGH) or the body (MEDIUM), or ignore it
(safe), via respx.
"""
import httpx
import pytest
import respx

from core import Context, Target
from plugins.p2_web.host_header import CANARY, HostHeaderInjectionPlugin

URL = "http://127.0.0.1:8080"
TARGET = Target(host="127.0.0.1", port=8080)


def _reflect_in_location(request):
    # Trusts X-Forwarded-Host when building a redirect.
    xfh = request.headers.get("x-forwarded-host")
    host = xfh or request.headers.get("host", "")
    return httpx.Response(302, headers={"location": f"https://{host}/next"})


def _reflect_in_body(request):
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    return httpx.Response(200, text=f'<a href="https://{host}/reset">reset</a>')


def _safe(request):
    return httpx.Response(200, text='<a href="https://fixed.example/reset">reset</a>')


@pytest.mark.asyncio
async def test_host_header_reflected_in_location_is_high():
    with respx.mock(assert_all_called=False) as mock:
        mock.get(URL).mock(side_effect=_reflect_in_location)
        ctx = Context(authorized=True, extra={"host_header_url": URL})
        findings = await HostHeaderInjectionPlugin().run(TARGET, ctx)

    highs = [f for f in findings if f.severity.value == "HIGH"]
    assert highs, [f.title for f in findings]
    assert CANARY in highs[0].evidence


@pytest.mark.asyncio
async def test_host_header_reflected_in_body_is_medium():
    with respx.mock(assert_all_called=False) as mock:
        mock.get(URL).mock(side_effect=_reflect_in_body)
        ctx = Context(authorized=True, extra={"host_header_url": URL})
        findings = await HostHeaderInjectionPlugin().run(TARGET, ctx)

    assert any(f.severity.value == "MEDIUM" for f in findings), \
        [f.title for f in findings]


@pytest.mark.asyncio
async def test_host_header_safe_server_no_finding():
    with respx.mock(assert_all_called=False) as mock:
        mock.get(URL).mock(side_effect=_safe)
        ctx = Context(authorized=True, extra={"host_header_url": URL})
        findings = await HostHeaderInjectionPlugin().run(TARGET, ctx)

    assert all(f.severity.value == "INFO" for f in findings)
