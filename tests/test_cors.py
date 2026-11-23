"""
P2 web attack - CORS misconfiguration tests. A fake server reflects (or not)
the Origin header into ACAO, via respx (no real traffic).
"""
import httpx
import pytest
import respx

from core import Context, Target
from plugins.p2_web.cors import CorsMisconfigPlugin, classify

URL = "http://127.0.0.1:8080"


def test_classify_reflected_with_credentials_is_high():
    reason, sev, score = classify("https://evil.example",
                                  "https://evil.example", "true")
    assert sev.value == "HIGH"


def test_classify_reflected_without_credentials_is_medium():
    _, sev, _ = classify("https://evil.example", "https://evil.example", None)
    assert sev.value == "MEDIUM"


def test_classify_safe_returns_none():
    assert classify("https://evil.example", "https://trusted.example", "true") is None
    assert classify("https://evil.example", None, None) is None


def test_classify_wildcard_is_info_observation():
    reason, sev, score = classify("https://evil.example", "*", None)
    assert sev.value == "INFO" and score == 0.0


def _reflect_origin(request):
    origin = request.headers.get("origin", "")
    return httpx.Response(200, headers={
        "access-control-allow-origin": origin,       # naive reflection
        "access-control-allow-credentials": "true",
    })


@pytest.mark.asyncio
async def test_cors_detects_reflected_origin_with_credentials():
    with respx.mock(assert_all_called=False) as mock:
        mock.get(URL).mock(side_effect=_reflect_origin)
        ctx = Context(authorized=True, extra={"cors_url": URL})
        findings = await CorsMisconfigPlugin().run(Target(host="127.0.0.1", port=8080), ctx)

    highs = [f for f in findings if f.severity.value == "HIGH"]
    assert highs, [f.title for f in findings]
    assert "credentials" in highs[0].evidence.lower()


@pytest.mark.asyncio
async def test_cors_safe_server_no_finding():
    with respx.mock(assert_all_called=False) as mock:
        mock.get(URL).mock(return_value=httpx.Response(200, headers={
            "access-control-allow-origin": "https://trusted.example"}))
        ctx = Context(authorized=True, extra={"cors_url": URL})
        findings = await CorsMisconfigPlugin().run(Target(host="127.0.0.1", port=8080), ctx)

    assert all(f.severity.value == "INFO" for f in findings)
