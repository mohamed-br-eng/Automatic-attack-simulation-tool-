"""Tests du plugin access_control (IDOR / méthodes HTTP / SSRF) avec respx."""
import httpx
import pytest
import respx

from core import Context, Target
from plugins.p4_auth.access_control import AccessControlPlugin

HOST = "http://127.0.0.1:8080"


@pytest.mark.asyncio
async def test_idor_detected():
    with respx.mock(assert_all_called=False) as mock:
        # Chaque id renvoie un contenu distinct (objets d'utilisateurs differents).
        for i in range(1, 6):
            mock.get(f"{HOST}/api/user/{i}").mock(
                return_value=httpx.Response(200, text=f'{{"id":{i},"email":"u{i}@x.fr","x":"{"a"*i}"}}'))
        ctx = Context(authorized=True, extra={
            "idor_url": HOST + "/api/user/{id}",
            "baseline_id": 1, "id_range": range(1, 6)})
        findings = await AccessControlPlugin().run(Target(host="127.0.0.1"), ctx)
    idor = [f for f in findings if "IDOR" in f.title]
    assert len(idor) == 1
    assert idor[0].severity.value == "HIGH"


@pytest.mark.asyncio
async def test_idor_no_false_positive_when_all_404():
    with respx.mock(assert_all_called=False) as mock:
        for i in range(1, 6):
            mock.get(f"{HOST}/api/user/{i}").mock(
                return_value=httpx.Response(404, text="Not Found"))
        ctx = Context(authorized=True, extra={
            "idor_url": HOST + "/api/user/{id}", "id_range": range(1, 6)})
        findings = await AccessControlPlugin().run(Target(host="127.0.0.1"), ctx)
    assert [f for f in findings if "IDOR" in f.title] == []


@pytest.mark.asyncio
async def test_dangerous_methods():
    url = HOST + "/resource"
    with respx.mock(assert_all_called=False) as mock:
        mock.route(method="OPTIONS", url=url).mock(
            return_value=httpx.Response(200, headers={"allow": "GET,PUT,DELETE"}))
        mock.route(method="PUT", url=url).mock(return_value=httpx.Response(201))
        mock.route(method="DELETE", url=url).mock(return_value=httpx.Response(204))
        mock.route(method="TRACE", url=url).mock(return_value=httpx.Response(405))
        mock.route(method="PATCH", url=url).mock(return_value=httpx.Response(405))
        ctx = Context(authorized=True, extra={"methods_url": url})
        findings = await AccessControlPlugin().run(Target(host="127.0.0.1"), ctx)
    m = [f for f in findings if "Méthodes HTTP" in f.title]
    assert len(m) == 1
    assert "PUT" in m[0].evidence and "DELETE" in m[0].evidence


@pytest.mark.asyncio
async def test_ssrf_metadata():
    url = HOST + "/fetch"
    with respx.mock(assert_all_called=False) as mock:
        def handler(request):
            target = request.url.params.get("url", "")
            if "169.254.169.254" in target:
                return httpx.Response(200, text="ami-id\ninstance-id\niam/security-credentials/")
            return httpx.Response(200, text="ok")
        mock.get(url).mock(side_effect=handler)
        ctx = Context(authorized=True, extra={"ssrf_url": url, "ssrf_param": "url"})
        findings = await AccessControlPlugin().run(Target(host="127.0.0.1"), ctx)
    ssrf = [f for f in findings if "SSRF" in f.title]
    assert len(ssrf) == 1
    assert ssrf[0].severity.value == "HIGH"
