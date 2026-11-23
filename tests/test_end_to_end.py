"""End-to-end test: all P4 plugins -> findings -> report pipeline."""
import json
from pathlib import Path

import httpx
import pytest
import respx

from core import Context, Finding, Target, get_registry
from reporting import ReportBuilder
from scoring import score as cvss_score, CvssError

import plugins.p4_auth  # noqa: F401


def _enrich_cvss(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        if f.cvss_vector:
            try:
                result = cvss_score(f.cvss_vector)
                f.cvss_score = result.base_score
                f.severity = result.severity
            except CvssError:
                pass
    return findings


HOST = "http://127.0.0.1:8080"
LOGIN_URL = f"{HOST}/login.php"
IDOR_URL = f"{HOST}/api/user/{{id}}"
METHODS_URL = f"{HOST}/resource"
SSRF_URL = f"{HOST}/fetch"
AUTH_URL = f"{HOST}/secret"

CSRF_TOKEN = "tok-abc-123"
LOGIN_HTML = (
    f'<form action="{LOGIN_URL}" method="post">'
    f'<input type="text" name="username">'
    f'<input type="password" name="password">'
    f'<input type="hidden" name="user_token" value="{CSRF_TOKEN}">'
    f'<input type="submit"></form>'
)
FAIL_HTML = '<p>Login failed</p>' + LOGIN_HTML


@pytest.mark.asyncio
async def test_full_pipeline(tmp_path):
    """Run every P4 plugin, enrich CVSS, and generate a full report."""

    with respx.mock(assert_all_called=False) as mock:
        # --- Brute force mock (DVWA-like) ---
        _login_calls = {"n": 0}

        def login_handler(request):
            _login_calls["n"] += 1
            if request.method == "GET":
                return httpx.Response(200, text=LOGIN_HTML)
            data = str(request.content, "utf-8") if isinstance(request.content, bytes) else str(request.content)
            if "admin" in data and "password" in data:
                return httpx.Response(302, headers={"location": "/index.php"}, text="")
            return httpx.Response(200, text=FAIL_HTML)

        mock.route(url=LOGIN_URL).mock(side_effect=login_handler)
        mock.get(f"{HOST}/index.php").mock(
            return_value=httpx.Response(200, text="Welcome, admin! <a>Logout</a>"))

        # --- IDOR mock ---
        for i in range(1, 6):
            mock.get(f"{HOST}/api/user/{i}").mock(
                return_value=httpx.Response(
                    200, text=f'{{"id":{i},"email":"u{i}@x.com","data":"{"x"*i}"}}'))

        # --- HTTP methods mock ---
        mock.route(method="OPTIONS", url=METHODS_URL).mock(
            return_value=httpx.Response(200, headers={"allow": "GET,PUT,DELETE"}))
        mock.route(method="PUT", url=METHODS_URL).mock(
            return_value=httpx.Response(201))
        mock.route(method="DELETE", url=METHODS_URL).mock(
            return_value=httpx.Response(204))
        mock.route(method="TRACE", url=METHODS_URL).mock(
            return_value=httpx.Response(405))
        mock.route(method="PATCH", url=METHODS_URL).mock(
            return_value=httpx.Response(405))

        # --- SSRF mock ---
        def ssrf_handler(request):
            target = request.url.params.get("url", "")
            if "169.254.169.254" in target:
                return httpx.Response(200, text="ami-id\ninstance-id\niam/security-credentials/")
            return httpx.Response(200, text="ok")
        mock.get(SSRF_URL).mock(side_effect=ssrf_handler)

        # --- HTTP Basic auth mock ---
        def auth_handler(request):
            auth = request.headers.get("authorization", "")
            if not auth:
                return httpx.Response(401, headers={"www-authenticate": 'Basic realm="lab"'})
            if auth == "Basic YWRtaW46cGFzc3dvcmQ=":  # admin:password
                return httpx.Response(200, text="secret")
            return httpx.Response(401, headers={"www-authenticate": 'Basic realm="lab"'})
        mock.get(AUTH_URL).mock(side_effect=auth_handler)

        # --- Run all plugins ---
        ctx = Context(authorized=True, extra={
            "login_url": LOGIN_URL,
            "users": ["admin"], "passwords": ["wrong", "password"],
            "idor_url": IDOR_URL, "baseline_id": 1, "id_range": range(1, 6),
            "methods_url": METHODS_URL,
            "ssrf_url": SSRF_URL, "ssrf_param": "url",
            "auth_url": AUTH_URL,
        })
        target = Target(host="127.0.0.1", port=8080)
        registry = get_registry()
        assert len(registry) >= 3, f"Expected >=3 plugins, got {list(registry)}"

        all_findings: list[Finding] = []
        for name, plugin_cls in registry.items():
            plugin = plugin_cls()
            findings = await plugin.run(target, ctx)
            all_findings.extend(findings)

    all_findings = _enrich_cvss(all_findings)

    # --- Assertions on findings ---
    titles = [f.title for f in all_findings]
    assert any("admin:password" in t for t in titles), f"Brute force hit missing: {titles}"
    assert any("IDOR" in t for t in titles), f"IDOR finding missing: {titles}"
    assert any("Dangerous HTTP methods" in t for t in titles), f"Methods finding missing: {titles}"
    assert any("SSRF" in t for t in titles), f"SSRF finding missing: {titles}"
    assert any("Basic" in t for t in titles), f"HTTP auth finding missing: {titles}"

    for f in all_findings:
        if f.cvss_vector:
            assert f.cvss_score > 0, f"CVSS not enriched for {f.title}"

    # --- Generate report ---
    rb = ReportBuilder(all_findings, target="127.0.0.1", scan_id="e2e-test")
    json_text = rb.to_json(tmp_path / "e2e.json")
    html_text = rb.to_html(tmp_path / "e2e.html")

    data = json.loads(json_text)
    assert data["summary"]["total"] >= 5
    assert data["summary"]["posture"] in ("HIGH", "CRITICAL")
    assert "Executive Summary" in html_text
    assert len(data["findings"]) >= 5
