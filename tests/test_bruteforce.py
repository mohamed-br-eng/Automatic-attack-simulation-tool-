"""
Brute-force module tests (P4) WITHOUT a real target: we simulate a mini-DVWA
with respx. Each GET /login returns a unique single-use CSRF token, and the
POST only accepts admin/password if the returned token is the last one issued.
"""
import itertools

import httpx
import pytest
import respx

from core import Context, Target
from plugins.p4_auth.bruteforce import (
    BruteForcePlugin, detect_login_form, extract_csrf,
)

LOGIN_URL = "http://127.0.0.1:8080/login.php"

LOGIN_PAGE = """
<html><body>
<form action="/login.php" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="user_token" value="{token}">
  <input type="submit" value="Login">
</form>
</body></html>
"""


class _FakeDVWA:
    """Mini server with a single-use CSRF token (DVWA pattern)."""

    def __init__(self):
        self._counter = itertools.count()
        self._valid_token = None

    def get_login(self, request):
        token = f"tok{next(self._counter)}"
        self._valid_token = token
        return httpx.Response(200, text=LOGIN_PAGE.format(token=token))

    def post_login(self, request):
        body = request.content.decode()
        data = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
        token = data.get("user_token", "")
        # The token must be the last one issued (single use).
        token_ok = token == self._valid_token
        self._valid_token = None  # consume
        if token_ok and data.get("username") == "admin" and data.get("password") == "password":
            return httpx.Response(302, headers={"location": "/index.php"},
                                  text="Welcome to the protected area")
        return httpx.Response(200, text="Username and/or password incorrect.")


@pytest.mark.asyncio
async def test_detect_login_form():
    form = detect_login_form(LOGIN_PAGE.format(token="abc"), LOGIN_URL)
    assert form is not None
    assert form.user_field == "username"
    assert form.pass_field == "password"
    assert form.csrf_field == "user_token"
    assert form.method == "post"


def test_extract_csrf():
    assert extract_csrf(LOGIN_PAGE.format(token="xyz123"), "user_token") == "xyz123"


@pytest.mark.asyncio
async def test_bruteforce_finds_admin_password_with_csrf():
    fake = _FakeDVWA()
    with respx.mock(assert_all_called=False) as mock:
        mock.get(LOGIN_URL).mock(side_effect=fake.get_login)
        mock.post(LOGIN_URL).mock(side_effect=fake.post_login)

        ctx = Context(authorized=True, max_concurrency=1,
                      extra={"login_url": LOGIN_URL,
                             "users": ["admin"],
                             "passwords": ["wrong", "password", "123456"]})
        findings = await BruteForcePlugin().run(
            Target(host="127.0.0.1", port=8080), ctx)

    hits = [f for f in findings if "admin:password" in f.title]
    assert len(hits) == 1, f"expected 1 hit, got: {[f.title for f in findings]}"
    assert hits[0].severity.value == "HIGH"
    assert "CSRF token handled: yes" in hits[0].evidence


@pytest.mark.asyncio
async def test_bruteforce_no_false_positive():
    fake = _FakeDVWA()
    with respx.mock(assert_all_called=False) as mock:
        mock.get(LOGIN_URL).mock(side_effect=fake.get_login)
        mock.post(LOGIN_URL).mock(side_effect=fake.post_login)

        ctx = Context(authorized=True, max_concurrency=1,
                      extra={"login_url": LOGIN_URL,
                             "users": ["admin"],
                             "passwords": ["wrong1", "wrong2", "nope"]})
        findings = await BruteForcePlugin().run(
            Target(host="127.0.0.1", port=8080), ctx)

    hits = [f for f in findings if f.severity.value == "HIGH"]
    assert hits == [], f"false positive: {[f.title for f in hits]}"
