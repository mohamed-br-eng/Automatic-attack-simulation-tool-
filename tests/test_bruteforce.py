"""
Tests du module brute force (P4) SANS cible reelle : on simule un mini-DVWA
avec respx. Chaque GET /login renvoie un token CSRF unique a usage unique,
et le POST n'accepte admin/password QUE si le token renvoye est le dernier emis.
"""
import re
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
    """Mini serveur avec token CSRF a usage unique (patron DVWA)."""

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
        # Le token doit etre celui emis en dernier (usage unique).
        token_ok = token == self._valid_token
        self._valid_token = None  # consomme
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
    assert len(hits) == 1, f"attendu 1 hit, obtenu: {[f.title for f in findings]}"
    assert hits[0].severity.value == "HIGH"
    assert "CSRF gere: oui" in hits[0].evidence


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
    assert hits == [], f"faux positif: {[f.title for f in hits]}"
