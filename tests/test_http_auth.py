"""Tests de l'auth HTTP Basic/Digest codee main (P4)."""
import base64
import hashlib

import httpx
import pytest
import respx

from core import Context, Target
from plugins.p4_auth.http_auth import (
    basic_header, digest_header, parse_challenge, HttpAuthPlugin,
)

URL = "http://127.0.0.1:8080/secret"


def _md5(s): return hashlib.md5(s.encode()).hexdigest()


def test_basic_header():
    assert basic_header("admin", "password") == "Basic " + \
        base64.b64encode(b"admin:password").decode()


def test_parse_challenge_digest():
    h = 'Digest realm="area", nonce="abc123", qop="auth", opaque="xyz"'
    c = parse_challenge(h)
    assert c["_scheme"] == "digest"
    assert c["realm"] == "area" and c["nonce"] == "abc123"


@pytest.mark.asyncio
async def test_basic_bruteforce():
    good = basic_header("admin", "password")

    def handler(request):
        auth = request.headers.get("authorization", "")
        if not auth:
            return httpx.Response(401, headers={"www-authenticate": 'Basic realm="area"'})
        if auth == good:
            return httpx.Response(200, text="secret content")
        return httpx.Response(401, headers={"www-authenticate": 'Basic realm="area"'})

    with respx.mock(assert_all_called=False) as mock:
        mock.get(URL).mock(side_effect=handler)
        ctx = Context(authorized=True, extra={
            "auth_url": URL, "users": ["admin"],
            "passwords": ["wrong", "password"]})
        findings = await HttpAuthPlugin().run(Target(host="127.0.0.1"), ctx)

    hits = [f for f in findings if "admin:password" in f.title]
    assert len(hits) == 1
    assert "Basic" in hits[0].title


@pytest.mark.asyncio
async def test_digest_bruteforce():
    realm, nonce = "protected", "deadbeef"

    def handler(request):
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("digest"):
            return httpx.Response(401, headers={
                "www-authenticate": f'Digest realm="{realm}", nonce="{nonce}", qop="auth"'})
        # Re-calcule la reponse attendue pour admin:secret et compare.
        import re
        params = dict(re.findall(r'(\w+)="?([^",]+)"?', auth))
        ha1 = _md5(f'admin:{realm}:secret')
        ha2 = _md5(f'GET:{params.get("uri","")}')
        expected = _md5(f'{ha1}:{nonce}:{params.get("nc","")}:'
                        f'{params.get("cnonce","")}:auth:{ha2}')
        if params.get("username") == "admin" and params.get("response") == expected:
            return httpx.Response(200, text="ok")
        return httpx.Response(401, headers={
            "www-authenticate": f'Digest realm="{realm}", nonce="{nonce}", qop="auth"'})

    with respx.mock(assert_all_called=False) as mock:
        mock.get(URL).mock(side_effect=handler)
        ctx = Context(authorized=True, extra={
            "auth_url": URL, "users": ["admin"],
            "passwords": ["nope", "secret"]})
        findings = await HttpAuthPlugin().run(Target(host="127.0.0.1"), ctx)

    hits = [f for f in findings if "admin:secret" in f.title]
    assert len(hits) == 1
    assert "Digest" in hits[0].title
