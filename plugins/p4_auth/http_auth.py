"""
P4 — Brute force sur l'authentification HTTP (Basic & Digest), codée MAIN.
Catégorie : A07:2025 Authentication Failures.

Pas de bibliothèque d'auth : on forge nous-mêmes les en-têtes.
  - Basic  : Authorization: Basic base64(user:pass).
  - Digest : challenge-response MD5 (RFC 2617) — on parse le challenge
             WWW-Authenticate, puis on calcule
             HA1 = MD5(user:realm:pass)
             HA2 = MD5(method:uri)
             response = MD5(HA1:nonce:nc:cnonce:qop:HA2).

Le schéma (Basic ou Digest) est DÉTECTÉ depuis la réponse 401 du serveur.
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
    """Parse un en-tête WWW-Authenticate: Digest realm=..., nonce=..., qop=..."""
    scheme = "digest" if header.lower().startswith("digest") else "basic"
    params = dict(re.findall(r'(\w+)="?([^",]+)"?', header))
    params["_scheme"] = scheme
    return params


def digest_header(user: str, password: str, method: str, uri: str,
                  challenge: dict, cnonce: str | None = None, nc: str = "00000001") -> str:
    """Construit l'en-tête Authorization: Digest (qop=auth)."""
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
            # 1. Déclenche le challenge 401 pour détecter le schéma.
            try:
                probe = await client.get(url)
            except httpx.HTTPError as e:
                return [self._info(url, f"endpoint inaccessible: {e}")]

            if probe.status_code != 401:
                return [self._info(url, "pas d'authentification HTTP (401 attendu)")]

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
                    title=f"Auth HTTP {scheme.capitalize()} faible : {u}:{p}",
                    severity=Severity.HIGH, cvss_score=8.7,
                    cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                    evidence=f"Schéma {scheme}, realm='{challenge.get('realm','')}'. "
                             f"Identifiants {u}:{p} acceptés (HTTP non-401).",
                    recommendation=("Mots de passe forts, bannir Basic sur HTTP clair, "
                                    "préférer une auth applicative + MFA + lockout."),
                    target=url, plugin=self.name,
                    request=f"GET {url}  (Authorization: {scheme})"))

        if not findings:
            findings.append(self._info(url, "aucun identifiant HTTP faible trouvé"))
        return findings

    def _info(self, url: str, msg: str) -> Finding:
        return Finding(
            category="A07:2025 Authentication Failures",
            title="Auth HTTP : rien à signaler", severity=Severity.INFO,
            evidence=msg, recommendation="—", target=url, plugin=self.name)
