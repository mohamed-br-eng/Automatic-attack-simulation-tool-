"""
P2 (web) - CORS misconfiguration detection, reimplemented from scratch.
Category: A02:2025 Security Misconfiguration.

Cross-Origin Resource Sharing is controlled by the server's response headers:
  - Access-Control-Allow-Origin        (ACAO): which origin may read the response
  - Access-Control-Allow-Credentials   (ACAC): may the browser send cookies?

The DETECTION LOGIC (what the jury grades, not the payload list): we send the
same request with several crafted Origin headers and classify the ACAO/ACAC
reply. The dangerous combination is ACAO *reflecting an attacker origin* TOGETHER
WITH ACAC:true -> any site can read authenticated responses of the victim.

Crafted origins (each probes a classic server-side regex mistake):
  1. arbitrary       https://evil.example        -> naive full reflection
  2. null            null                        -> sandboxed iframe bypass
  3. suffix trick    https://target.evil.example -> startswith()/contains() bug
  4. prefix trick    https://evil-target.example -> endswith() bug
  5. subdomain       https://sub.<host>          -> over-broad *.host trust

Input: target.base_url, or ctx.extra["cors_url"] (e.g. an API endpoint from
P3's crawler). Each probe records the exact request/response as evidence.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

from core import AttackPlugin, Context, Finding, Severity, Target, register

EVIL = "https://evil.example"


def _origins_for(url: str) -> list[tuple[str, str]]:
    """Return (label, origin) probes, some derived from the target host."""
    host = urlparse(url).hostname or ""
    probes = [
        ("arbitrary-origin", EVIL),
        ("null-origin", "null"),
        ("suffix-trick", f"https://{host}.evil.example"),
        ("prefix-trick", f"https://evil-{host}.example"),
    ]
    if host:
        probes.append(("subdomain-trust", f"https://sub.{host}"))
    return probes


def classify(sent_origin: str, acao: str | None, acac: str | None) -> tuple[str, Severity, float] | None:
    """
    Decide whether an ACAO/ACAC pair is a vulnerability.
    Returns (reason, severity, cvss) or None if safe.
    """
    if not acao:
        return None
    acao = acao.strip()
    creds = (acac or "").strip().lower() == "true"

    # Reflecting the exact attacker origin is the core bug.
    reflected = acao == sent_origin or (sent_origin == "null" and acao == "null")

    if reflected and creds:
        return ("Origin reflected WITH credentials allowed: any site can read "
                "authenticated responses.", Severity.HIGH, 8.1)
    if reflected:
        return ("Attacker origin reflected in ACAO (no credentials): data "
                "readable cross-origin.", Severity.MEDIUM, 5.3)
    if acao == "*" and creds:
        # Browsers reject this combo, but it signals a broken config.
        return ("Wildcard ACAO combined with credentials (misconfiguration).",
                Severity.LOW, 3.7)
    if acao == "*":
        # Legitimate for truly public resources, but worth confirming that the
        # endpoint exposes no sensitive data cross-origin (low-noise INFO).
        return ("Permissive wildcard CORS (ACAO: *): confirm these endpoints "
                "expose no sensitive data cross-origin.", Severity.INFO, 0.0)
    return None


@register
class CorsMisconfigPlugin(AttackPlugin):
    name = "cors"
    owasp_category = "A02:2025 Security Misconfiguration"

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        url = ctx.extra.get("cors_url", target.base_url)
        probes = _origins_for(url)
        findings: list[Finding] = []
        seen: set[str] = set()

        async with httpx.AsyncClient(timeout=ctx.timeout,
                                     follow_redirects=False, verify=False) as client:
            async def probe(label: str, origin: str):
                try:
                    r = await client.get(url, headers={"Origin": origin})
                except httpx.HTTPError as e:
                    return label, origin, None, None, str(e)
                return (label, origin,
                        r.headers.get("access-control-allow-origin"),
                        r.headers.get("access-control-allow-credentials"), "")

            results = await asyncio.gather(*(probe(l, o) for l, o in probes))

        for label, origin, acao, acac, err in results:
            if err:
                continue
            verdict = classify(origin, acao, acac)
            if verdict is None:
                continue
            reason, sev, score = verdict
            dedup = f"{sev}|{reason[:30]}"
            if dedup in seen:
                continue
            seen.add(dedup)
            findings.append(Finding(
                category=self.owasp_category,
                title=f"CORS misconfiguration ({label})",
                severity=sev, cvss_score=score,
                cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
                evidence=(f"{reason}\nProbe: Origin: {origin}\n"
                          f"Response ACAO: {acao}\n"
                          f"Response ACAC: {acac}"),
                recommendation=("Validate Origin against a strict server-side "
                                "allow-list (exact match, not substring). Never "
                                "combine a reflected/arbitrary origin with "
                                "Access-Control-Allow-Credentials: true."),
                target=url, plugin=self.name,
                request=f"GET {url}  (Origin: {origin})",
                response=f"ACAO={acao}  ACAC={acac}"))

        if not findings:
            findings.append(Finding(
                category=self.owasp_category,
                title="No CORS misconfiguration detected",
                severity=Severity.INFO,
                evidence=f"Tested {len(probes)} crafted origins on {url}.",
                recommendation="Keep the strict Origin allow-list.",
                target=url, plugin=self.name))
        return findings
