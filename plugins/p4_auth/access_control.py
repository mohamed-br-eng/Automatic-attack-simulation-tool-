"""
P4 - Broken Access Control / SSRF.
Category: A01:2025 Broken Access Control (which ABSORBS SSRF in 2025,
formerly A10:2021). Still #1 of the Top 10.

Three families of tests, all reimplemented:
  1. IDOR  : object-ID increment -> access to other users' resources.
  2. Dangerous HTTP methods : PUT / DELETE / TRACE enabled.
  3. SSRF  : probe cloud metadata (169.254.169.254), internal IPs,
             file:// scheme on a parameter that fetches a URL.

Inputs via ctx.extra (eventually provided by P3's crawler):
  - idor_url  : URL with {id} (e.g. "http://h/api/user/{id}"), baseline_id, id_range
  - methods_url : URL to probe for HTTP methods
  - ssrf_url + ssrf_param : endpoint that takes a URL parameter
"""
from __future__ import annotations

import asyncio
import re

import httpx

from core import AttackPlugin, Context, Finding, Severity, Target, register

_ERROR_SIG = re.compile(
    r"not found|404|403|forbidden|unauthorized|does not exist|error", re.I)
_METADATA_SIG = re.compile(
    r"ami-id|instance-id|iam/|meta-data|computeMetadata|security-credentials", re.I)
_PASSWD_SIG = re.compile(r"root:.*:0:0:", re.I)

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "PATCH"]
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:22/",
    "http://localhost/",
    "file:///etc/passwd",
]


@register
class AccessControlPlugin(AttackPlugin):
    name = "access_control"
    owasp_category = "A01:2025 Broken Access Control"

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        findings: list[Finding] = []
        async with httpx.AsyncClient(timeout=ctx.timeout,
                                     follow_redirects=False) as client:
            if ctx.extra.get("idor_url"):
                findings += await self._test_idor(client, ctx)
            if ctx.extra.get("methods_url"):
                findings += await self._test_methods(client, ctx)
            if ctx.extra.get("ssrf_url") and ctx.extra.get("ssrf_param"):
                findings += await self._test_ssrf(client, ctx)
        return findings

    # --- 1. IDOR ------------------------------------------------------------
    async def _test_idor(self, client, ctx: Context) -> list[Finding]:
        url_tpl: str = ctx.extra["idor_url"]          # ".../user/{id}"
        baseline_id = ctx.extra.get("baseline_id", 1)
        id_range = ctx.extra.get("id_range", range(baseline_id, baseline_id + 5))

        async def fetch(i):
            try:
                r = await client.get(url_tpl.format(id=i))
                return i, r
            except httpx.HTTPError:
                return i, None

        results = await asyncio.gather(*(fetch(i) for i in id_range))
        accessible = []
        for i, r in results:
            if r is None:
                continue
            body = r.text
            if r.status_code == 200 and len(body) > 0 and not _ERROR_SIG.search(body[:200]):
                accessible.append((i, len(body)))

        # Likely IDOR: several distinct objects accessible without auth.
        distinct_lengths = {ln for _, ln in accessible}
        findings = []
        if len(accessible) >= 2 and len(distinct_lengths) >= 2:
            ids = ", ".join(str(i) for i, _ in accessible)
            findings.append(Finding(
                category="A01:2025 Broken Access Control",
                title="Likely IDOR: sequential objects accessible without authorization",
                severity=Severity.HIGH, cvss_score=8.1,
                cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
                evidence=(f"IDs accessible via {url_tpl}: {ids}. "
                          f"200 responses with distinct content and no access control."),
                recommendation=("Enforce server-side ownership checks (does the current "
                                "user own the object?), use non-guessable identifiers (UUID)."),
                target=url_tpl, plugin=self.name))
        return findings

    # --- 2. Dangerous HTTP methods -----------------------------------------
    async def _test_methods(self, client, ctx: Context) -> list[Finding]:
        url = ctx.extra["methods_url"]
        findings = []
        # OPTIONS: read the Allow header.
        allow = ""
        try:
            r = await client.request("OPTIONS", url)
            allow = r.headers.get("allow", "")
        except httpx.HTTPError:
            pass

        async def probe(method):
            try:
                r = await client.request(method, url)
                return method, r.status_code, r.text[:200]
            except httpx.HTTPError:
                return method, 0, ""

        results = await asyncio.gather(*(probe(m) for m in DANGEROUS_METHODS))
        enabled = []
        for method, status, body in results:
            if method == "TRACE" and status == 200 and ("TRACE" in body or url in body):
                enabled.append("TRACE (Cross-Site Tracing possible)")
            elif method in ("PUT", "DELETE", "PATCH") and status in (200, 201, 204):
                enabled.append(f"{method} (write/delete allowed)")

        if enabled:
            findings.append(Finding(
                category="A01:2025 Broken Access Control",
                title="Dangerous HTTP methods enabled",
                severity=Severity.MEDIUM, cvss_score=6.5,
                evidence=(f"Methods accepted on {url}: {', '.join(enabled)}. "
                          f"Allow header='{allow}'."),
                recommendation=("Disable unnecessary methods (PUT, DELETE, TRACE, "
                                "PATCH) at the server/WAF level."),
                target=url, plugin=self.name))
        return findings

    # --- 3. SSRF ------------------------------------------------------------
    async def _test_ssrf(self, client, ctx: Context) -> list[Finding]:
        url = ctx.extra["ssrf_url"]
        param = ctx.extra["ssrf_param"]
        findings = []

        async def probe(payload):
            try:
                r = await client.get(url, params={param: payload})
                return payload, r.text
            except httpx.HTTPError:
                return payload, ""

        results = await asyncio.gather(*(probe(p) for p in SSRF_PAYLOADS))
        for payload, body in results:
            hit = None
            if _METADATA_SIG.search(body):
                hit = "cloud metadata exposed"
            elif _PASSWD_SIG.search(body):
                hit = "local file read (file://)"
            if hit:
                findings.append(Finding(
                    category="A01:2025 Broken Access Control",
                    title=f"SSRF: {hit}",
                    severity=Severity.HIGH, cvss_score=9.1,
                    cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:N/SA:N",
                    evidence=f"Payload '{payload}' on {url}?{param}= returned "
                             f"internal content.",
                    recommendation=("Strict allow-list of permitted hosts/schemes, "
                                    "block internal IPs and the file:// scheme, "
                                    "disable redirects."),
                    target=url, plugin=self.name))
        return findings
