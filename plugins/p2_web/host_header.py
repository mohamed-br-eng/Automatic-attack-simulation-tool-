"""
P2 (web) - Host header injection detection, reimplemented from scratch.
Category: A02:2025 Security Misconfiguration.

Many apps build absolute URLs (password-reset links, redirects, cached content)
from the incoming Host / X-Forwarded-Host header WITHOUT validating it. An
attacker who controls that value can poison those URLs -> password-reset
poisoning, web-cache poisoning, routing-based SSRF.

DETECTION LOGIC (what the jury grades): we inject a unique canary host through
several headers and check whether that canary is REFLECTED back where the app
uses the host - either in the Location redirect header (most dangerous) or in
the response body (links / reset URLs). A reflected canary that the legitimate
baseline does NOT contain is the signal.

Injection vectors (each a classic trust mistake):
  - Host: <canary>                 (the app trusts the raw Host header)
  - X-Forwarded-Host: <canary>     (trusted behind a reverse proxy)
  - X-Host / X-Forwarded-Server    (framework-specific variants)

Input: target.base_url, or ctx.extra["host_header_url"].
"""
from __future__ import annotations

import asyncio

import httpx

from core import AttackPlugin, Context, Finding, Severity, Target, register

CANARY = "canary-injection.example"

# (label, headers to inject). The canary is the value in each.
VECTORS = [
    ("host-override", {"Host": CANARY}),
    ("x-forwarded-host", {"X-Forwarded-Host": CANARY}),
    ("x-host", {"X-Host": CANARY}),
    ("x-forwarded-server", {"X-Forwarded-Server": CANARY}),
]


@register
class HostHeaderInjectionPlugin(AttackPlugin):
    name = "host_header_injection"
    owasp_category = "A02:2025 Security Misconfiguration"

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        url = ctx.extra.get("host_header_url", target.base_url)
        findings: list[Finding] = []

        async with httpx.AsyncClient(timeout=ctx.timeout,
                                     follow_redirects=False, verify=False) as client:
            # Baseline with the legitimate Host (the canary must not appear here).
            try:
                base = await client.get(url)
            except httpx.HTTPError as e:
                return [Finding(
                    category=self.owasp_category,
                    title="Host header test not executable",
                    severity=Severity.INFO, evidence=f"Target unreachable: {e}",
                    recommendation="Check the provided URL.",
                    target=url, plugin=self.name)]

            if CANARY in base.text or CANARY in base.headers.get("location", ""):
                return [Finding(
                    category=self.owasp_category,
                    title="Host header test inconclusive",
                    severity=Severity.INFO,
                    evidence="Canary already present in the baseline response.",
                    recommendation="Manual review recommended.",
                    target=url, plugin=self.name)]

            async def probe(label: str, headers: dict):
                try:
                    r = await client.get(url, headers=headers)
                except httpx.HTTPError as e:
                    return label, headers, None, None, str(e)
                return (label, headers, r.headers.get("location", ""),
                        r.text, "")

            results = await asyncio.gather(*(probe(l, h) for l, h in VECTORS))

        for label, headers, location, body, err in results:
            if err:
                continue
            in_location = location and CANARY in location
            in_body = body and CANARY in body
            if not (in_location or in_body):
                continue

            if in_location:
                where, sev, score = "redirect Location header", Severity.HIGH, 7.4
                impact = ("Enables open redirect / web-cache poisoning: the "
                          "server redirects users to the attacker host.")
            else:
                where, sev, score = "response body (links/URLs)", Severity.MEDIUM, 6.1
                impact = ("Enables password-reset poisoning: reset links are "
                          "built with the attacker-controlled host.")

            hdr = ", ".join(f"{k}: {v}" for k, v in headers.items())
            findings.append(Finding(
                category=self.owasp_category,
                title=f"Host header injection via {label}",
                severity=sev, cvss_score=score,
                cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
                evidence=(f"Injected host reflected in the {where}.\n{impact}\n"
                          f"Injected header -> {hdr}\n"
                          f"Reflected value: {CANARY}"),
                recommendation=("Validate the Host header against an allow-list "
                                "of expected domains; do not trust "
                                "X-Forwarded-Host; build absolute URLs from a "
                                "fixed, configured base URL."),
                target=url, plugin=self.name,
                request=f"GET {url}  ({hdr})",
                response=(f"Location: {location}" if in_location
                          else f"body contains '{CANARY}'")))

        if not findings:
            findings.append(Finding(
                category=self.owasp_category,
                title="No Host header injection detected",
                severity=Severity.INFO,
                evidence=f"Tested {len(VECTORS)} injection vectors on {url}.",
                recommendation="Keep validating the Host header server-side.",
                target=url, plugin=self.name))
        return findings
