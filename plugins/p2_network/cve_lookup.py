"""
P2 - CVE / vulnerable-version detection from fingerprints (reimplemented).
Category: A03:2025 Software Supply Chain Failures (vulnerable/outdated components).

Two sub-tasks (well-documented pattern, cf. arXiv 2206.14539):
  1. Build a CPE (vendor:product:version) from the banner fingerprint (P2.banner).
  2. Query a CVE source and enrich it for a modern, risk-based prioritisation:
       - NVD API 2.0 (NIST)                -> CVE id, CVSS score, severity
       - EPSS (FIRST)                      -> 30-day exploitation probability
       - CISA KEV                          -> exploited in the wild (yes/no)

OFFLINE MODE (default, recommended for the demo): a small bundled database of
iconic CVEs avoids the NVD rate-limit (5 req / 30 s without an API key) and any
Internet dependency during the soutenance -- a real engineering reflex to show.
Set ctx.extra["cve_online"]=True to hit the live APIs instead.
"""
from __future__ import annotations

import asyncio

import httpx

from core import AttackPlugin, Context, Finding, Severity, Target, register

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# --- Offline demo database --------------------------------------------------
# product -> list of {max_version, cve, cvss, severity, epss, kev, summary}.
# A finding is raised when the detected version is <= max_version.
OFFLINE_DB: dict[str, list[dict]] = {
    "vsftpd": [{
        "exact": "2.3.4", "cve": "CVE-2011-2523", "cvss": 9.8,
        "severity": "CRITICAL", "epss": 0.94, "kev": True,
        "summary": "vsftpd 2.3.4 ships a backdoor opening a root shell on 6200/tcp.",
    }],
    "http_server": [{  # Apache httpd
        "max": "2.4.49", "cve": "CVE-2021-41773", "cvss": 7.5,
        "severity": "HIGH", "epss": 0.97, "kev": True,
        "summary": "Apache 2.4.49 path traversal / RCE (CVE-2021-41773).",
    }],
    "openssh": [{
        "max": "7.7", "cve": "CVE-2018-15473", "cvss": 5.3,
        "severity": "MEDIUM", "epss": 0.89, "kev": False,
        "summary": "OpenSSH <= 7.7 username enumeration via auth timing.",
    }],
    "openssl": [{
        "max": "1.0.1f", "cve": "CVE-2014-0160", "cvss": 7.5,
        "severity": "HIGH", "epss": 0.97, "kev": True,
        "summary": "OpenSSL Heartbleed memory disclosure (CVE-2014-0160).",
    }],
    "php": [{
        "max": "5.4.1", "cve": "CVE-2012-1823", "cvss": 9.8,
        "severity": "CRITICAL", "epss": 0.97, "kev": True,
        "summary": "PHP-CGI argument injection / RCE (CVE-2012-1823).",
    }],
}

_SEV = {"INFO": Severity.INFO, "LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}


def _version_tuple(v: str) -> tuple:
    """Loose version parse ('2.4.49' -> (2,4,49)); non-numeric parts -> 0."""
    out = []
    for part in str(v).replace("-", ".").replace("p", ".").split("."):
        digits = "".join(c for c in part if c.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def _le(a: str, b: str) -> bool:
    return _version_tuple(a) <= _version_tuple(b)


def match_offline(product: str, version: str) -> list[dict]:
    """Return offline CVE entries whose version condition the service matches."""
    hits = []
    for entry in OFFLINE_DB.get(product, []):
        if "exact" in entry and version == entry["exact"]:
            hits.append(entry)
        elif "max" in entry and version and _le(version, entry["max"]):
            hits.append(entry)
    return hits


@register
class CveLookupPlugin(AttackPlugin):
    name = "cve_lookup"
    owasp_category = "A03:2025 Software Supply Chain Failures"

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        services: list[dict] = ctx.extra.get("services", [])
        if not services:
            return [Finding(
                category=self.owasp_category,
                title="No fingerprinted service to correlate with CVEs",
                severity=Severity.INFO,
                evidence="Run the banner plugin first to populate ctx.extra['services'].",
                recommendation="Chain: port_scan -> banner -> cve_lookup.",
                target=target.host, plugin=self.name)]

        online = bool(ctx.extra.get("cve_online"))
        findings: list[Finding] = []
        for svc in services:
            product = svc.get("product")
            version = svc.get("version", "")
            if not product or not version:
                continue
            if online:
                findings += await self._lookup_online(target, svc, ctx)
            else:
                findings += self._lookup_offline(target, svc)

        if not findings:
            findings.append(Finding(
                category=self.owasp_category,
                title="No known CVE matched the detected versions",
                severity=Severity.INFO,
                evidence=f"Checked {len(services)} service(s) "
                         f"({'online NVD' if online else 'offline DB'}).",
                recommendation="Keep components patched and monitor new CVEs.",
                target=target.host, plugin=self.name))
        return findings

    # --- offline ------------------------------------------------------------
    def _lookup_offline(self, target, svc) -> list[Finding]:
        findings = []
        for e in match_offline(svc["product"], svc["version"]):
            findings.append(self._cve_finding(
                target, svc, e["cve"], e["cvss"], _SEV[e["severity"]],
                e["epss"], e["kev"], e["summary"]))
        return findings

    # --- online -------------------------------------------------------------
    async def _lookup_online(self, target, svc, ctx) -> list[Finding]:
        keyword = f"{svc['vendor']} {svc['product']} {svc['version']}".replace("_", " ")
        headers = {}
        if ctx.extra.get("nvd_api_key"):
            headers["apiKey"] = ctx.extra["nvd_api_key"]
        findings = []
        try:
            async with httpx.AsyncClient(timeout=ctx.timeout, headers=headers) as client:
                r = await client.get(NVD_API, params={"keywordSearch": keyword,
                                                       "resultsPerPage": 5})
                r.raise_for_status()
                vulns = r.json().get("vulnerabilities", [])
                cves = [self._parse_nvd(v) for v in vulns]
                cves = [c for c in cves if c]
                epss_map = await self._fetch_epss(client, [c["cve"] for c in cves])
                kev_set = await self._fetch_kev(client)
                for c in cves:
                    findings.append(self._cve_finding(
                        target, svc, c["cve"], c["cvss"],
                        self._sev_from_score(c["cvss"]),
                        epss_map.get(c["cve"]), c["cve"] in kev_set, c["summary"]))
        except httpx.HTTPError as e:
            findings.append(Finding(
                category=self.owasp_category,
                title="NVD lookup failed (falling back to offline DB)",
                severity=Severity.INFO,
                evidence=f"NVD error: {e}", recommendation="Retry or use offline mode.",
                target=target.host, plugin=self.name))
            findings += self._lookup_offline(target, svc)
        return findings

    @staticmethod
    def _parse_nvd(v: dict) -> dict | None:
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            return None
        score = 0.0
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0]["cvssData"].get("baseScore", 0.0)
                break
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:200]
                break
        return {"cve": cve_id, "cvss": score, "summary": desc}

    async def _fetch_epss(self, client, cve_ids: list[str]) -> dict[str, float]:
        if not cve_ids:
            return {}
        try:
            r = await client.get(EPSS_API, params={"cve": ",".join(cve_ids)})
            r.raise_for_status()
            return {d["cve"]: float(d["epss"]) for d in r.json().get("data", [])}
        except (httpx.HTTPError, KeyError, ValueError):
            return {}

    async def _fetch_kev(self, client) -> set[str]:
        try:
            r = await client.get(KEV_FEED)
            r.raise_for_status()
            return {v["cveID"] for v in r.json().get("vulnerabilities", [])}
        except (httpx.HTTPError, KeyError, ValueError):
            return set()

    @staticmethod
    def _sev_from_score(score: float) -> Severity:
        if score == 0:
            return Severity.INFO
        if score < 4.0:
            return Severity.LOW
        if score < 7.0:
            return Severity.MEDIUM
        if score < 9.0:
            return Severity.HIGH
        return Severity.CRITICAL

    # --- shared finding builder --------------------------------------------
    def _cve_finding(self, target, svc, cve, cvss, severity,
                     epss, kev, summary) -> Finding:
        kev_tag = " [CISA KEV: exploited in the wild]" if kev else ""
        return Finding(
            category=self.owasp_category,
            title=f"{cve} in {svc['product']} {svc['version']}{kev_tag}",
            severity=severity, cvss_score=cvss, epss=epss,
            evidence=(f"Service {svc['vendor']}:{svc['product']} "
                      f"{svc['version']} (port {svc.get('port')}) is affected.\n"
                      f"{summary}\nCPE: {svc.get('cpe', 'n/a')}\n"
                      f"EPSS: {epss if epss is not None else 'n/a'}"
                      f"{kev_tag}"),
            recommendation=(f"Upgrade {svc['product']} to a fixed version. "
                            + ("Prioritise: actively exploited (KEV)."
                               if kev else "Prioritise by CVSS x EPSS.")),
            target=f"{target.host}:{svc.get('port')}", plugin=self.name)
