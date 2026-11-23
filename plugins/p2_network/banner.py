"""
P2 - Banner grabbing + service / version fingerprinting (reimplemented).
Category: A02:2025 Security Misconfiguration (verbose version disclosure).

After the port scan found open ports, we connect and read what the service
announces:
  - TCP services (SSH, FTP, SMTP, ...) send a greeting banner on connect.
  - HTTP services need a request: we send a minimal GET and read the
    Server / X-Powered-By headers.

We then extract (product, version) with regexes and build a best-effort CPE
string (vendor:product:version). The result is written into
ctx.extra["services"] so the CVE plugin can map each version to known CVEs.
This is the "scan -> fingerprint -> CVE" chain documented in the project guide.
"""
from __future__ import annotations

import asyncio
import re

from core import AttackPlugin, Context, Finding, Severity, Target, register

HTTP_PORTS = {80, 443, 3000, 8000, 8080, 8443, 9200}

# (regex on the banner, vendor, product). Group 1 = version.
SERVICE_PATTERNS = [
    (re.compile(r"SSH-\d+\.\d+-OpenSSH[_-]([\w.]+)", re.I), "openbsd", "openssh"),
    (re.compile(r"vsFTPd\s+([\d.]+)", re.I), "vsftpd", "vsftpd"),
    (re.compile(r"ProFTPD\s+([\d.]+)", re.I), "proftpd", "proftpd"),
    (re.compile(r"Pure-FTPd", re.I), "pureftpd", "pure-ftpd"),
    (re.compile(r"Apache/([\d.]+)", re.I), "apache", "http_server"),
    (re.compile(r"nginx/([\d.]+)", re.I), "nginx", "nginx"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "microsoft", "iis"),
    (re.compile(r"lighttpd/([\d.]+)", re.I), "lighttpd", "lighttpd"),
    (re.compile(r"PHP/([\d.]+)", re.I), "php", "php"),
    (re.compile(r"OpenSSL/([\w.]+)", re.I), "openssl", "openssl"),
    (re.compile(r"Postfix", re.I), "postfix", "postfix"),
    (re.compile(r"Exim\s+([\d.]+)", re.I), "exim", "exim"),
    (re.compile(r"MySQL.*?([\d.]+)", re.I), "mysql", "mysql"),
    (re.compile(r"Redis.*?([\d.]+)", re.I), "redis", "redis"),
]


def build_cpe(vendor: str, product: str, version: str) -> str:
    """Best-effort CPE 2.3 string (vendor:product:version) for display/lookup."""
    v = version or "*"
    return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


def fingerprint(banner: str) -> dict | None:
    """Extract {vendor, product, version, cpe} from a raw banner, or None."""
    for pattern, vendor, product in SERVICE_PATTERNS:
        m = pattern.search(banner)
        if m:
            version = m.group(1) if m.groups() else ""
            return {
                "vendor": vendor,
                "product": product,
                "version": version,
                "cpe": build_cpe(vendor, product, version),
            }
    return None


async def grab_tcp_banner(host: str, port: int, timeout: float) -> str:
    """Read a service greeting banner (SSH/FTP/SMTP...) on connect."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return ""
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        return data.decode("latin-1", "replace").strip()
    except (asyncio.TimeoutError, OSError):
        return ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass


async def grab_http_banner(host: str, port: int, timeout: float) -> str:
    """Send a minimal GET and return the Server / X-Powered-By header line."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return ""
    try:
        req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: p2-scanner\r\nConnection: close\r\n\r\n")
        writer.write(req.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        text = raw.decode("latin-1", "replace")
        headers = text.split("\r\n\r\n", 1)[0]
        wanted = [ln for ln in headers.splitlines()
                  if re.match(r"(Server|X-Powered-By):", ln, re.I)]
        return " | ".join(wanted) if wanted else headers.splitlines()[0]
    except (asyncio.TimeoutError, OSError, IndexError):
        return ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass


@register
class BannerPlugin(AttackPlugin):
    name = "banner"
    owasp_category = "A02:2025 Security Misconfiguration"

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        # Prefer ports discovered by the port scan; otherwise scan a default set.
        ports: list[int] = ctx.extra.get("open_ports") \
            or ctx.extra.get("ports") \
            or [21, 22, 25, 80, 443, 8080]

        sem = asyncio.Semaphore(ctx.max_concurrency)

        async def one(port: int):
            async with sem:
                if port in HTTP_PORTS:
                    banner = await grab_http_banner(target.host, port, ctx.timeout)
                else:
                    # Try a service greeting first (SSH/FTP/SMTP...); if the
                    # service stays silent, fall back to an HTTP probe so web
                    # servers on non-standard ports are still fingerprinted.
                    banner = await grab_tcp_banner(target.host, port, ctx.timeout)
                    if not banner:
                        banner = await grab_http_banner(target.host, port, ctx.timeout)
            return port, banner

        results = await asyncio.gather(*(one(p) for p in ports))

        services: list[dict] = ctx.extra.setdefault("services", [])
        findings: list[Finding] = []
        for port, banner in results:
            if not banner:
                continue
            fp = fingerprint(banner)
            svc = {"port": port, "banner": banner[:200]}
            if fp:
                svc.update(fp)
                services.append(svc)
                findings.append(self._version_finding(target, port, banner, fp))
            else:
                # Banner present but unrecognised: still useful info disclosure.
                services.append(svc)
                findings.append(Finding(
                    category=self.owasp_category,
                    title=f"Service banner exposed on port {port}",
                    severity=Severity.LOW, cvss_score=3.1,
                    evidence=f"Port {port}: {banner[:200]}",
                    recommendation="Suppress or genericise version banners.",
                    target=f"{target.host}:{port}", plugin=self.name,
                    response=banner[:200]))
        return findings

    def _version_finding(self, target, port, banner, fp) -> Finding:
        return Finding(
            category=self.owasp_category,
            title=f"Version disclosure: {fp['product']} {fp['version']} (port {port})",
            severity=Severity.LOW, cvss_score=3.7,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            evidence=(f"Port {port} banner reveals {fp['vendor']}:{fp['product']} "
                      f"version {fp['version']}.\nBanner: {banner[:200]}\n"
                      f"CPE: {fp['cpe']}"),
            recommendation=("Hide precise version numbers (ServerTokens Prod, "
                            "server_tokens off, etc.) and keep software patched."),
            target=f"{target.host}:{port}", plugin=self.name,
            response=banner[:200])
