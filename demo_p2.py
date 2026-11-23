"""
P2 live demo against a local vulnerable target (OWASP Juice Shop by default).

    # 1. Start the lab (loopback only):
    #    docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
    # 2. Run the P2 demo:
    #    python demo_p2.py                 (default: 127.0.0.1:3000)
    #    python demo_p2.py 127.0.0.1 3000  (explicit host/port)

Runs this team member's P2 plugins -- network (port scan, banner, CVE) AND the
two WEB attacks (CORS, Host header injection) -- then writes a JSON + HTML
report into reports/. DoS is intentionally NOT run here (opt-in only).

Everything targets a private/loopback address: the ethics gate is satisfied and
no traffic leaves the machine.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from core import Context, Target
from plugins.p2_network.banner import BannerPlugin
from plugins.p2_network.cve_lookup import CveLookupPlugin
from plugins.p2_network.port_scan import PortScanPlugin
from plugins.p2_web.cors import CorsMisconfigPlugin
from plugins.p2_web.host_header import HostHeaderInjectionPlugin
from reporting import ReportBuilder

# Ports worth checking on the lab host (fast, demo-friendly).
DEMO_PORTS = [22, 80, 443, 3000, 3306, 8080]


async def run_demo(host: str, port: int) -> None:
    target = Target(host=host, base_url=f"http://{host}:{port}", port=port)
    ctx = Context(
        authorized=True,          # we own the lab target
        timeout=8.0,
        max_concurrency=20,
        extra={
            # Always include the target port so the scan matches the web attacks.
            "ports": sorted(set(DEMO_PORTS) | {port}),
            # Point the web attacks at the app (an API endpoint is a good CORS
            # probe once P3's crawler exists; the base URL works for the demo).
            "cors_url": f"http://{host}:{port}/rest/user/whoami",
            "host_header_url": f"http://{host}:{port}/",
            # "enable_dos": True,  # uncomment to also run a measured DoS test
        },
    )

    # Order = the dependency chain (scan -> fingerprint -> CVE), then web attacks.
    pipeline = [
        ("Port scan", PortScanPlugin()),
        ("Banner / fingerprint", BannerPlugin()),
        ("CVE lookup", CveLookupPlugin()),
        ("CORS misconfiguration", CorsMisconfigPlugin()),
        ("Host header injection", HostHeaderInjectionPlugin()),
    ]

    all_findings = []
    print(f"\n=== P2 scan of {target.base_url} ===\n")
    for label, plugin in pipeline:
        findings = await plugin.run(target, ctx)
        all_findings += findings
        worst = max((f.severity.value for f in findings), default="-")
        print(f"[{label:<24}] {len(findings):>2} finding(s)  (worst: {worst})")
        for f in findings:
            print(f"      - {f.severity.value:<8} {f.title}")

    # --- Report (reuses P4's engine) ---------------------------------------
    out = Path("reports")
    out.mkdir(exist_ok=True)
    rb = ReportBuilder(all_findings, target=target.base_url, scan_id="p2-juice-shop")
    rb.to_json(out / "p2_scan.json")
    rb.to_html(out / "p2_scan.html")

    s = rb.summary()
    print(f"\n=== Summary ===")
    print(f"Posture: {s['posture']}  |  total: {s['total']}  |  by severity: {s['by_severity']}")
    print(f"Report: {(out / 'p2_scan.html').resolve()}")
    print(f"        {(out / 'p2_scan.json').resolve()}\n")


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    asyncio.run(run_demo(host, port))


if __name__ == "__main__":
    main()
