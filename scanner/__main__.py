"""
CLI entry point for the Automatic Attacks Simulation Tool.

Usage:
    python -m scanner --target 127.0.0.1 --port 8080 --i-have-authorization

The scanner auto-discovers all registered plugins, runs them against the
target, enriches findings with CVSS 4.0 scores, and generates JSON + HTML
reports.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

from core import Context, Finding, Target, get_registry
from reporting import ReportBuilder
from scoring import score as cvss_score, CvssError

# Force plugin registration by importing the packages.
import plugins.p4_auth  # noqa: F401


def _enrich_cvss(findings: list[Finding]) -> list[Finding]:
    """Recompute cvss_score from cvss_vector when a vector is present."""
    for f in findings:
        if f.cvss_vector:
            try:
                result = cvss_score(f.cvss_vector)
                f.cvss_score = result.base_score
                f.severity = result.severity
            except CvssError:
                pass
    return findings


async def _run(target: Target, ctx: Context) -> list[Finding]:
    ctx.ethics_gate(target)
    registry = get_registry()
    if not registry:
        print("No plugins registered.", file=sys.stderr)
        return []

    all_findings: list[Finding] = []
    for name, plugin_cls in registry.items():
        plugin = plugin_cls()
        print(f"  [{plugin.name}] running ...", end=" ", flush=True)
        t0 = time.perf_counter()
        try:
            findings = await plugin.run(target, ctx)
            elapsed = time.perf_counter() - t0
            print(f"{len(findings)} finding(s) in {elapsed:.1f}s")
            all_findings.extend(findings)
        except Exception as exc:
            elapsed = time.perf_counter() - t0
            print(f"ERROR ({elapsed:.1f}s): {exc}", file=sys.stderr)

    return _enrich_cvss(all_findings)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Automatic Attacks Simulation Tool (ISEP PFE)")
    parser.add_argument("--target", required=True,
                        help="Target IP or hostname (must be private/lab)")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--login-url",
                        help="Login page URL (brute force)")
    parser.add_argument("--idor-url",
                        help="IDOR URL with {id} placeholder")
    parser.add_argument("--methods-url",
                        help="URL to probe for dangerous HTTP methods")
    parser.add_argument("--ssrf-url",
                        help="SSRF endpoint URL")
    parser.add_argument("--ssrf-param", default="url",
                        help="SSRF query parameter name (default: url)")
    parser.add_argument("--auth-url",
                        help="HTTP Basic/Digest protected URL")
    parser.add_argument("--rate-limit", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument("--scan-id", default="")
    parser.add_argument("--i-have-authorization", action="store_true",
                        required=True,
                        help="Confirm you are authorized to scan this target")
    args = parser.parse_args()

    target = Target(host=args.target, port=args.port)

    extra: dict = {}
    if args.login_url:
        extra["login_url"] = args.login_url
    if args.idor_url:
        extra["idor_url"] = args.idor_url
    if args.methods_url:
        extra["methods_url"] = args.methods_url
    if args.ssrf_url:
        extra["ssrf_url"] = args.ssrf_url
        extra["ssrf_param"] = args.ssrf_param
    if args.auth_url:
        extra["auth_url"] = args.auth_url

    ctx = Context(
        authorized=True,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        max_concurrency=args.concurrency,
        extra=extra,
    )

    print(f"\n=== Automatic Attacks Simulation Tool ===")
    print(f"Target : {target.base_url}")
    print(f"Plugins: {len(get_registry())}\n")

    findings = asyncio.run(_run(target, ctx))

    out = Path(args.output_dir)
    out.mkdir(exist_ok=True)
    scan_id = args.scan_id or f"scan-{int(time.time())}"
    rb = ReportBuilder(findings, target=args.target, scan_id=scan_id)

    json_path = out / f"{scan_id}.json"
    html_path = out / f"{scan_id}.html"
    rb.to_json(json_path)
    rb.to_html(html_path)

    crit = sum(1 for f in findings if f.severity.value == "CRITICAL")
    high = sum(1 for f in findings if f.severity.value == "HIGH")
    med = sum(1 for f in findings if f.severity.value == "MEDIUM")
    low = sum(1 for f in findings if f.severity.value == "LOW")
    info = sum(1 for f in findings if f.severity.value == "INFO")

    print(f"\n=== Results: {len(findings)} finding(s) ===")
    print(f"  CRITICAL {crit}  |  HIGH {high}  |  MEDIUM {med}  |  LOW {low}  |  INFO {info}")
    print(f"\nReports:")
    print(f"  JSON : {json_path}")
    print(f"  HTML : {html_path}")
    print(f"\nOpen {html_path} in a browser to view the full report.")


if __name__ == "__main__":
    main()
