# P2 — Network, DoS & CVE

Network attack plugins, **reimplemented from scratch** (no nmap / hydra / sqlmap,
per the ISEP brief). Every plugin implements the shared `AttackPlugin` contract
(`async def run(target, ctx) -> list[Finding]`) and self-registers via
`@register`, so P1's orchestrator discovers them automatically.

## Plugins

| name | file | OWASP 2025 | What it does |
|------|------|-----------|--------------|
| `port_scan` | `port_scan.py` | A02 Security Misconfiguration | TCP connect scan (stdlib), optional SYN half-open (Scapy), best-effort UDP. Flags risky/clear-text services. |
| `banner` | `banner.py` | A02 Security Misconfiguration | Banner grabbing + regex fingerprinting (product/version) → CPE. |
| `dos_slowloris` | `dos.py` | A02 (availability) | "Low and slow": partial HTTP headers keep sockets open. |
| `dos_http_flood` | `dos.py` | A02 (availability) | Layer-7 flood of concurrent GETs. |
| `dos_syn_flood` | `dos.py` | A02 (availability) | Spoofed half-open SYN packets (optional, Scapy). |
| `cve_lookup` | `cve_lookup.py` | A03 Software Supply Chain | CPE → CVE via offline DB (default) or live NVD 2.0 + EPSS + CISA KEV. |

## The dependency chain (what to show the jury)

```
port_scan  ──writes──▶ ctx.extra["open_ports"]
                              │
banner     ──reads────────────┘──writes──▶ ctx.extra["services"]  (product, version, cpe)
                                                    │
cve_lookup ──reads──────────────────────────────────┘──▶ Findings enriched with CVSS + EPSS + KEV
```

Each stage feeds the next through the shared `Context`, which materialises the
orchestrator's dependency graph (scan → fingerprint → CVE).

## Safety (DoS)

The DoS plugins run **only** when **all** of these hold:

1. `ctx.authorized is True` (the `--i-have-authorization` flag),
2. `target.is_private()` (loopback / private lab network),
3. `ctx.extra["enable_dos"] is True` (explicit per-scan opt-in).

(1) and (2) are the shared `ctx.ethics_gate()`; we call it again here as
defense-in-depth, and (3) ensures DoS never runs by accident. A failed guard
returns an INFO "refused" finding instead of raising, so the scan continues.
Intensity is capped (`MAX_DURATION_S`, `MAX_CONNECTIONS`, `MAX_FLOOD_REQUESTS`)
and impact is **measured** (response time before vs. during).

## Usage example

```python
from core import Context, Target
from plugins.p2_network.port_scan import PortScanPlugin
from plugins.p2_network.banner import BannerPlugin
from plugins.p2_network.cve_lookup import CveLookupPlugin

ctx = Context(authorized=True, extra={"ports": [21, 22, 80, 443]})
target = Target(host="127.0.0.1", port=80)

findings = []
for plugin in (PortScanPlugin(), BannerPlugin(), CveLookupPlugin()):
    findings += await plugin.run(target, ctx)   # ctx is shared → chain works
```

Enable a DoS resilience test (lab only):

```python
ctx = Context(authorized=True, extra={"enable_dos": True, "dos_duration": 8})
findings = await SlowlorisPlugin().run(Target(host="127.0.0.1", port=80), ctx)
```

Live CVE lookup instead of the offline DB:

```python
ctx.extra["cve_online"] = True
ctx.extra["nvd_api_key"] = "<optional NVD key: raises the rate limit>"
```

## Optional dependency

SYN scan / SYN flood use **Scapy** (`pip install scapy`, plus Npcap + admin on
Windows). Without it, `port_scan` falls back to the TCP connect scan and
`dos_syn_flood` returns a refused finding — the tool still runs everywhere.

## Tests

```
pytest tests/test_port_scan.py tests/test_banner.py tests/test_dos.py tests/test_cve_lookup.py
```

Tests use loopback servers (scan/banner) and `respx` (HTTP flood, online CVE),
so **no real traffic** leaves the machine.
