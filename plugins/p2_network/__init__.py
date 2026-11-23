"""
P2 - Network plugins: port scanning, banner grabbing / fingerprinting,
Denial-of-Service (lab only), and CVE lookup.

Importing this package registers every P2 plugin in the shared registry
(core.register), so the orchestrator (P1) discovers them automatically.

All attacks are REIMPLEMENTED from scratch (ISEP brief: nmap / hydra / sqlmap
and other existing tools are forbidden). The low-level primitives used here are
the Python standard library (socket, asyncio) and, OPTIONALLY, Scapy for raw
packet crafting (SYN scan / SYN flood). When Scapy or the required privileges
are missing, the modules degrade gracefully to a stdlib implementation.
"""
from . import banner, cve_lookup, dos, port_scan  # noqa: F401  (side-effect: register)

__all__ = ["port_scan", "banner", "dos", "cve_lookup"]
