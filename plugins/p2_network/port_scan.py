"""
P2 - Port scanning, REIMPLEMENTED from scratch (no nmap).
Category: A02:2025 Security Misconfiguration (exposed services / attack surface).

Three techniques are provided, from the most portable to the most "pro":

  1. TCP connect scan  -- stdlib only, no privilege.
       asyncio.open_connection(): a completed 3-way handshake => port OPEN.
       Massively concurrent, bounded by an asyncio.Semaphore (ethics by design).

  2. SYN half-open scan -- OPTIONAL (Scapy + root/admin + Npcap on Windows).
       We forge IP()/TCP(flags="S") ourselves and read the reply flags:
         0x12 (SYN-ACK) => OPEN   (we send a RST to NOT complete the handshake)
         0x14 (RST-ACK) => CLOSED
         no reply       => FILTERED
       If Scapy or privileges are missing, we fall back to the TCP connect scan.

  3. UDP scan -- best-effort, stdlib.
       Empty datagram on a *connected* UDP socket; an ICMP port-unreachable
       surfaces as ConnectionRefusedError => CLOSED. Silence => OPEN|FILTERED.
       Slower and less reliable than TCP (good discussion point for the jury).

The list of open ports is written into ctx.extra["open_ports"] so the banner
and CVE plugins can consume it: this materialises the P2 dependency graph
(scan -> fingerprint -> CVE) that P1's orchestrator relies on.
"""
from __future__ import annotations

import asyncio
import socket

from core import AttackPlugin, Context, Finding, Severity, Target, register

# A small, fast, demo-friendly set of common ports. Override via
# ctx.extra["ports"] (list[int]).
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
    9200, 11211, 27017,
]

# port -> (service label, is_plaintext_or_risky, why)
WELL_KNOWN = {
    21: ("ftp", True, "clear-text credentials"),
    23: ("telnet", True, "clear-text credentials"),
    25: ("smtp", True, "clear-text mail relay"),
    110: ("pop3", True, "clear-text credentials"),
    143: ("imap", True, "clear-text credentials"),
    3306: ("mysql", True, "database exposed to the network"),
    5432: ("postgresql", True, "database exposed to the network"),
    6379: ("redis", True, "often unauthenticated, exposed to the network"),
    9200: ("elasticsearch", True, "often unauthenticated, exposed"),
    11211: ("memcached", True, "unauthenticated, UDP amplification vector"),
    27017: ("mongodb", True, "often unauthenticated, exposed"),
    3389: ("rdp", True, "remote desktop exposed to the network"),
    5900: ("vnc", True, "remote desktop exposed to the network"),
    22: ("ssh", False, ""),
    80: ("http", False, ""),
    443: ("https", False, ""),
    8080: ("http-alt", False, ""),
    8443: ("https-alt", False, ""),
    3000: ("http-dev", False, ""),
}


# --- Low-level primitives (reimplemented) -----------------------------------
async def check_tcp(host: str, port: int, timeout: float) -> bool:
    """TCP connect scan: True if the handshake completes (port open)."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass
        return True
    except (asyncio.TimeoutError, OSError):
        return False


def _check_udp_sync(host: str, port: int, timeout: float) -> str:
    """UDP probe (blocking). Returns 'open', 'open|filtered' or 'closed'."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.send(b"\x00")
        try:
            s.recv(1024)
            return "open"                 # a service answered
        except socket.timeout:
            return "open|filtered"        # no reply: cannot distinguish
        except ConnectionRefusedError:
            return "closed"               # ICMP port-unreachable received
    except OSError:
        return "closed"
    finally:
        s.close()


async def check_udp(host: str, port: int, timeout: float) -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _check_udp_sync, host, port, timeout)


def syn_scan_sync(host: str, ports: list[int], timeout: float) -> dict[int, str]:
    """
    SYN half-open scan via Scapy (OPTIONAL). Returns {port: state}.
    Raises RuntimeError if Scapy / privileges are unavailable so the caller
    can fall back to the TCP connect scan.
    """
    try:
        from scapy.all import IP, TCP, sr  # type: ignore
        from scapy.all import conf
    except Exception as e:  # ImportError or backend error
        raise RuntimeError(f"Scapy unavailable: {e}")

    conf.verb = 0
    pkts = IP(dst=host) / TCP(dport=ports, flags="S")
    try:
        answered, _ = sr(pkts, timeout=timeout, retry=0)
    except PermissionError as e:
        raise RuntimeError(f"raw socket denied (need root/admin): {e}")
    except Exception as e:
        raise RuntimeError(f"SYN scan failed: {e}")

    states: dict[int, str] = {p: "filtered" for p in ports}
    rst_pkts = []
    for sent, recv in answered:
        if recv.haslayer(TCP):
            flags = int(recv[TCP].flags)
            dport = sent[TCP].dport
            if flags & 0x12 == 0x12:          # SYN-ACK => open
                states[dport] = "open"
                # Send a RST so we do NOT complete the handshake (stealth).
                rst_pkts.append(IP(dst=host) / TCP(dport=dport,
                                sport=sent[TCP].sport, flags="R",
                                seq=recv[TCP].ack))
            elif flags & 0x14 == 0x14:        # RST-ACK => closed
                states[dport] = "closed"
    if rst_pkts:
        try:
            from scapy.all import send  # type: ignore
            send(rst_pkts)
        except Exception:
            pass
    return states


@register
class PortScanPlugin(AttackPlugin):
    name = "port_scan"
    owasp_category = "A02:2025 Security Misconfiguration"

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        ports: list[int] = list(ctx.extra.get("ports", DEFAULT_PORTS))
        method: str = ctx.extra.get("scan_method", "connect")  # connect|syn|udp

        if method == "syn":
            open_ports, how = await self._syn_or_fallback(target, ports, ctx)
        elif method == "udp":
            open_ports, how = await self._udp_scan(target, ports, ctx)
        else:
            open_ports = await self._connect_scan(target, ports, ctx)
            how = "TCP connect"

        # Publish results for the banner / CVE plugins (dependency graph).
        ctx.extra.setdefault("open_ports", [])
        for p in open_ports:
            if p not in ctx.extra["open_ports"]:
                ctx.extra["open_ports"].append(p)

        return self._build_findings(target, open_ports, how)

    # --- scan strategies ----------------------------------------------------
    async def _connect_scan(self, target, ports, ctx) -> list[int]:
        sem = asyncio.Semaphore(ctx.max_concurrency)

        async def one(port: int):
            async with sem:
                if await check_tcp(target.host, port, ctx.timeout):
                    return port
            return None

        results = await asyncio.gather(*(one(p) for p in ports))
        return sorted(p for p in results if p is not None)

    async def _syn_or_fallback(self, target, ports, ctx) -> tuple[list[int], str]:
        loop = asyncio.get_running_loop()
        try:
            states = await loop.run_in_executor(
                None, syn_scan_sync, target.host, ports, ctx.timeout)
            return sorted(p for p, s in states.items() if s == "open"), "SYN half-open"
        except RuntimeError:
            # Graceful degradation (zero friction on Windows demos).
            return await self._connect_scan(target, ports, ctx), \
                "TCP connect (Scapy fallback)"

    async def _udp_scan(self, target, ports, ctx) -> tuple[list[int], str]:
        sem = asyncio.Semaphore(ctx.max_concurrency)

        async def one(port: int):
            async with sem:
                state = await check_udp(target.host, port, ctx.timeout)
                return port if state in ("open", "open|filtered") else None

        results = await asyncio.gather(*(one(p) for p in ports))
        return sorted(p for p in results if p is not None), "UDP"

    # --- reporting ----------------------------------------------------------
    def _build_findings(self, target, open_ports, how) -> list[Finding]:
        if not open_ports:
            return [Finding(
                category=self.owasp_category,
                title="No open port found (demo port set)",
                severity=Severity.INFO,
                evidence=f"Scan method: {how}. No reachable port.",
                recommendation="Keep the exposed attack surface minimal.",
                target=target.host, plugin=self.name)]

        services = ", ".join(
            f"{p}/{WELL_KNOWN.get(p, ('?',))[0]}" for p in open_ports)
        findings = [Finding(
            category=self.owasp_category,
            title=f"{len(open_ports)} open port(s) detected",
            severity=Severity.INFO,
            evidence=f"Scan method: {how}. Open ports: {services}.",
            recommendation=("Close every unused port; restrict the rest with a "
                            "firewall / network segmentation."),
            target=target.host, plugin=self.name,
            response=services)]

        # Flag notably risky / clear-text services individually.
        for p in open_ports:
            label, risky, why = WELL_KNOWN.get(p, (None, False, ""))
            if risky:
                findings.append(Finding(
                    category=self.owasp_category,
                    title=f"Risky service exposed: {label} ({p}/tcp)",
                    severity=Severity.MEDIUM, cvss_score=5.3,
                    cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                    evidence=f"Port {p}/tcp ({label}) is open: {why}.",
                    recommendation=(f"Disable {label} if unused, or put it behind "
                                    f"a VPN and enforce encryption/authentication."),
                    target=f"{target.host}:{p}", plugin=self.name))
        return findings
