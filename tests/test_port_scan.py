"""
P2 port-scan tests. We use a real loopback TCP server (no mocking needed) so
the TCP connect scan is exercised end-to-end against a known-open port.
"""
import asyncio

import pytest

from core import Context, Target
from plugins.p2_network.port_scan import PortScanPlugin, check_tcp


async def _open_server() -> tuple[asyncio.AbstractServer, int]:
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
async def test_check_tcp_open_then_closed():
    server, port = await _open_server()
    assert await check_tcp("127.0.0.1", port, 1.0) is True
    server.close()
    await server.wait_closed()
    # Port is now closed -> connection refused.
    assert await check_tcp("127.0.0.1", port, 0.5) is False


@pytest.mark.asyncio
async def test_port_scan_detects_open_port_and_publishes():
    server, port = await _open_server()
    try:
        ctx = Context(authorized=True, extra={"ports": [port, port + 1]})
        findings = await PortScanPlugin().run(Target(host="127.0.0.1", port=port), ctx)
    finally:
        server.close()
        await server.wait_closed()

    # The open port is published for the banner / CVE plugins.
    assert port in ctx.extra["open_ports"]
    assert any("open port" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_port_scan_no_open_ports():
    # A very-unlikely-to-be-open port, scanned alone.
    ctx = Context(authorized=True, extra={"ports": [1]})
    findings = await PortScanPlugin().run(Target(host="127.0.0.1"), ctx)
    assert findings and findings[0].severity.value == "INFO"
