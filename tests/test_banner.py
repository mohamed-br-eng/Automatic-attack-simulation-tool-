"""
P2 banner / fingerprinting tests. fingerprint() is pure and unit-tested; the
BannerPlugin is exercised against a loopback server that emits a greeting
banner (SSH/FTP style).
"""
import asyncio

import pytest

from core import Context, Target
from plugins.p2_network.banner import (
    BannerPlugin, build_cpe, fingerprint, grab_http_banner,
)


def test_fingerprint_openssh():
    fp = fingerprint("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
    assert fp["product"] == "openssh"
    assert fp["version"].startswith("8.2")
    assert fp["cpe"] == build_cpe("openbsd", "openssh", fp["version"])


def test_fingerprint_apache_and_vsftpd():
    assert fingerprint("Server: Apache/2.4.49 (Unix)")["version"] == "2.4.49"
    assert fingerprint("220 (vsFTPd 2.3.4)")["version"] == "2.3.4"


def test_fingerprint_unknown_returns_none():
    assert fingerprint("hello world, nothing recognisable") is None


@pytest.mark.asyncio
async def test_banner_plugin_reads_greeting_and_fingerprints():
    async def handle(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_7.4\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        ctx = Context(authorized=True, extra={"open_ports": [port]})
        findings = await BannerPlugin().run(Target(host="127.0.0.1", port=port), ctx)
    finally:
        server.close()
        await server.wait_closed()

    services = ctx.extra["services"]
    assert any(s.get("product") == "openssh" for s in services)
    assert any("openssh" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_banner_plugin_http_fallback_on_non_http_port():
    """A web server on a non-standard port (no greeting) is still fingerprinted."""
    async def handle(reader, writer):
        await reader.read(1024)  # Apache-like: stays silent until it gets a request
        writer.write(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.25 (Debian)\r\n"
                     b"Content-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]  # random port, NOT in HTTP_PORTS
    try:
        ctx = Context(authorized=True, timeout=1.0, extra={"open_ports": [port]})
        findings = await BannerPlugin().run(Target(host="127.0.0.1", port=port), ctx)
    finally:
        server.close()
        await server.wait_closed()

    assert any(s.get("product") == "http_server" for s in ctx.extra["services"])


@pytest.mark.asyncio
async def test_grab_http_banner_extracts_server_header():
    async def handle(reader, writer):
        await reader.read(1024)  # consume the GET request
        writer.write(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
                     b"Content-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        banner = await grab_http_banner("127.0.0.1", port, 2.0)
    finally:
        server.close()
        await server.wait_closed()

    assert "nginx/1.18.0" in banner
    assert fingerprint(banner)["product"] == "nginx"
