"""
Target and Context: the objects passed to every plugin.

WARNING - SHARED CONTRACT (owned by P1). P4 proposal, to be reconciled.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Target:
    """
    The scan target. The project's user input is "simply the target IP address"
    (per the ISEP brief), but we keep the base URL for web plugins.
    """
    host: str                      # IP or hostname
    base_url: str = ""             # e.g. "http://127.0.0.1:8080"
    port: int = 80

    def __post_init__(self) -> None:
        if not self.base_url:
            self.base_url = f"http://{self.host}:{self.port}"

    def is_private(self) -> bool:
        """True if the target is a private / loopback IP (ethics guard)."""
        host = urlparse(self.base_url).hostname or self.host
        if host in ("localhost",):
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback
        except ValueError:
            # unresolved hostname here: refuse by default (fail-closed)
            return False


@dataclass
class Context:
    """
    Shared scan context: ethics guards + concurrency settings.
    Ethical mode (P1) requires BOTH authorization AND a private-network target.
    """
    authorized: bool = False       # --i-have-authorization flag
    rate_limit: float = 10.0       # max requests/second per plugin
    timeout: float = 10.0          # per-request timeout (s)
    max_concurrency: int = 10      # Semaphore bound
    extra: dict = field(default_factory=dict)

    def ethics_gate(self, target: Target) -> None:
        """
        Raise if the scan is not authorized OR the target is not private.
        Called by the orchestrator (P1) before running any plugin.
        """
        if not self.authorized:
            raise PermissionError(
                "Scan refused: missing authorization (--i-have-authorization)."
            )
        if not target.is_private():
            raise PermissionError(
                f"Scan refused: {target.host} is not in a private/lab network."
            )
