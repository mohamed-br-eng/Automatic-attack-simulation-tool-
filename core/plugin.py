"""
AttackPlugin: base class of every attack module (Plugin/Strategy pattern).

WARNING - SHARED CONTRACT (owned by P1). P4 proposal, to be reconciled.
Each team member builds their plugins against THIS interface, in isolation.
The orchestrator (P1) discovers them automatically via the registry.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from .context import Context, Target
from .finding import Finding


class AttackPlugin(ABC):
    """Single interface for every attack plugin."""

    name: str = "unnamed"
    owasp_category: str = ""       # e.g. "A07:2025 Authentication Failures"

    @abstractmethod
    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        """Run the attack and return the list of detected findings."""
        raise NotImplementedError


# --- Automatic discovery registry (simple decorator) ------------------------
# P1 will provide the final version; this one enables standalone testing.
_REGISTRY: dict[str, type[AttackPlugin]] = {}


def register(cls: type[AttackPlugin]) -> type[AttackPlugin]:
    """Decorator that self-registers a plugin."""
    _REGISTRY[cls.name] = cls
    return cls


def get_registry() -> dict[str, type[AttackPlugin]]:
    return dict(_REGISTRY)
