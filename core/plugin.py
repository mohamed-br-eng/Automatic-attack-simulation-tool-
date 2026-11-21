"""
AttackPlugin : la classe de base de tout module d'attaque (Plugin/Strategy pattern).

⚠️ CONTRAT PARTAGÉ (appartient à P1). Proposition P4 à réconcilier.
Chaque membre de l'équipe développe ses plugins contre CETTE interface,
isolément. L'orchestrateur (P1) les découvre automatiquement via le registre.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from .context import Context, Target
from .finding import Finding


class AttackPlugin(ABC):
    """Interface unique de tout plugin d'attaque."""

    name: str = "unnamed"
    owasp_category: str = ""       # ex. "A07:2025 Authentication Failures"

    @abstractmethod
    async def run(self, target: Target, ctx: Context) -> list[Finding]:
        """Exécute l'attaque et retourne la liste des findings détectés."""
        raise NotImplementedError


# --- Registre de découverte automatique (simple décorateur) -----------------
# P1 fournira la version définitive ; celle-ci permet de tester en autonomie.
_REGISTRY: dict[str, type[AttackPlugin]] = {}


def register(cls: type[AttackPlugin]) -> type[AttackPlugin]:
    """Décorateur d'auto-enregistrement d'un plugin."""
    _REGISTRY[cls.name] = cls
    return cls


def get_registry() -> dict[str, type[AttackPlugin]]:
    return dict(_REGISTRY)
