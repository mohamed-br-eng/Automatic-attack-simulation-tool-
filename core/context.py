"""
Target et Context : les objets passés à chaque plugin.

⚠️ CONTRAT PARTAGÉ (appartient à P1). Proposition P4 à réconcilier.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Target:
    """
    La cible du scan. L'entrée utilisateur du projet est "simplement l'adresse IP"
    (cf. cahier des charges ISEP), mais on garde l'URL de base pour les plugins web.
    """
    host: str                      # IP ou hostname
    base_url: str = ""             # ex. "http://127.0.0.1:8080"
    port: int = 80

    def __post_init__(self) -> None:
        if not self.base_url:
            self.base_url = f"http://{self.host}:{self.port}"

    def is_private(self) -> bool:
        """True si la cible est une IP privée / loopback (garde-fou éthique)."""
        host = urlparse(self.base_url).hostname or self.host
        if host in ("localhost",):
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback
        except ValueError:
            # hostname non résolu ici : on refuse par défaut (fail-closed)
            return False


@dataclass
class Context:
    """
    Contexte partagé d'un scan : garde-fous éthiques + réglages de concurrence.
    Le mode éthique (P1) impose l'autorisation ET une cible en réseau privé.
    """
    authorized: bool = False       # flag --i-have-authorization
    rate_limit: float = 10.0       # requêtes/seconde max par plugin
    timeout: float = 10.0          # timeout par requête (s)
    max_concurrency: int = 10      # borne du Semaphore
    extra: dict = field(default_factory=dict)

    def ethics_gate(self, target: Target) -> None:
        """
        Lève une exception si le scan n'est pas autorisé OU hors réseau privé.
        Appelé par l'orchestrateur (P1) avant de lancer un plugin.
        """
        if not self.authorized:
            raise PermissionError(
                "Scan refusé : autorisation manquante (--i-have-authorization)."
            )
        if not target.is_private():
            raise PermissionError(
                f"Scan refusé : {target.host} n'est pas dans un réseau privé/lab."
            )
