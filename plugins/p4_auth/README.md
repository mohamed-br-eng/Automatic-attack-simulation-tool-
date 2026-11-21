# P4 — Web : Auth, Access Control & Rapport

> Partie de **Mohamed** dans « Automatic Attacks Simulation Tool » (ISEP).
> Branche de travail : `mohammed`.

## Périmètre (ce que je présente en soutenance)

| Bloc | Fichier | Statut |
|------|---------|--------|
| **Brute force / dictionnaire** avec gestion token anti-CSRF | `plugins/p4_auth/bruteforce.py` | ✅ fait + testé |
| **HTTP Basic / Digest** (challenge-response MD5 codé main) | `plugins/p4_auth/http_auth.py` | ⏳ à faire |
| **Broken Access Control / SSRF** (IDOR, méthodes dangereuses, `169.254.169.254`) | `plugins/p4_auth/access_control.py` | ⏳ à faire |
| **Moteur de rapport** JSON → HTML (Jinja2) → PDF (WeasyPrint) | `reporting/` | ✅ JSON+HTML faits + testés · PDF à activer (WeasyPrint) |
| **Scoring CVSS 4.0** + priorisation EPSS | `scoring/cvss4.py` | ⏳ à faire |

Catégories OWASP couvertes : **A07:2025 Authentication Failures**, **A01:2025 Broken Access Control** (absorbe le SSRF en 2025).

## Dépendances d'équipe

- **Contrat partagé** (`core/finding.py`, `core/plugin.py`, `core/context.py`) : appartient à **P1**. La version ici est une **proposition** pour travailler en autonomie → à réconcilier avec P1 en revue croisée (PR).
- Le **crawler de P3** fournira la surface d'attaque (URLs, formulaires) ; en attendant, on passe l'URL de login via `ctx.extra["login_url"]`.
- Le moteur de rapport **consomme les `Finding` de tout le monde** → se caler tôt avec P1 sur le format JSON.

## Lancer les tests

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
pytest -q                       # tests hors-ligne (respx), aucune cible reelle
```

## Le brute force en bref (ce qui vaut des points)

1. **Détection du formulaire** : parsing HTML (stdlib) → champs user/password, action, méthode.
2. **Token CSRF à usage unique** : re-fetch d'une page fraîche **avant chaque tentative** (patron DVWA / g0tmi1k).
3. **Session/cookies** maintenus via un unique `httpx.AsyncClient`.
4. **Succès/échec multi-signaux** : redirection 30x + marqueur de succès/échec + longueur de réponse → score de signaux (≥2 = succès). Réduit les faux positifs.
5. **Rate-limiting** : les réponses `429` sont ignorées (pas comptées comme succès).
6. **Concurrence bornée** par `asyncio.Semaphore` (éthique by design).

> ⚠️ **Mode éthique** : le module ne doit tourner que contre le lab local (DVWA / Juice Shop, bindés sur `127.0.0.1`). Le garde-fou est dans `core/context.py` (`Context.ethics_gate`).
