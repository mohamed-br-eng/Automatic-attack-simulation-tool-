# P4 — Web: Authentication, Access Control & Reporting

> Mohamed's part of the "Automatic Attacks Simulation Tool" (ISEP).
> Working branch: `mohammed`.

## Scope (what I present at the defense)

| Block | File | Status |
|-------|------|--------|
| **Brute force / dictionary** with anti-CSRF token handling | `plugins/p4_auth/bruteforce.py` | Done + tested |
| **HTTP Basic / Digest** (hand-coded MD5 challenge-response) | `plugins/p4_auth/http_auth.py` | Done + tested |
| **Broken Access Control / SSRF** (IDOR, dangerous methods, `169.254.169.254`) | `plugins/p4_auth/access_control.py` | Done + tested |
| **Reporting engine** JSON → HTML (Jinja2) → PDF (WeasyPrint) | `reporting/` | JSON+HTML done + tested · PDF to enable (WeasyPrint) |
| **CVSS 4.0 scoring** + EPSS prioritization | `scoring/cvss4.py` | Done + tested |

OWASP categories covered: **A07:2025 Authentication Failures**, **A01:2025 Broken Access Control** (which absorbs SSRF in 2025).

## Team dependencies

- The **shared contract** (`core/finding.py`, `core/plugin.py`, `core/context.py`) is owned by **P1**. The version here is a **proposal** to allow independent work → to be reconciled with P1 during peer review (PR).
- **P3's crawler** will provide the attack surface (URLs, forms); meanwhile the login URL is passed via `ctx.extra["login_url"]`.
- The reporting engine **consumes everyone's `Finding` objects** → align early with P1 on the JSON format.

## Running the tests

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
pytest -q                       # offline tests (respx), no real target
```

## Generating a sample report

```bash
python -m reporting.demo        # writes reports/demo.html and reports/demo.json
```

Open `reports/demo.html` in a browser. The report uses a brand-neutral,
validated status palette (security-standard red / orange / amber / blue / grey).

## Brute force in a nutshell (what earns points)

1. **Form detection**: HTML parsing (stdlib) → user/password fields, action, method.
2. **Single-use CSRF token**: re-fetch a fresh page **before each attempt** (DVWA / g0tmi1k pattern).
3. **Session/cookies** kept via a single `httpx.AsyncClient`.
4. **Multi-signal success/failure**: 30x redirect + success/failure marker + response length → a signal score (≥2 = success). Reduces false positives.
5. **Rate-limiting**: `429` responses are ignored (not counted as success).
6. **Bounded concurrency** via `asyncio.Semaphore` (ethics by design).

> **Ethical mode**: this module must only run against the local lab (DVWA / Juice Shop, bound to `127.0.0.1`). The guard lives in `core/context.py` (`Context.ethics_gate`).
