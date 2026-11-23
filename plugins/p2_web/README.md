# P2 — Web application attacks

The **two web application attacks** owned by this team member, satisfying the
brief's requirement ("each member implements at least 2 *web* attacks; network
attacks do not count toward the minimum"). Both are reimplemented from scratch
and are distinct from P3's (SQLi/XSS/…) and P4's (brute force/IDOR/SSRF/…).

| name | file | OWASP 2025 | Detection logic (what the jury grades) |
|------|------|-----------|----------------------------------------|
| `cors` | `cors.py` | A02 Security Misconfiguration | Send the request with crafted `Origin` headers; flag when `Access-Control-Allow-Origin` reflects an attacker origin — critically when combined with `Access-Control-Allow-Credentials: true`. |
| `host_header_injection` | `host_header.py` | A02 Security Misconfiguration | Inject a unique canary host via `Host` / `X-Forwarded-Host` / `X-Host`; flag when the canary is reflected in the `Location` header (cache poisoning / open redirect) or body (password-reset poisoning). |

## Why these two

- **Unique in the team** — no overlap with teammates, so each is clearly yours.
- **Pure detection reasoning** — the value is the classification of the server's
  response (safe vs. vulnerable), not a payload list. That reasoning is exactly
  what distinguishes a serious scanner from a naïve `grep`.
- **Context-aware** — both read their target from `ctx.extra` (`cors_url`,
  `host_header_url`), so P3's crawler can feed them discovered endpoints.

## Usage

```python
from core import Context, Target
from plugins.p2_web import CorsMisconfigPlugin, HostHeaderInjectionPlugin

target = Target(host="127.0.0.1", port=8080)
ctx = Context(authorized=True, extra={
    "cors_url": "http://127.0.0.1:8080/api/account",
    "host_header_url": "http://127.0.0.1:8080/reset-password",
})

findings = []
for plugin in (CorsMisconfigPlugin(), HostHeaderInjectionPlugin()):
    findings += await plugin.run(target, ctx)
```

## Tests

```
pytest tests/test_cors.py tests/test_host_header.py
```

Fake vulnerable/safe servers via `respx` — no real traffic leaves the machine.
