"""
P2 - WEB application attacks (the 2 web attacks owned by this team member,
as required by the brief: each member implements >= 2 *web* attacks).

These are distinct from the P2 network plugins (plugins/p2_network) and from
the web attacks owned by P3 (SQLi/XSS/...) and P4 (brute force/IDOR/SSRF/...):
  - CORS misconfiguration  (cors.py)
  - Host header injection   (host_header.py)

Importing this package self-registers both plugins in the shared registry.
"""
from .cors import CorsMisconfigPlugin
from .host_header import HostHeaderInjectionPlugin

__all__ = ["CorsMisconfigPlugin", "HostHeaderInjectionPlugin"]
