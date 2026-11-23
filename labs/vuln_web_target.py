"""
Deliberately-vulnerable demo target for P2's WEB attacks (CORS + Host header).
Stdlib only (no Docker, no framework). LOCAL / LAB USE ONLY.

    python labs/vuln_web_target.py            # serves on 127.0.0.1:8000
    python demo_p2.py 127.0.0.1 8000          # run the P2 scan against it

It reproduces two real bugs so the plugins show POSITIVE detections:
  - CORS:        reflects the request Origin into Access-Control-Allow-Origin
                 AND sets Access-Control-Allow-Credentials: true   -> HIGH
  - Host header: builds a password-reset link from X-Forwarded-Host / Host,
                 and /redirect sends a Location based on it         -> HIGH/MEDIUM

Juice Shop does NOT have these specific flaws (its ACAO is a safe wildcard), so
this tiny lab is what makes a convincing demo of these two attacks.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8000


class VulnHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        origin = self.headers.get("Origin")
        # BUG: trust X-Forwarded-Host over the real Host.
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")

        if path == "/redirect":
            # BUG: open redirect / cache poisoning via the host header.
            self.send_response(302)
            self.send_header("Location", f"https://{host}/home")
            self.end_headers()
            return

        # CORS BUG on every endpoint: reflect the attacker origin + credentials.
        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        # Host header BUG: the reset link is built from the (spoofable) host.
        body = (
            "<html><body><h1>Vulnerable demo app (lab only)</h1>"
            f'<p>Password reset link: '
            f'<a href="https://{host}/reset?token=SECRET">reset your password</a></p>'
            "</body></html>"
        )
        self.wfile.write(body.encode())

    def log_message(self, *args) -> None:  # silence request logging
        pass


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), VulnHandler)
    print(f"Vulnerable demo target on http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
