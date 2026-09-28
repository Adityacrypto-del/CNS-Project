"""HTTPS server for the web frontend (frontend/): static files only, TLS 1.3, strict CSP.

It serves the one origin the API's CORS policy allows (SECURE_EXAM_ALLOWED_ORIGIN, default
https://localhost:5173), and generates /config.js with the server's RSA public key so the
browser can pin it. The pin is read from the local key file, not fetched from the API, so a
network attacker who answers for the API cannot substitute their own key.
"""

import argparse
import http.server
import json
import ssl
import threading
from urllib.parse import urlsplit

from . import config
from .crypto_utils import key_fingerprint, load_public_key
from .server import make_tls_context

FRONTEND_DIR = config.ROOT / "frontend"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
}


def api_origin(api_port: int) -> str:
    return f"https://{config.SERVER_HOSTNAME}:{api_port}"


def content_security_policy(api_port: int) -> str:
    return ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            f"connect-src {api_origin(api_port)}; form-action 'none'; base-uri 'none'; "
            "frame-ancestors 'none'")


def config_js(api_port: int) -> bytes:
    pem = config.SERVER_SIGN_PUB.read_text()
    cfg = {"apiBase": api_origin(api_port), "serverPublicKeyPem": pem,
           "serverKeyFingerprint": key_fingerprint(load_public_key(pem.encode()))}
    return f"export const CONFIG = Object.freeze({json.dumps(cfg, indent=2)});\n".encode()


class WebHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SecureExam"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30
    web: "WebServer"

    def handle(self):
        try:
            super().handle()
        except (ssl.SSLError, ConnectionError, OSError):
            pass

    def log_message(self, fmt, *args):
        pass

    def _send(self, status: int, body: bytes, ctype: str, head: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", content_security_policy(self.web.api_port))
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _resolve(self):
        path = urlsplit(self.path).path
        if path == "/config.js":
            return config_js(self.web.api_port), CONTENT_TYPES[".js"]
        target = (FRONTEND_DIR / (path.lstrip("/") or "index.html")).resolve()
        # No directory traversal, no dotfiles, only known file types.
        if (not target.is_relative_to(FRONTEND_DIR.resolve()) or not target.is_file()
                or any(part.startswith(".") for part in target.relative_to(FRONTEND_DIR.resolve()).parts)
                or target.suffix not in CONTENT_TYPES):
            return None, None
        return target.read_bytes(), CONTENT_TYPES[target.suffix]

    def do_GET(self, head: bool = False):
        body, ctype = self._resolve()
        if body is None:
            self._send(404, b"Not found", "text/plain; charset=utf-8", head)
        else:
            self._send(200, body, ctype, head)

    def do_HEAD(self):
        self.do_GET(head=True)


class WebServer:
    def __init__(self, host: str = config.HOST, port: int = config.WEB_PORT,
                 api_port: int = config.API_PORT):
        self.api_port = api_port
        handler = type("BoundWebHandler", (WebHandler,), {"web": self})
        self.httpd = http.server.ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        self.httpd.socket = make_tls_context().wrap_socket(
            self.httpd.socket, server_side=True, do_handshake_on_connect=False)
        self.port = self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"https://{config.SERVER_HOSTNAME}:{self.port}/"

    def start(self) -> None:
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the Secure Exam web frontend over HTTPS")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--port", type=int, default=config.WEB_PORT)
    parser.add_argument("--api-port", type=int, default=config.API_PORT)
    args = parser.parse_args()
    if not config.SERVER_SIGN_PUB.exists():
        raise SystemExit("System not initialised. Run: python -m secure_exam.init_system")
    web = WebServer(args.host, args.port, args.api_port)
    print(f"[*] Web frontend on {web.url}  (API expected at {api_origin(args.api_port)})")
    try:
        web.httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        web.httpd.server_close()


if __name__ == "__main__":
    main()
