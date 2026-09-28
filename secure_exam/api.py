"""HTTPS JSON API: the same secure protocol as the socket server, over HTTP for web frontends.

Endpoints (all under /api/v1, TLS 1.3 only):

  GET  /health      liveness probe                       -> {"status": "ok"}
  GET  /info        protocol + algorithm description,    -> {"server_public_key": PEM, ...}
                    server signing key and fingerprint
  POST /handshake   body = HELLO frame                   -> {"session_id", HELLO_OK fields}
  POST /rpc         body = {"session_id", "envelope"}    -> {"envelope"}

Every operation (LOGIN, GET_EXAM, SUBMIT, ...) travels inside an encrypted, HMAC-protected
SecureChannel envelope through /rpc, so URLs, status codes and bodies reveal nothing about
what a student is doing. The session_id is only a lookup handle: without the session keys
derived in the handshake it cannot produce a valid envelope, so stealing it is useless.

Requests within one session must be sent one at a time (the channel enforces strictly
increasing sequence numbers). See docs/API.md for the full client guide.
"""

import http.server
import json
import secrets
import ssl
import threading
import time

from . import config
from .crypto_utils import IntegrityError, key_fingerprint, public_key_to_pem
from .protocol import ProtocolError, ReplayError, SecureChannel, server_handshake
from .server import classify_security_error, make_tls_context
from .service import ExamService, Session

API_PREFIX = "/api/v1"
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class ApiSession:
    def __init__(self, channel: SecureChannel, peer: str):
        self.channel = channel
        self.session = Session(peer)
        self.last_used = time.time()
        self.lock = threading.Lock()


class SessionTable:
    def __init__(self, service: ExamService):
        self.service = service
        self.sessions: dict[str, ApiSession] = {}
        self.lock = threading.Lock()

    def create(self, channel: SecureChannel, peer: str) -> str | None:
        self.expire()
        with self.lock:
            if len(self.sessions) >= config.API_MAX_SESSIONS:
                return None
            sid = secrets.token_urlsafe(32)
            self.sessions[sid] = ApiSession(channel, peer)
            return sid

    def get(self, sid: str) -> ApiSession | None:
        with self.lock:
            s = self.sessions.get(sid)
        if s and time.time() - s.last_used > config.API_SESSION_IDLE:
            self.destroy(sid)
            return None
        return s

    def destroy(self, sid: str) -> None:
        with self.lock:
            s = self.sessions.pop(sid, None)
        if s:
            self.service.release(s.session)

    def expire(self) -> None:
        now = time.time()
        with self.lock:
            stale = [k for k, s in self.sessions.items() if now - s.last_used > config.API_SESSION_IDLE]
        for sid in stale:
            self.destroy(sid)


class ApiHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SecureExam"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30                      # slow-loris protection: per-socket read timeout
    api: "ApiServer"                  # injected by ApiServer

    # --- plumbing -------------------------------------------------------------

    def handle(self):
        try:
            super().handle()
        except (ssl.SSLError, ConnectionError, OSError) as exc:
            self.api.service.audit.record("TLS_HANDSHAKE_FAILED", peer=self._peer(),
                                          transport="https", reason=str(exc)[:200])

    def log_message(self, fmt, *args):   # access logging would leak timing/metadata to stderr
        pass

    def _peer(self) -> str:
        return f"{self.client_address[0]}:{self.client_address[1]}"

    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin == config.API_ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")

    def _send(self, status: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict | None:
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self._send(415, {"error": "UNSUPPORTED_MEDIA_TYPE"})
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if not 0 < length <= config.MAX_FRAME_BYTES:
            self._send(413, {"error": "BAD_LENGTH"})
            return None
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "INVALID_JSON"})
            return None
        if not isinstance(body, dict):
            self._send(400, {"error": "INVALID_JSON"})
            return None
        return body

    # --- routes ---------------------------------------------------------------

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == f"{API_PREFIX}/health":
            self._send(200, {"status": "ok"})
        elif self.path == f"{API_PREFIX}/info":
            pub = self.api.service.sign_key.public_key()
            self._send(200, {
                "protocol": "secure-exam/1",
                "server_public_key": public_key_to_pem(pub).decode(),
                "server_key_fingerprint": key_fingerprint(pub),
                "algorithms": {
                    "key_transport": "RSA-OAEP (SHA-256, MGF1-SHA-256), 32-byte master secret",
                    "handshake_signature": "RSA-PSS (SHA-256, max salt length)",
                    "kdf": "HKDF-SHA256(master, salt=client_nonce||server_nonce, "
                           "info='secure-exam session v1', 64 bytes) -> k_enc||k_mac",
                    "cipher": "AES-256-CBC, PKCS#7 padding, random 16-byte IV",
                    "mac": "HMAC-SHA256 over direction||seq(u64be)||ts(u64be)||iv||ct",
                    "data_signatures": "RSA-PSS (SHA-256) over canonical JSON",
                },
                "max_clock_skew_seconds": config.MAX_CLOCK_SKEW,
                "session_idle_timeout_seconds": config.API_SESSION_IDLE,
            })
        else:
            self._send(404, {"error": "NOT_FOUND"})

    def do_POST(self):
        if self.path == f"{API_PREFIX}/handshake":
            self._handshake()
        elif self.path == f"{API_PREFIX}/rpc":
            self._rpc()
        else:
            self._send(404, {"error": "NOT_FOUND"})

    def _handshake(self):
        hello = self._read_json()
        if hello is None:
            return
        try:
            reply, k_enc, k_mac = server_handshake(self.api.service.sign_key, hello)
        except ProtocolError as exc:
            self.api.service.audit.record("PROTOCOL_VIOLATION", peer=self._peer(),
                                          transport="https", reason=str(exc))
            self._send(400, {"error": "BAD_HANDSHAKE"})
            return
        sid = self.api.sessions.create(SecureChannel(None, k_enc, k_mac, is_server=True),
                                       self._peer())
        if sid is None:
            self._send(503, {"error": "TOO_MANY_SESSIONS"})
            return
        self._send(200, {"session_id": sid, **reply})

    def _rpc(self):
        body = self._read_json()
        if body is None:
            return
        sid = body.get("session_id")
        api_session = self.api.sessions.get(sid) if isinstance(sid, str) else None
        if api_session is None or not isinstance(body.get("envelope"), dict):
            self._send(401, {"error": "UNKNOWN_SESSION"})
            return

        with api_session.lock:
            channel, session = api_session.channel, api_session.session
            try:
                request = channel.open(body["envelope"])
            except (IntegrityError, ReplayError, ProtocolError) as exc:
                kind = classify_security_error(exc)
                self.api.service.audit.record(kind, peer=self._peer(), user=session.user_id,
                                              transport="https", reason=str(exc))
                # A tampered or replayed request burns the whole session.
                reply = channel.seal({"ok": False, "error": kind, "detail": str(exc)})
                self.api.sessions.destroy(sid)
                self._send(400, {"envelope": reply})
                return
            api_session.last_used = time.time()
            response = self.api.service.dispatch(request, session)
            reply = channel.seal(response)
        if request.get("type") == "LOGOUT":
            self.api.sessions.destroy(sid)
        self._send(200, {"envelope": reply})


class ApiServer:
    def __init__(self, host: str = config.HOST, port: int = config.API_PORT,
                 service: ExamService | None = None):
        self.service = service or ExamService()
        self.sessions = SessionTable(self.service)
        handler = type("BoundApiHandler", (ApiHandler,), {"api": self})
        self.httpd = http.server.ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        # Handshake lazily in the worker thread so a slow/bad client cannot block accept().
        self.httpd.socket = make_tls_context().wrap_socket(
            self.httpd.socket, server_side=True, do_handshake_on_connect=False)
        self.port = self.httpd.server_address[1]

    def start(self) -> None:
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
