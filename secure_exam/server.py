"""Examination server: TLS socket transport and HTTPS JSON API.

    python -m secure_exam.server                 # both transports
    python -m secure_exam.server --no-api        # socket protocol only

Security layers, outermost first:
  1. TLS 1.3 with a CA-issued server certificate          (secure communication)
  2. RSA-OAEP key exchange + RSA-PSS signed handshake     (key management, server auth)
  3. AES-256-CBC + HMAC-SHA256 channel with seq/timestamp (confidentiality, integrity, anti-replay)
  4. PBKDF2 password auth with lockout, role checks       (authentication, authorisation)
  5. RSA-PSS signatures on papers, submissions, receipts,
     results and examiner actions                         (non-repudiation)
  6. AES-256-GCM encryption of every database at rest     (confidentiality at rest)
"""

import argparse
import socket
import ssl
import threading

from . import config
from .crypto_utils import IntegrityError
from .protocol import (ProtocolError, ReplayError, SecureChannel, recv_frame, send_frame,
                       server_handshake)
from .service import ExamService, Session


def make_tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(config.SERVER_TLS_CERT, config.SERVER_TLS_KEY)
    return ctx


def classify_security_error(exc: Exception) -> str:
    return {IntegrityError: "TAMPERING_DETECTED", ReplayError: "REPLAY_DETECTED"}.get(
        type(exc), "PROTOCOL_VIOLATION")


class ExamServer:
    """TLS socket transport: one SecureChannel per TCP connection."""

    def __init__(self, host: str = config.HOST, port: int = config.PORT,
                 service: ExamService | None = None):
        self.host, self.port = host, port
        self.service = service or ExamService()
        self.audit = self.service.audit
        self.tls = make_tls_context()
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    # --- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Bind and serve in a background thread."""
        self._bind()
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()

    def _bind(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(64)
        self.port = sock.getsockname()[1]
        self._sock = sock

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                raw, addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_connection, args=(raw, addr), daemon=True).start()

    # --- per-connection -----------------------------------------------------

    def _handle_connection(self, raw: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        raw.settimeout(config.API_SESSION_IDLE)
        try:
            conn = self.tls.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            self.audit.record("TLS_HANDSHAKE_FAILED", peer=peer, reason=str(exc))
            raw.close()
            return

        channel, session = None, Session(peer)
        try:
            reply, k_enc, k_mac = server_handshake(self.service.sign_key, recv_frame(conn))
            send_frame(conn, reply)
            channel = SecureChannel(conn, k_enc, k_mac, is_server=True)
            while True:
                request = channel.recv()
                channel.send(self.service.dispatch(request, session))
                if request.get("type") == "LOGOUT":
                    break
        except (IntegrityError, ReplayError, ProtocolError) as exc:
            kind = classify_security_error(exc)
            self.audit.record(kind, peer=peer, user=session.user_id, transport="socket",
                              reason=str(exc))
            # Release before replying so a legitimate reconnect is not refused.
            self.service.release(session)
            if channel:
                try:
                    channel.send({"ok": False, "error": kind, "detail": str(exc)})
                except OSError:
                    pass
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            self.service.release(session)
            conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure online examination server")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--port", type=int, default=config.PORT, help="TLS socket port")
    parser.add_argument("--api-port", type=int, default=config.API_PORT, help="HTTPS API port")
    parser.add_argument("--web-port", type=int, default=config.WEB_PORT, help="web frontend port")
    parser.add_argument("--no-api", action="store_true", help="do not start the HTTPS API")
    parser.add_argument("--no-web", action="store_true", help="do not serve the web frontend")
    args = parser.parse_args()
    if not config.SERVER_SIGN_KEY.exists():
        raise SystemExit("System not initialised. Run: python -m secure_exam.init_system")

    service = ExamService()
    service.audit.verify()                   # refuse to start on a tampered audit log
    socket_server = ExamServer(args.host, args.port, service)
    socket_server.start()
    print(f"[*] TLS socket server  on {args.host}:{socket_server.port}")
    api = web = None
    if not args.no_api:
        from .api import ApiServer
        api = ApiServer(args.host, args.api_port, service)
        api.start()
        print(f"[*] HTTPS JSON API     on https://{config.SERVER_HOSTNAME}:{api.port}/api/v1")
        if not args.no_web:
            from .web import WebServer
            web = WebServer(args.host, args.web_port, api.port)
            web.start()
            print(f"[*] Web frontend       on {web.url}")
    print("[*] Ctrl+C to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
    finally:
        socket_server.stop()
        if api:
            api.stop()
        if web:
            web.stop()


if __name__ == "__main__":
    main()
