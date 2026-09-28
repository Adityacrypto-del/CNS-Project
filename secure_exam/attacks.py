"""Attack simulations against a live server (Objective 7: attack detection).

    python -m secure_exam.attacks

Runs in a throw-away sandbox: fresh keys, fresh databases, and both transports (TLS socket
server and HTTPS API) on random ports, so the real data directory is never touched. Each
scenario returns an AttackResult; `blocked=True` means the system detected / prevented the
attack as expected.

Threat model for channel attacks: the attacker is positioned *inside* the TLS tunnel
(e.g. a compromised proxy or malware on the client host) and can capture, modify and
re-inject application frames. TLS alone would stop an on-path network attacker; these
tests show the application layer still holds when that outer layer is bypassed.
"""

import http.client
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import config
from .client import ExamClient, ServerError, load_key_file
from .crypto_utils import (IntegrityError, b64d, b64e, canonical_json, load_public_key,
                           private_key_to_pem, public_key_to_pem, rsa_generate, rsa_sign,
                           rsa_verify)
from .init_system import ADMIN, DEMO_STUDENTS, PENDING_CODE, PENDING_STUDENT
from .pki import cert_to_pem, create_ca, issue_server_cert
from .protocol import SecureChannel, handshake_transcript, recv_frame, send_frame, send_raw_frame
from .storage import EncryptedStore, load_wrapped_key

PASSWORDS = {sid: pw for sid, _, _, pw in DEMO_STUDENTS}
ADMIN_ID, ADMIN_PASSWORD = ADMIN[0], ADMIN[2]
PENDING_PASSWORD = "Dev#Secure2026"
MIDTERM, QUIZ, DRAFT = "CNS-MIDTERM-2026", "CNS-QUIZ-1", "CNS-FINAL-2026"


@dataclass
class AttackResult:
    name: str
    category: str
    blocked: bool
    detail: str


class Sandbox:
    """Socket server + HTTPS API sharing one ExamService."""

    def __init__(self, server, api):
        self.server, self.api, self.service = server, api, server.service
        self._admin_key = None

    @property
    def socket_port(self) -> int:
        return self.server.port

    @property
    def api_port(self) -> int:
        return self.api.port

    @property
    def admin_key(self):
        if self._admin_key is None:
            self._admin_key = load_key_file(ADMIN_ID, ADMIN_PASSWORD)
        return self._admin_key

    def client(self, transport: str = "socket") -> ExamClient:
        port = self.api_port if transport == "https" else self.socket_port
        return ExamClient(config.HOST, port, transport).connect()

    def student(self, sid: str, transport: str = "socket", password: str | None = None) -> ExamClient:
        c = self.client(transport)
        c.login(sid, password or PASSWORDS[sid])
        return c

    def admin(self, transport: str = "socket") -> ExamClient:
        c = self.client(transport)
        c.login(ADMIN_ID, ADMIN_PASSWORD, role="admin")
        return c

    def stop(self) -> None:
        self.server.stop()
        self.api.stop()


def run_in_sandbox(module: str) -> None:
    """Re-execute `module` with SECURE_EXAM_DATA pointing at a temporary directory."""
    if os.environ.get("SECURE_EXAM_DATA"):
        return
    tmp = tempfile.mkdtemp(prefix="secure-exam-sandbox-")
    try:
        env = {**os.environ, "SECURE_EXAM_DATA": tmp}
        code = subprocess.call([sys.executable, "-m", module, *sys.argv[1:]], env=env)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(code)


def start_sandbox() -> Sandbox:
    from .api import ApiServer
    from .init_system import initialise
    from .server import ExamServer
    initialise(force=True, quiet=True)
    server = ExamServer(config.HOST, 0)
    server.start()
    api = ApiServer(config.HOST, 0, server.service)
    api.start()
    return Sandbox(server, api)


# --- helpers -------------------------------------------------------------------

def _expect(code: str, fn, *args, **kwargs) -> tuple[bool, str]:
    """Run a request that must be refused with `code`."""
    try:
        fn(*args, **kwargs)
        return False, "request was accepted"
    except ServerError as exc:
        return exc.code == code, str(exc)


def _server_reply(client: ExamClient) -> dict:
    """Read the server's reply to an injected socket frame; {} if it just hung up."""
    try:
        return client.channel.recv()
    except (ConnectionError, OSError):
        return {}


def _post_rpc(client: ExamClient, envelope: dict, session_id: str | None = None) -> tuple[int, dict]:
    return client.transport._post("/rpc", {"session_id": session_id or client.transport.session_id,
                                           "envelope": envelope})


def _signed_action(client: ExamClient, key, op: str, params: dict, ts: int | None = None) -> dict:
    action = {"op": op, "params": params, "admin_id": client.user_id,
              "ts": ts if ts is not None else int(time.time()), "nonce": b64e(os.urandom(16))}
    return {"type": "ADMIN_ACTION", "action": action,
            "signature": b64e(rsa_sign(key, canonical_json(action)))}


def _last_audit_events(n: int = 5) -> list[str]:
    return [line for line in config.AUDIT_LOG.read_text().strip().splitlines()[-n:]]


# ================================================================================
# 1. Tampering
# ================================================================================

def attack_tamper_ciphertext(sb: Sandbox) -> AttackResult:
    with sb.client() as c:
        env = c.channel.seal({"type": "LOGIN", "user_id": "S1001", "password": PASSWORDS["S1001"]})
        ct = bytearray(b64d(env["ct"]))
        ct[5] ^= 0x01                                          # flip one bit
        env["ct"] = b64e(bytes(ct))
        send_frame(c.sock, env)
        reply = _server_reply(c)
    return AttackResult("Bit-flip in encrypted LOGIN message (socket)", "Tampering",
                        reply.get("error") == "TAMPERING_DETECTED",
                        f"server replied {reply.get('error')!r}: {reply.get('detail', '')}")


def attack_tamper_header(sb: Sandbox) -> AttackResult:
    with sb.student("S1001") as c:
        env = c.channel.seal({"type": "LIST_EXAMS"})
        env["seq"] += 10                                       # try to skip ahead in the sequence
        send_frame(c.sock, env)
        reply = _server_reply(c)
    return AttackResult("Modify sequence number in message header", "Tampering",
                        reply.get("error") == "TAMPERING_DETECTED",
                        f"server replied {reply.get('error')!r} (header is covered by the HMAC)")


def attack_tamper_https_envelope(sb: Sandbox) -> AttackResult:
    with sb.client("https") as c:
        env = c.channel.seal({"type": "LOGIN", "user_id": "S1001", "password": PASSWORDS["S1001"]})
        iv = bytearray(b64d(env["iv"]))
        iv[0] ^= 0x80
        env["iv"] = b64e(bytes(iv))
        status, body = _post_rpc(c, env)
        reply = c.channel.open(body["envelope"]) if "envelope" in body else {}
        follow_status, _ = _post_rpc(c, c.channel.seal({"type": "WHOAMI"}))
    blocked = status == 400 and reply.get("error") == "TAMPERING_DETECTED" and follow_status == 401
    return AttackResult("Modify IV of an HTTPS API envelope", "Tampering", blocked,
                        f"HTTP {status} {reply.get('error')!r}; session then revoked "
                        f"(next request HTTP {follow_status})")


def attack_modify_signed_answers(sb: Sandbox) -> AttackResult:
    with sb.student("S1002") as c:
        c.get_exam(MIDTERM)
        key = load_key_file("S1002", PASSWORDS["S1002"])
        submission = c.build_submission(MIDTERM, {"Q1": "A"})
        signature = rsa_sign(key, canonical_json(submission))
        submission["answers"]["Q1"] = "C"                     # changed after signing
        blocked, detail = _expect("INVALID_SIGNATURE", c.request,
                                  {"type": "SUBMIT", "submission": submission,
                                   "signature": b64e(signature)})
    return AttackResult("Alter answers after they were signed", "Tampering", blocked, detail)


def attack_forged_exam_paper(sb: Sandbox) -> AttackResult:
    with sb.student("S1003") as c:
        signed = c.call("GET_EXAM", exam_id=QUIZ)["paper"]
        signed["body"]["exam"]["questions"][0]["text"] = "Injected question from attacker"
        try:
            c.verify_signed(signed)
            blocked, detail = False, "client accepted forged paper"
        except IntegrityError as exc:
            blocked, detail = True, f"client rejected paper: {exc or 'RSA-PSS signature invalid'}"
    return AttackResult("Modify exam paper in transit (server-signed)", "Tampering", blocked, detail)


def attack_tamper_storage(sb: Sandbox) -> AttackResult:
    original = config.EXAMS_DB.read_bytes()
    blob = bytearray(original)
    blob[40] ^= 0xFF
    config.EXAMS_DB.write_bytes(bytes(blob))
    try:
        sb.service.exams_db.load()
        blocked, detail = False, "tampered database decrypted"
    except IntegrityError as exc:
        blocked, detail = True, f"AES-GCM rejected it: {exc}"
    finally:
        config.EXAMS_DB.write_bytes(original)
    return AttackResult("Tamper with encrypted exam database on disk", "Tampering", blocked, detail)


def attack_swap_storage_files(sb: Sandbox) -> AttackResult:
    """Replace the answer-key file with another valid ciphertext (same key, different file)."""
    original = config.ANSWER_KEYS_DB.read_bytes()
    config.ANSWER_KEYS_DB.write_bytes(config.EXAMS_DB.read_bytes())
    try:
        sb.service.answers_db.load()
        blocked, detail = False, "swapped file decrypted"
    except IntegrityError as exc:
        blocked, detail = True, f"file name is GCM associated data: {exc}"
    finally:
        config.ANSWER_KEYS_DB.write_bytes(original)
    return AttackResult("Swap one encrypted database file for another", "Tampering", blocked, detail)


def attack_tamper_audit_log(sb: Sandbox) -> AttackResult:
    original = config.AUDIT_LOG.read_text()
    lines = original.strip().splitlines()
    doctored = [ln for ln in lines if "TAMPERING_DETECTED" not in ln]   # hide the evidence
    if len(doctored) == len(lines):
        doctored = lines[:1] + lines[2:]
    config.AUDIT_LOG.write_text("\n".join(doctored) + "\n")
    try:
        sb.service.audit.verify()
        blocked, detail = False, "deletion went unnoticed"
    except IntegrityError as exc:
        blocked, detail = True, str(exc)
    finally:
        config.AUDIT_LOG.write_text(original)
    return AttackResult("Delete entries from the audit log", "Tampering", blocked, detail)


# ================================================================================
# 2. Replay
# ================================================================================

def attack_replay_same_session(sb: Sandbox) -> AttackResult:
    with sb.student("S1003") as c:
        env = c.channel.seal({"type": "LIST_EXAMS"})
        send_frame(c.sock, env)
        c.channel.recv()                                       # legitimate response
        send_frame(c.sock, env)                                # replay identical frame
        reply = _server_reply(c)
    return AttackResult("Replay a captured request in the same session (socket)", "Replay",
                        reply.get("error") == "REPLAY_DETECTED",
                        f"server replied {reply.get('error')!r}: {reply.get('detail', '')}")


def attack_replay_https(sb: Sandbox) -> AttackResult:
    with sb.student("S1003", "https") as c:
        env = c.channel.seal({"type": "LIST_EXAMS"})
        first, body1 = _post_rpc(c, env)
        c.channel.open(body1["envelope"])
        second, body2 = _post_rpc(c, env)                      # replay identical envelope
        reply = c.channel.open(body2["envelope"]) if "envelope" in body2 else {}
    return AttackResult("Replay a captured HTTPS API request", "Replay",
                        first == 200 and second == 400 and reply.get("error") == "REPLAY_DETECTED",
                        f"first HTTP {first}, replay HTTP {second} {reply.get('error')!r}")


def attack_replay_new_session(sb: Sandbox) -> AttackResult:
    # Record a victim's full session at the frame level: HELLO + encrypted LOGIN.
    with sb.client() as c:
        hello = c.hello_frame
        login_env = c.channel.seal({"type": "LOGIN", "user_id": "S1001",
                                    "password": PASSWORDS["S1001"]})

    # Replay it on a brand new connection.
    tls = ssl.create_default_context(cafile=str(config.CA_CERT))
    sock = tls.wrap_socket(socket.create_connection((config.HOST, sb.socket_port)),
                           server_hostname=config.SERVER_HOSTNAME)
    try:
        send_frame(sock, hello)
        recv_frame(sock)                                       # HELLO_OK with a *new* server nonce
        send_frame(sock, login_env)
        try:
            reply = recv_frame(sock)
            replied = "encrypted error frame (attacker cannot read it)" if "ct" in reply else reply
        except (ConnectionError, OSError):
            replied = "connection closed"
    finally:
        sock.close()
    time.sleep(0.1)
    blocked = any("TAMPERING_DETECTED" in e for e in _last_audit_events())
    return AttackResult("Replay a whole recorded session on a new connection", "Replay", blocked,
                        f"fresh server nonce -> different session keys -> MAC fails; got {replied}")


def attack_stale_message(sb: Sandbox) -> AttackResult:
    with sb.student("S1001") as c:
        real_time = time.time
        time.time = lambda: real_time() - 10 * 60              # message created 10 minutes ago
        try:
            env = c.channel.seal({"type": "LIST_EXAMS"})
        finally:
            time.time = real_time
        send_frame(c.sock, env)
        reply = _server_reply(c)
    return AttackResult("Delayed / stale message (10 min old)", "Replay",
                        reply.get("error") == "REPLAY_DETECTED",
                        f"server replied {reply.get('error')!r}: {reply.get('detail', '')}")


def attack_duplicate_submission(sb: Sandbox) -> AttackResult:
    with sb.student("S1001") as c:
        c.get_exam(QUIZ)
        key = load_key_file("S1001", PASSWORDS["S1001"])
        c.submit(QUIZ, {"Q1": "C", "Q2": "A"}, key)
        blocked, detail = _expect("ALREADY_SUBMITTED", c.submit, QUIZ,
                                  {"Q1": "C", "Q2": "A", "Q3": "B"}, key)
    return AttackResult("Resubmit answers after first submission", "Replay", blocked, detail)


def attack_replay_admin_action(sb: Sandbox) -> AttackResult:
    with sb.admin() as c:
        req = _signed_action(c, sb.admin_key, "UNLOCK_ACCOUNT", {"user_id": "S1001"})
        c.request(req)                                         # legitimate
        blocked, detail = _expect("REPLAYED_ACTION", c.request, req)
    return AttackResult("Replay a signed examiner action", "Replay", blocked, detail)


def attack_stale_admin_action(sb: Sandbox) -> AttackResult:
    with sb.admin() as c:
        req = _signed_action(c, sb.admin_key, "RELEASE_RESULTS", {"exam_id": MIDTERM},
                             ts=int(time.time()) - 3600)
        blocked, detail = _expect("STALE_ACTION", c.request, req)
    return AttackResult("Re-use an hour-old signed examiner action", "Replay", blocked, detail)


# ================================================================================
# 3. Unauthorized access
# ================================================================================

def attack_no_login(sb: Sandbox) -> AttackResult:
    with sb.client() as c:
        blocked, detail = _expect("UNAUTHORIZED", c.call, "GET_EXAM", exam_id=MIDTERM)
    return AttackResult("Request exam paper without logging in", "Unauthorized access",
                        blocked, detail)


def attack_wrong_password(sb: Sandbox) -> AttackResult:
    with sb.client() as c:
        blocked, detail = _expect("INVALID_CREDENTIALS", c.login, "S1002", "password123")
    return AttackResult("Login with wrong password", "Unauthorized access", blocked, detail)


def attack_brute_force(sb: Sandbox) -> AttackResult:
    target = "S1003"
    guesses = ["123456", "password", "qwerty", "letmein", "admin", "Chitra123",
               PASSWORDS[target]]                              # correct one is last
    last = None
    for guess in guesses:
        with sb.client() as c:
            try:
                c.login(target, guess)
                last = "LOGGED_IN"
            except ServerError as exc:
                last = exc.code
    sb.service.failed.pop(f"student:{target}", None)          # reset for later scenarios
    return AttackResult("Online brute-force of a password", "Unauthorized access",
                        last == "ACCOUNT_LOCKED",
                        f"after {config.MAX_FAILED_LOGINS} failures even the correct password "
                        f"gets {last!r}")


def attack_concurrent_session(sb: Sandbox) -> AttackResult:
    with sb.student("S1002"):
        with sb.client("https") as thief:
            blocked, detail = _expect("SESSION_ACTIVE", thief.login, "S1002", PASSWORDS["S1002"])
    return AttackResult("Second login with stolen credentials while victim is online",
                        "Unauthorized access", blocked, detail)


def attack_session_hijack_https(sb: Sandbox) -> AttackResult:
    """Attacker steals a logged-in victim's session_id but not the session keys."""
    with sb.student("S1002", "https") as victim:
        attacker = SecureChannel(None, os.urandom(32), os.urandom(32), is_server=False)
        status, body = _post_rpc(victim, attacker.seal({"type": "GET_RESULT", "exam_id": QUIZ}))
        try:
            attacker.open(body.get("envelope", {}))
            readable = True
        except Exception:
            readable = False
    return AttackResult("Hijack HTTPS session with a stolen session_id", "Unauthorized access",
                        status == 400 and not readable,
                        f"HTTP {status}; forged envelope failed the MAC, reply unreadable to the "
                        "attacker, session revoked")


def attack_unknown_session(sb: Sandbox) -> AttackResult:
    with sb.client("https") as c:
        status, body = _post_rpc(c, c.channel.seal({"type": "WHOAMI"}), session_id="guessed-id")
    return AttackResult("Call the HTTPS API with a guessed session_id", "Unauthorized access",
                        status == 401, f"HTTP {status} {body.get('error')}")


def attack_impersonate_submission(sb: Sandbox) -> AttackResult:
    with sb.student("S1002") as c:
        c.get_exam(MIDTERM)
        submission = c.build_submission(MIDTERM, {"Q1": "A"})
        submission["student_id"] = "S1003"                     # submit on behalf of someone else
        sig = rsa_sign(load_key_file("S1002", PASSWORDS["S1002"]), canonical_json(submission))
        blocked, detail = _expect("UNAUTHORIZED", c.request,
                                  {"type": "SUBMIT", "submission": submission,
                                   "signature": b64e(sig)})
    return AttackResult("Submit answers as another student", "Unauthorized access", blocked, detail)


def attack_forged_signature(sb: Sandbox) -> AttackResult:
    with sb.student("S1002") as c:
        c.get_exam(MIDTERM)
        rogue_key = rsa_generate(2048)                         # attacker's own key
        blocked, detail = _expect("INVALID_SIGNATURE", c.submit, MIDTERM, {"Q1": "C"}, rogue_key)
    return AttackResult("Sign submission with an unregistered key", "Unauthorized access",
                        blocked, detail)


def attack_student_privilege_escalation(sb: Sandbox) -> AttackResult:
    with sb.student("S1001") as c:
        ok1, d1 = _expect("FORBIDDEN", c.call, "ADMIN_LIST_STUDENTS")
        req = _signed_action(c, load_key_file("S1001", PASSWORDS["S1001"]), "RELEASE_RESULTS",
                             {"exam_id": MIDTERM})
        req["action"]["admin_id"] = ADMIN_ID
        ok2, d2 = _expect("FORBIDDEN", c.request, req)
    return AttackResult("Student calls examiner operations", "Unauthorized access",
                        ok1 and ok2, f"read: {d1}; action: {d2}")


def attack_forged_admin_action(sb: Sandbox) -> AttackResult:
    """Attacker has the examiner's password but not their signing key."""
    with sb.admin() as c:
        blocked, detail = _expect("INVALID_SIGNATURE", c.request,
                                  _signed_action(c, rsa_generate(2048), "RELEASE_RESULTS",
                                                 {"exam_id": MIDTERM}))
    released = sb.service.exams_db.load()[MIDTERM]["results_released"]
    return AttackResult("Examiner action signed with the wrong key (stolen password only)",
                        "Unauthorized access", blocked and not released, detail)


def attack_results_before_release(sb: Sandbox) -> AttackResult:
    with sb.student("S1001") as c:
        blocked, detail = _expect("RESULTS_NOT_RELEASED", c.get_result, QUIZ)
    return AttackResult("Fetch result before the examiner releases it", "Unauthorized access",
                        blocked, detail)


def attack_draft_exam_access(sb: Sandbox) -> AttackResult:
    with sb.student("S1001") as c:
        blocked, detail = _expect("NO_SUCH_EXAM", c.get_exam, DRAFT)
        listed = DRAFT in {e["exam_id"] for e in c.list_exams()}
    return AttackResult("Open an unpublished (draft) exam paper", "Unauthorized access",
                        blocked and not listed, f"{detail}; not shown in LIST_EXAMS")


def attack_exam_outside_window(sb: Sandbox) -> AttackResult:
    now = int(time.time())
    exam = {"exam_id": "CNS-FUTURE-1", "title": "Future exam", "duration_minutes": 20,
            "opens_at": now + 86400, "closes_at": now + 2 * 86400,
            "questions": [{"id": "Q1", "text": "?", "options": {"A": "x", "B": "y"}}]}
    with sb.admin() as a:
        a.admin_action("CREATE_EXAM", {"exam": exam, "answer_key": {"Q1": "A"}}, sb.admin_key)
        a.admin_action("PUBLISH_EXAM", {"exam_id": "CNS-FUTURE-1"}, sb.admin_key)
    with sb.student("S1001") as c:
        blocked, detail = _expect("EXAM_NOT_OPEN", c.get_exam, "CNS-FUTURE-1")
    return AttackResult("Open a published exam before its window", "Unauthorized access",
                        blocked, detail)


def attack_enroll_wrong_code(sb: Sandbox) -> AttackResult:
    with sb.client() as c:
        blocked, detail = _expect("INVALID_ENROLLMENT", c.enroll, PENDING_STUDENT[0],
                                  "AAAA-BBBB-CCCC-DDDD", PENDING_PASSWORD)
    return AttackResult("Enroll with a guessed enrollment code", "Unauthorized access",
                        blocked, detail)


def attack_enroll_bad_proof(sb: Sandbox) -> AttackResult:
    """Register someone else's public key without holding its private key."""
    sid = PENDING_STUDENT[0]
    victim_pub = public_key_to_pem(rsa_generate(2048).public_key()).decode()
    proof = rsa_sign(rsa_generate(2048), canonical_json({"student_id": sid, "public_key": victim_pub,
                                                          "purpose": "enroll"}))
    with sb.client() as c:
        blocked, detail = _expect("INVALID_PUBLIC_KEY", c.call, "ENROLL", student_id=sid,
                                  enrollment_code=PENDING_CODE, password=PENDING_PASSWORD,
                                  public_key=victim_pub, proof=b64e(proof))
    return AttackResult("Enroll a public key without proof of possession", "Unauthorized access",
                        blocked, detail)


def attack_enroll_code_reuse(sb: Sandbox) -> AttackResult:
    sid = PENDING_STUDENT[0]
    with sb.client() as c:
        c.enroll(sid, PENDING_CODE, PENDING_PASSWORD)          # the legitimate student
    with sb.client() as c:                                     # attacker who saw the code
        blocked, detail = _expect("INVALID_ENROLLMENT", c.enroll, sid, PENDING_CODE,
                                  "Attacker#Pass2026")
    return AttackResult("Re-use a consumed enrollment code to take over an account",
                        "Unauthorized access", blocked, detail)


def attack_weak_password(sb: Sandbox) -> AttackResult:
    with sb.student("S1001") as c:
        blocked, detail = _expect("WEAK_PASSWORD", c.call, "CHANGE_PASSWORD",
                                  old_password=PASSWORDS["S1001"], new_password="password1")
    return AttackResult("Set a weak password", "Unauthorized access", blocked, detail)


def attack_plaintext_connection(sb: Sandbox) -> AttackResult:
    sock = socket.create_connection((config.HOST, sb.socket_port))
    try:
        send_raw_frame(sock, b'{"type":"HELLO"}')
        sock.settimeout(3)
        data = sock.recv(100)
        blocked, detail = b"HELLO_OK" not in data, "server refused non-TLS client"
    except (ConnectionError, OSError):
        blocked, detail = True, "server closed non-TLS connection"
    finally:
        sock.close()
    return AttackResult("Connect to the socket server without TLS", "Unauthorized access",
                        blocked, detail)


def attack_plaintext_http(sb: Sandbox) -> AttackResult:
    conn = http.client.HTTPConnection(config.HOST, sb.api_port, timeout=5)
    try:
        conn.request("GET", "/api/v1/health")
        status = conn.getresponse().status
        blocked, detail = status != 200, f"HTTP {status}"
    except (ConnectionError, OSError, http.client.HTTPException) as exc:
        blocked, detail = True, f"plain HTTP refused ({type(exc).__name__})"
    finally:
        conn.close()
    return AttackResult("Call the API over plain HTTP", "Unauthorized access", blocked, detail)


def attack_tls_downgrade(sb: Sandbox) -> AttackResult:
    ctx = ssl.create_default_context(cafile=str(config.CA_CERT))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    results = []
    for port in (sb.socket_port, sb.api_port):
        raw = socket.create_connection((config.HOST, port), timeout=5)
        try:
            ctx.wrap_socket(raw, server_hostname=config.SERVER_HOSTNAME).close()
            results.append(False)
        except (ssl.SSLError, OSError):
            results.append(True)
        finally:
            raw.close()
    return AttackResult("Force a TLS 1.2 downgrade", "Unauthorized access", all(results),
                        "both transports require TLS 1.3" if all(results) else f"{results}")


# ================================================================================
# 4. Man-in-the-middle / rogue server
# ================================================================================

def _rogue_server(cert_pem: bytes, key_pem: bytes, sign_key) -> int:
    """Start a fake exam server; returns its port."""
    tmp = Path(tempfile.mkdtemp())
    (tmp / "c.pem").write_bytes(cert_pem)
    (tmp / "k.pem").write_bytes(key_pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp / "c.pem", tmp / "k.pem")
    shutil.rmtree(tmp)
    lsock = socket.socket()
    lsock.bind((config.HOST, 0))
    lsock.listen(1)

    def serve():
        raw, _ = lsock.accept()
        conn = raw
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
            hello = recv_frame(conn)
            nonce = os.urandom(32)
            sig = rsa_sign(sign_key, handshake_transcript(b64d(hello["client_nonce"]), nonce,
                                                          b64d(hello["wrapped_master"])))
            send_frame(conn, {"type": "HELLO_OK", "server_nonce": b64e(nonce),
                              "signature": b64e(sig)})
            time.sleep(0.5)
        except Exception:
            pass
        finally:
            conn.close()
            raw.close()
            lsock.close()

    threading.Thread(target=serve, daemon=True).start()
    return lsock.getsockname()[1]


def _connect_to(port: int):
    c = ExamClient(config.HOST, port)
    try:
        c.connect()
    finally:
        c.transport.close()


def attack_rogue_tls_server(sb: Sandbox) -> AttackResult:
    ca_key, ca_cert = create_ca()                              # attacker's own CA
    key, cert = issue_server_cert(ca_key, ca_cert, config.SERVER_HOSTNAME)
    port = _rogue_server(cert_to_pem(cert), private_key_to_pem(key), rsa_generate(2048))
    try:
        _connect_to(port)
        blocked, detail = False, "client trusted rogue server"
    except ssl.SSLCertVerificationError as exc:
        blocked, detail = True, f"TLS rejected certificate: {exc.verify_message}"
    return AttackResult("MITM with a certificate from an untrusted CA", "MITM", blocked, detail)


def attack_stolen_tls_cert(sb: Sandbox) -> AttackResult:
    # Worst case: attacker stole the real TLS key but not the application signing key.
    port = _rogue_server(config.SERVER_TLS_CERT.read_bytes(), config.SERVER_TLS_KEY.read_bytes(),
                         rsa_generate(2048))
    try:
        _connect_to(port)
        blocked, detail = False, "client trusted impostor"
    except IntegrityError:
        blocked, detail = True, "TLS passed, but the RSA-PSS handshake signature did not verify"
    return AttackResult("Impostor server with stolen TLS certificate", "MITM", blocked, detail)


# ================================================================================
# 5. Key management / non-repudiation
# ================================================================================

def attack_old_storage_key(sb: Sandbox) -> AttackResult:
    """After rotation, a leaked copy of the old storage key no longer decrypts anything."""
    old_key = load_wrapped_key(sb.service.sign_key, config.STORAGE_KEY_WRAPPED)
    with sb.admin() as c:
        c.admin_action("ROTATE_STORAGE_KEY", {}, sb.admin_key)
    try:
        EncryptedStore(config.STUDENTS_DB, old_key).load()
        blocked, detail = False, "old key still decrypts the database"
    except IntegrityError:
        still_readable = "S1001" in sb.service.students_db.load()
        blocked = still_readable
        detail = "old key rejected by AES-GCM; data re-encrypted and still readable by the server"
    with sb.student("S1001"):                                  # the system keeps working
        pass
    return AttackResult("Use a leaked storage key after key rotation", "Key management",
                        blocked, detail)


def check_non_repudiation(sb: Sandbox) -> AttackResult:
    """A student later denies submitting: verify the stored signature against their public key."""
    record = sb.service.submissions_db.load().get(QUIZ, {}).get("submissions", {}).get("S1001")
    if record is None:
        return AttackResult("Student denies making a submission", "Non-repudiation", False,
                            "no submission on record")
    pub = load_public_key(sb.service.students_db.load()["S1001"]["public_key"].encode())
    rsa_verify(pub, b64d(record["signature"]), canonical_json(record["submission"]))
    receipt = record["receipt"]
    rsa_verify(sb.service.sign_key.public_key(), b64d(receipt["signature"]),
               canonical_json(receipt["body"]))
    return AttackResult("Student denies making a submission", "Non-repudiation", True,
                        "stored submission verifies under S1001's public key; "
                        "server receipt verifies under the server key")


def check_admin_accountability(sb: Sandbox) -> AttackResult:
    """Every accepted examiner action is in the audit log with the examiner's signature."""
    entries = [e for e in sb.service.audit.entries() if e["event"] == "ADMIN_ACTION"]
    ok = bool(entries) and all(e["details"].get("signature") and e["details"].get("action_hash")
                               and e["details"].get("user") == ADMIN_ID for e in entries)
    return AttackResult("Examiner denies publishing / releasing / rotating", "Non-repudiation", ok,
                        f"{len(entries)} examiner actions logged with RSA-PSS signature and "
                        "SHA-256 action hash in the HMAC-chained audit log")


ALL_ATTACKS = [
    attack_tamper_ciphertext, attack_tamper_header, attack_tamper_https_envelope,
    attack_modify_signed_answers, attack_forged_exam_paper, attack_tamper_storage,
    attack_swap_storage_files, attack_tamper_audit_log,
    attack_replay_same_session, attack_replay_https, attack_replay_new_session,
    attack_stale_message, attack_duplicate_submission, attack_replay_admin_action,
    attack_stale_admin_action,
    attack_no_login, attack_wrong_password, attack_brute_force, attack_concurrent_session,
    attack_session_hijack_https, attack_unknown_session, attack_impersonate_submission,
    attack_forged_signature, attack_student_privilege_escalation, attack_forged_admin_action,
    attack_results_before_release, attack_draft_exam_access, attack_exam_outside_window,
    attack_enroll_wrong_code, attack_enroll_bad_proof, attack_enroll_code_reuse,
    attack_weak_password, attack_plaintext_connection, attack_plaintext_http,
    attack_tls_downgrade,
    attack_rogue_tls_server, attack_stolen_tls_cert,
    attack_old_storage_key, check_non_repudiation, check_admin_accountability,
]


def run_all(sb: Sandbox) -> list[AttackResult]:
    results = []
    for attack in ALL_ATTACKS:
        try:
            results.append(attack(sb))
        except Exception as exc:  # an unexpected exception is a failed test, not a crash
            results.append(AttackResult(attack.__name__, "ERROR", False, repr(exc)))
    return results


def print_results(results: list[AttackResult]) -> None:
    width = max(len(r.name) for r in results)
    category = None
    for r in results:
        if r.category != category:
            category = r.category
            print(f"\n  {category}")
        mark = "\033[32mBLOCKED\033[0m" if r.blocked else "\033[31mNOT BLOCKED\033[0m"
        print(f"    {r.name:<{width}}  {mark}")
        print(f"      └─ {r.detail}")
    ok = sum(r.blocked for r in results)
    print(f"\n  {ok}/{len(results)} attacks detected or prevented\n")


def main() -> None:
    run_in_sandbox("secure_exam.attacks")
    print("[*] Setting up sandbox (fresh keys, databases, socket server and HTTPS API)…")
    sb = start_sandbox()
    try:
        results = run_all(sb)
    finally:
        sb.stop()
    print_results(results)
    sys.exit(0 if all(r.blocked for r in results) else 1)


if __name__ == "__main__":
    main()
