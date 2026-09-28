"""Client library and student command-line client.

    python -m secure_exam.client                      # log in and sit exams
    python -m secure_exam.client enroll               # first-time account activation
    python -m secure_exam.client verify-receipt FILE  # offline receipt check
    python -m secure_exam.client --transport https    # use the HTTPS API instead of the socket

ExamClient speaks the secure protocol over either transport:
  * "socket": length-prefixed frames on a TLS 1.3 socket (server.py)
  * "https" : the same envelopes POSTed to the HTTPS JSON API (api.py)
"""

import argparse
import getpass
import http.client
import json
import os
import socket
import ssl
import time
from pathlib import Path

from . import config
from .crypto_utils import (IntegrityError, b64d, b64e, canonical_json, load_private_key,
                           load_public_key, private_key_to_pem, public_key_to_pem, rsa_generate,
                           rsa_sign, rsa_verify, sha256_hex)
from .protocol import (ProtocolError, SecureChannel, client_finish, client_hello, recv_frame,
                       send_frame)


class ServerError(Exception):
    def __init__(self, response: dict):
        self.response = response
        self.code = response.get("error")
        super().__init__(f"{response.get('error')}: {response.get('detail', '')}".rstrip(": "))


def client_tls_context(ca_cert=config.CA_CERT) -> ssl.SSLContext:
    # Verifies the certificate chain against the system CA and the hostname against the SAN.
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


# --- Transports ----------------------------------------------------------------

class SocketTransport:
    def __init__(self, host: str, port: int, ca_cert):
        self.host, self.port, self.tls = host, port, client_tls_context(ca_cert)
        self.sock: ssl.SSLSocket | None = None

    def open(self, hello: dict) -> dict:
        raw = socket.create_connection((self.host, self.port), timeout=30)
        self.sock = self.tls.wrap_socket(raw, server_hostname=config.SERVER_HOSTNAME)
        send_frame(self.sock, hello)
        return recv_frame(self.sock)

    def exchange(self, envelope: dict) -> dict:
        send_frame(self.sock, envelope)
        return recv_frame(self.sock)

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None


class HttpsTransport:
    def __init__(self, host: str, port: int, ca_cert):
        self.host, self.port, self.tls = host, port, client_tls_context(ca_cert)
        self.conn: http.client.HTTPSConnection | None = None
        self.session_id: str | None = None
        self.sock = None                      # socket-level attacks do not apply here

    def _post(self, path: str, body: dict) -> tuple[int, dict]:
        data = json.dumps(body).encode()
        self.conn.request("POST", f"/api/v1{path}", body=data,
                          headers={"Content-Type": "application/json"})
        resp = self.conn.getresponse()
        return resp.status, json.loads(resp.read() or b"{}")

    def open(self, hello: dict) -> dict:
        self.conn = http.client.HTTPSConnection(config.SERVER_HOSTNAME, self.port, timeout=30,
                                                context=self.tls)
        # Connect to the configured address but verify the certificate for SERVER_HOSTNAME.
        self.conn.sock = self.tls.wrap_socket(socket.create_connection((self.host, self.port), 30),
                                              server_hostname=config.SERVER_HOSTNAME)
        status, body = self._post("/handshake", hello)
        if status != 200:
            raise ProtocolError(f"handshake failed: HTTP {status} {body}")
        self.session_id = body.pop("session_id")
        return body

    def exchange(self, envelope: dict) -> dict:
        status, body = self._post("/rpc", {"session_id": self.session_id, "envelope": envelope})
        if "envelope" not in body:
            raise ProtocolError(f"HTTP {status}: {body.get('error')}")
        return body["envelope"]

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None


# --- Client --------------------------------------------------------------------

class ExamClient:
    def __init__(self, host: str = config.HOST, port: int | None = None, transport: str = "socket",
                 ca_cert=config.CA_CERT, server_pub=config.SERVER_SIGN_PUB):
        # The server's application signing key is pinned (distributed out of band).
        self.server_pub = load_public_key(Path(server_pub).read_bytes())
        if transport == "https":
            self.transport = HttpsTransport(host, port or config.API_PORT, ca_cert)
        else:
            self.transport = SocketTransport(host, port or config.PORT, ca_cert)
        self.channel: SecureChannel | None = None
        self.user_id: str | None = None
        self.role: str | None = None
        self.papers: dict[str, dict] = {}
        self.hello_frame: dict | None = None

    @property
    def sock(self):
        return self.transport.sock

    # --- connection ---------------------------------------------------------

    def connect(self) -> "ExamClient":
        hello, client_nonce, master = client_hello(self.server_pub)
        self.hello_frame = hello
        reply = self.transport.open(hello)
        k_enc, k_mac = client_finish(self.server_pub, hello, client_nonce, master, reply)
        self.channel = SecureChannel(self.transport.sock, k_enc, k_mac, is_server=False)
        return self

    def close(self) -> None:
        if self.channel and self.user_id:
            try:                                              # best-effort: free the session now
                self.transport.exchange(self.channel.seal({"type": "LOGOUT"}))
            except (OSError, ValueError, ProtocolError, http.client.HTTPException):
                pass
            self.user_id = None
        self.transport.close()

    def __enter__(self):
        return self if self.channel else self.connect()

    def __exit__(self, *exc):
        self.close()

    def request(self, payload: dict) -> dict:
        response = self.channel.open(self.transport.exchange(self.channel.seal(payload)))
        if not response.get("ok"):
            raise ServerError(response)
        return response

    def call(self, op: str, **params) -> dict:
        return self.request({"type": op, **params})

    def verify_signed(self, signed: dict) -> dict:
        rsa_verify(self.server_pub, b64d(signed["signature"]), canonical_json(signed["body"]))
        return signed["body"]

    # --- common ---------------------------------------------------------------

    def login(self, user_id: str, password: str, role: str = "student") -> dict:
        resp = self.call("LOGIN", user_id=user_id, password=password, role=role)
        self.user_id, self.role = user_id, role
        return resp

    def logout(self) -> None:
        self.call("LOGOUT")
        self.user_id = None

    def change_password(self, old: str, new: str) -> None:
        self.call("CHANGE_PASSWORD", old_password=old, new_password=new)
        # Keep the local signing key protected by the current password.
        rewrap_key_file(self.user_id, old, new)

    def enroll(self, student_id: str, code: str, password: str) -> dict:
        """Generate the student's key pair locally; only the public key is sent."""
        key = rsa_generate(config.STUDENT_RSA_KEY_BITS)
        pub_pem = public_key_to_pem(key.public_key()).decode()
        proof = rsa_sign(key, canonical_json({"student_id": student_id, "public_key": pub_pem,
                                              "purpose": "enroll"}))
        resp = self.call("ENROLL", student_id=student_id, enrollment_code=code, password=password,
                         public_key=pub_pem, proof=b64e(proof))
        save_key_file(student_id, key, password)
        return resp

    # --- student --------------------------------------------------------------

    def list_exams(self) -> list[dict]:
        return self.call("LIST_EXAMS")["exams"]

    def get_exam(self, exam_id: str) -> dict:
        paper = self.verify_signed(self.call("GET_EXAM", exam_id=exam_id)["paper"])
        if paper["issued_to"] != self.user_id:
            raise IntegrityError("paper was issued to a different student")
        if paper["exam"]["exam_id"] != exam_id:
            raise IntegrityError("server returned a different exam")
        if paper["exam_hash"] != sha256_hex(canonical_json(paper["exam"])):
            raise IntegrityError("exam hash mismatch")
        self.papers[exam_id] = paper
        return paper

    def build_submission(self, exam_id: str, answers: dict) -> dict:
        paper = self.papers[exam_id]
        return {"student_id": self.user_id, "exam_id": exam_id, "exam_hash": paper["exam_hash"],
                "answers": answers, "submitted_at": int(time.time()),
                "nonce": b64e(os.urandom(16))}

    def submit(self, exam_id: str, answers: dict, private_key) -> dict:
        submission = self.build_submission(exam_id, answers)
        signature = rsa_sign(private_key, canonical_json(submission))
        resp = self.call("SUBMIT", submission=submission, signature=b64e(signature))
        receipt = self.verify_signed(resp["receipt"])
        if receipt["submission_hash"] != sha256_hex(canonical_json(submission)):
            raise IntegrityError("receipt does not match what we submitted")
        return {"receipt": receipt, "signed_receipt": resp["receipt"],
                "submission": submission, "signature": b64e(signature)}

    def get_result(self, exam_id: str) -> dict:
        result = self.verify_signed(self.call("GET_RESULT", exam_id=exam_id)["result"])
        if result["student_id"] != self.user_id or result["exam_id"] != exam_id:
            raise IntegrityError("result is for a different student or exam")
        return result

    # --- examiner -------------------------------------------------------------

    def admin_action(self, op: str, params: dict, admin_key) -> dict:
        """Sign a state-changing examiner action with the examiner's RSA key."""
        action = {"op": op, "params": params, "admin_id": self.user_id,
                  "ts": int(time.time()), "nonce": b64e(os.urandom(16))}
        return self.call("ADMIN_ACTION", action=action,
                         signature=b64e(rsa_sign(admin_key, canonical_json(action))))


# --- Local key store -----------------------------------------------------------

def key_path(user_id: str) -> Path:
    return config.CLIENT_DIR / f"{user_id}_key.pem"


def save_key_file(user_id: str, key, password: str) -> Path:
    path = key_path(user_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(private_key_to_pem(key, password.encode()))
    path.chmod(0o600)
    return path


def load_key_file(user_id: str, password: str):
    path = key_path(user_id)
    if not path.exists():
        raise FileNotFoundError(f"no key file for {user_id} at {path}")
    return load_private_key(path.read_bytes(), password.encode())


def rewrap_key_file(user_id: str, old: str, new: str) -> None:
    if key_path(user_id).exists():
        save_key_file(user_id, load_key_file(user_id, old), new)


# Backwards-compatible name used by earlier scripts.
load_student_key = load_key_file


def verify_receipt_file(path: str, server_pub=config.SERVER_SIGN_PUB) -> dict:
    """Offline check of a saved receipt: proves the server acknowledged this exact submission."""
    saved = json.loads(Path(path).read_text())
    signed = saved["signed_receipt"]
    rsa_verify(load_public_key(Path(server_pub).read_bytes()), b64d(signed["signature"]),
               canonical_json(signed["body"]))
    if signed["body"]["submission_hash"] != sha256_hex(canonical_json(saved["submission"])):
        raise IntegrityError("saved submission does not match the receipt")
    return signed["body"]


# --- Interactive student CLI ---------------------------------------------------

def _fmt_time(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def _show_exams(client: ExamClient) -> list[dict]:
    exams = client.list_exams()
    if not exams:
        print("  No exams available.")
    for e in exams:
        extra = "  [result available]" if e["result_available"] else ""
        print(f"  {e['exam_id']:<22} {e['state']:<12} {e['title']}  "
              f"({e['duration_minutes']} min, {_fmt_time(e['opens_at'])} -> "
              f"{_fmt_time(e['closes_at'])}){extra}")
    return exams


def _take_exam(client: ExamClient, key) -> None:
    exams = [e for e in _show_exams(client) if e["state"] in ("open", "in_progress")]
    if not exams:
        print("  Nothing to sit right now.")
        return
    exam_id = input("Exam ID to start: ").strip()
    if exam_id not in {e["exam_id"] for e in exams}:
        print("  Not an open exam.")
        return
    paper = client.get_exam(exam_id)
    exam = paper["exam"]
    print(f"\n[✓] Paper signature verified (SHA-256 {paper['exam_hash'][:16]}…)")
    print(f"\n=== {exam['title']} ===  ({exam['total_marks']} marks)")
    if exam["description"]:
        print(exam["description"])

    answers = {}
    for n, q in enumerate(exam["questions"], 1):
        remaining = paper["deadline"] - int(time.time())
        if remaining <= 0:
            print("\n[!] Time is up.")
            break
        print(f"\n[{remaining // 60}:{remaining % 60:02d} left]  Q{n} ({q['marks']} mark"
              f"{'s' if q['marks'] > 1 else ''}). {q['text']}")
        for letter, text in q["options"].items():
            print(f"     {letter}) {text}")
        while True:
            choice = input("   Answer (blank to skip): ").strip().upper()
            if choice == "" or choice in q["options"]:
                break
        if choice:
            answers[q["id"]] = choice

    print(f"\nYou answered {len(answers)}/{len(exam['questions'])} questions.")
    if input("Sign and submit? This cannot be undone [y/N]: ").strip().lower() != "y":
        print("Not submitted. You can resume until the deadline.")
        return
    out = client.submit(exam_id, answers, key)
    r = out["receipt"]
    receipt_path = config.CLIENT_DIR / f"{client.user_id}_{exam_id}_receipt.json"
    receipt_path.write_text(canonical_json(out).decode())
    print("\n[✓] Submission accepted. Server-signed receipt:")
    print(f"     submission SHA-256 : {r['submission_hash']}")
    print(f"     received at        : {time.ctime(r['received_at'])}")
    print(f"     saved to           : {receipt_path}")


def _view_result(client: ExamClient) -> None:
    exams = [e for e in _show_exams(client) if e["result_available"]]
    if not exams:
        print("  No results released yet.")
        return
    exam_id = input("Exam ID: ").strip()
    res = client.get_result(exam_id)
    print("\n[✓] Result signature verified")
    print(f"     {res['exam_id']}: {res['score']}/{res['total']} ({res['percentage']}%)")


def _change_password(client: ExamClient) -> None:
    old = getpass.getpass("Current password: ")
    new = getpass.getpass("New password: ")
    if new != getpass.getpass("Repeat new password: "):
        print("  Passwords do not match.")
        return
    client.change_password(old, new)
    print("[✓] Password changed; your local signing key was re-encrypted with it.")


def _interactive(args) -> None:
    student_id = input("Student ID: ").strip()
    password = getpass.getpass("Password: ")
    try:
        key = load_key_file(student_id, password)
    except (FileNotFoundError, ValueError, TypeError):
        raise SystemExit("Could not unlock your signing key (not enrolled on this device, "
                         "or wrong password).")

    with ExamClient(args.host, args.port, args.transport) as client:
        print(f"[✓] TLS 1.3 established over {args.transport}, server certificate verified")
        print("[✓] Server identity verified via RSA-PSS signed handshake")
        info = client.login(student_id, password)
        print(f"[✓] Logged in as {info['name']}")
        actions = {"1": lambda: _show_exams(client), "2": lambda: _take_exam(client, key),
                   "3": lambda: _view_result(client), "4": lambda: _change_password(client)}
        while True:
            print("\n1) List exams   2) Take exam   3) View result   4) Change password   5) Logout")
            choice = input("> ").strip()
            if choice == "5":
                client.logout()
                print("Logged out.")
                return
            if choice in actions:
                try:
                    actions[choice]()
                except ServerError as exc:
                    print(f"[!] Server refused: {exc}")
                except IntegrityError as exc:
                    print(f"[!] SECURITY ALERT: {exc}")
                    return


def _enroll(args) -> None:
    print("First-time enrollment. Your signing key is generated on this device and never "
          "leaves it.")
    student_id = input("Student ID: ").strip()
    code = input("Enrollment code (from your examiner): ").strip()
    password = getpass.getpass("Choose a password: ")
    if password != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match.")
    with ExamClient(args.host, args.port, args.transport) as client:
        client.enroll(student_id, code, password)
    print(f"[✓] Enrolled. Signing key saved to {key_path(student_id)} (encrypted with your password).")


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure online examination - student client")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--transport", choices=["socket", "https"], default="socket")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("enroll", help="activate your account with an enrollment code")
    vr = sub.add_parser("verify-receipt", help="verify a saved submission receipt offline")
    vr.add_argument("file")
    args = parser.parse_args()

    try:
        if args.command == "enroll":
            _enroll(args)
        elif args.command == "verify-receipt":
            r = verify_receipt_file(args.file)
            print(f"[✓] Receipt is authentic: server acknowledged {r['student_id']}'s submission "
                  f"for {r['exam_id']} at {time.ctime(r['received_at'])}")
        else:
            _interactive(args)
    except ServerError as exc:
        raise SystemExit(f"[!] {exc}")
    except IntegrityError as exc:
        raise SystemExit(f"[!] SECURITY ALERT / INVALID: {exc}")
    except (ConnectionError, OSError) as exc:
        raise SystemExit(f"[!] Connection problem: {exc}")


if __name__ == "__main__":
    main()
