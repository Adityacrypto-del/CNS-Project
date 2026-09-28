"""Security evaluation (Objective 8).

    python -m secure_exam.evaluate

Verifies every primitive against published test vectors and security properties,
inspects the negotiated TLS parameters, scans stored files for plaintext leaks,
benchmarks the mechanisms, runs the full attack suite, and writes a Markdown report
to reports/security_evaluation.md.
"""

import http.client
import json
import os
import socket
import statistics
import sys
import time

from . import config
from .admin import AdminCommands
from .api import SECURITY_HEADERS
from .attacks import (PASSWORDS, Sandbox, print_results, run_all, run_in_sandbox, start_sandbox)
from .client import ExamClient, client_tls_context, load_key_file
from .crypto_utils import (IntegrityError, aes_cbc_decrypt, aes_cbc_encrypt, aes_gcm_decrypt,
                           aes_gcm_encrypt, b64d, canonical_json, hash_password, hkdf, hmac_sha256,
                           load_public_key, rsa_decrypt, rsa_encrypt, rsa_generate, rsa_sign,
                           rsa_verify, sha256, sha256_hex, verify_password)

REPORT = config.ROOT / "reports" / "security_evaluation.md"


def _raises(fn, exc=Exception) -> bool:
    try:
        fn()
    except exc:
        return True
    return False


def _bit_diff(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _timeit(fn, n: int) -> float:
    """Median seconds per call."""
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t)
    return statistics.median(samples)


def primitive_checks() -> list[tuple[str, str, bool]]:
    k = os.urandom(32)
    msg = b"Q1=C;Q2=B;Q3=C;student=S1001"
    rsa_key = rsa_generate(2048)
    checks = []

    def add(objective, name, ok):
        checks.append((objective, name, bool(ok)))

    # SHA-256 / HMAC known-answer tests (FIPS 180-2, RFC 4231 test case 1).
    add("Integrity", "SHA-256 KAT: SHA256('abc')",
        sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    add("Integrity", "HMAC-SHA256 KAT: RFC 4231 case 1",
        hmac_sha256(b"\x0b" * 20, b"Hi There").hex()
        == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    add("Key management", "HKDF-SHA256 KAT: RFC 5869 case 1",
        hkdf(b"\x0b" * 22, salt=bytes(range(13)), info=bytes(range(0xf0, 0xfa)), length=42).hex()
        == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    avalanche = statistics.mean(
        _bit_diff(sha256(m), sha256(bytes([m[0] ^ 1]) + m[1:]))
        for m in (os.urandom(64) for _ in range(200))) / 256
    add("Integrity", f"SHA-256 avalanche: 1-bit input change flips {avalanche:.1%} of output bits",
        0.45 < avalanche < 0.55)
    add("Integrity", "HMAC differs under a different key",
        hmac_sha256(k, msg) != hmac_sha256(os.urandom(32), msg))

    # AES.
    iv, ct = aes_cbc_encrypt(k, msg)
    add("Confidentiality", "AES-256-CBC encrypt/decrypt round-trip", aes_cbc_decrypt(k, iv, ct) == msg)
    add("Confidentiality", "AES-256-CBC randomised IV: same plaintext -> different ciphertext",
        aes_cbc_encrypt(k, msg)[1] != ct)
    add("Confidentiality", "AES-256-CBC ciphertext does not contain plaintext", msg not in ct)
    try:
        wrong_key_ok = aes_cbc_decrypt(os.urandom(32), iv, ct) != msg
    except ValueError:                                        # bad padding
        wrong_key_ok = True
    add("Confidentiality", "AES-256-CBC wrong key does not recover plaintext", wrong_key_ok)
    blob = aes_gcm_encrypt(k, msg, b"aad")
    add("Confidentiality", "AES-256-GCM encrypt/decrypt round-trip", aes_gcm_decrypt(k, blob, b"aad") == msg)
    add("Integrity", "AES-256-GCM rejects wrong key",
        _raises(lambda: aes_gcm_decrypt(os.urandom(32), blob, b"aad"), IntegrityError))
    add("Integrity", "AES-256-GCM rejects modified ciphertext",
        _raises(lambda: aes_gcm_decrypt(k, blob[:-1] + bytes([blob[-1] ^ 1]), b"aad"), IntegrityError))
    add("Integrity", "AES-256-GCM rejects wrong associated data (file swap)",
        _raises(lambda: aes_gcm_decrypt(k, blob, b"other"), IntegrityError))

    # RSA.
    wrapped = rsa_encrypt(rsa_key.public_key(), k)
    add("Key management", "RSA-OAEP wrap/unwrap of AES key", rsa_decrypt(rsa_key, wrapped) == k)
    add("Key management", "RSA-OAEP is randomised", rsa_encrypt(rsa_key.public_key(), k) != wrapped)
    add("Key management", "RSA-OAEP unwrap fails with a different private key",
        _raises(lambda: rsa_decrypt(rsa_generate(2048), wrapped)))
    sig = rsa_sign(rsa_key, msg)
    add("Non-repudiation", "RSA-PSS signature verifies",
        not _raises(lambda: rsa_verify(rsa_key.public_key(), sig, msg)))
    add("Non-repudiation", "RSA-PSS rejects modified message",
        _raises(lambda: rsa_verify(rsa_key.public_key(), sig, msg + b"!"), IntegrityError))
    add("Non-repudiation", "RSA-PSS rejects signature from another key",
        _raises(lambda: rsa_verify(rsa_generate(2048).public_key(), sig, msg), IntegrityError))

    # Passwords.
    rec = hash_password("Correct#Horse")
    add("Authentication", "PBKDF2 accepts correct password", verify_password("Correct#Horse", rec))
    add("Authentication", "PBKDF2 rejects wrong password", not verify_password("correct#horse", rec))
    add("Authentication", "PBKDF2 salts are unique (same password -> different hash)",
        hash_password("Correct#Horse")["hash"] != rec["hash"])
    return checks


def tls_inspection(sb: Sandbox) -> dict:
    with sb.client() as c:
        cert = c.sock.getpeercert()
        return {"version": c.sock.version(), "cipher": c.sock.cipher()[0],
                "cipher_bits": c.sock.cipher()[2],
                "server_cert_subject": dict(x[0] for x in cert["subject"]),
                "hostname_verified": True}


def _api_get(sb: Sandbox, path: str, origin: str | None = None) -> http.client.HTTPResponse:
    ctx = client_tls_context()
    conn = http.client.HTTPSConnection(config.SERVER_HOSTNAME, sb.api_port, timeout=10, context=ctx)
    conn.sock = ctx.wrap_socket(socket.create_connection((config.HOST, sb.api_port), 10),
                                server_hostname=config.SERVER_HOSTNAME)
    conn.request("GET", path, headers={"Origin": origin} if origin else {})
    resp = conn.getresponse()
    resp.body = resp.read()
    conn.close()
    return resp


def api_checks(sb: Sandbox) -> list[tuple[str, bool]]:
    """HTTP-level hardening of the HTTPS API used by web frontends."""
    checks = []
    resp = _api_get(sb, "/api/v1/info")
    info = json.loads(resp.body)
    for name, value in SECURITY_HEADERS.items():
        checks.append((f"Header {name}: {value}", resp.getheader(name) == value))
    pinned = config.SERVER_SIGN_PUB.read_bytes().decode()
    checks.append(("/info publishes the same server signing key clients pin",
                   info["server_public_key"] == pinned))
    good = _api_get(sb, "/api/v1/health", origin=config.API_ALLOWED_ORIGIN)
    checks.append((f"CORS allows configured origin {config.API_ALLOWED_ORIGIN}",
                   good.getheader("Access-Control-Allow-Origin") == config.API_ALLOWED_ORIGIN))
    evil = _api_get(sb, "/api/v1/health", origin="https://evil.example")
    checks.append(("CORS refuses other origins (no Access-Control-Allow-Origin)",
                   evil.getheader("Access-Control-Allow-Origin") is None))
    checks.append(("Server header does not leak Python version",
                   "Python" not in (good.getheader("Server") or "")))
    checks.append(("Unknown route returns 404", _api_get(sb, "/api/v1/admin").status == 404))
    return checks


def at_rest_scan() -> list[tuple[str, bool]]:
    """Look for sensitive plaintext in every server-side file."""
    secrets = [b"Alice", b"alice@university.edu", b"CNS-MIDTERM", b"Meera",
               b"RSA-OAEP is primarily used", b'"Q1"', b"Secure#Exam2026"]
    secrets += [pw.encode() for pw in PASSWORDS.values()]
    results = []
    for path in sorted(config.SERVER_DIR.glob("*.enc")):
        data = path.read_bytes()
        results.append((path.name, not any(s in data for s in secrets)))
    audit = config.AUDIT_LOG.read_bytes()
    results.append(("audit.log (no passwords)",
                    not any(pw.encode() in audit for pw in [*PASSWORDS.values(), "Secure#Exam2026"])))
    for path in sorted(config.SERVER_DIR.glob("*_key.bin")):
        results.append((f"{path.name} (RSA-OAEP wrapped, 384 bytes)", len(path.read_bytes()) == 384))
    # Every private key held by a user must be encrypted (PKCS#8 with their password).
    for path in sorted(config.CLIENT_DIR.glob("*_key.pem")):
        results.append((f"clients/{path.name}", b"ENCRYPTED PRIVATE KEY" in path.read_bytes()))
    return results


def benchmarks(sb: Sandbox) -> list[tuple[str, str]]:
    k = os.urandom(32)
    mb = os.urandom(1 << 20)
    rsa3072 = rsa_generate(3072)
    rec = hash_password("x")
    rows = []
    t = _timeit(lambda: aes_cbc_encrypt(k, mb), 20)
    rows.append(("AES-256-CBC encrypt (1 MiB)", f"{t*1e3:.2f} ms  ({1/t:.0f} MiB/s)"))
    t = _timeit(lambda: aes_gcm_encrypt(k, mb), 20)
    rows.append(("AES-256-GCM encrypt (1 MiB)", f"{t*1e3:.2f} ms  ({1/t:.0f} MiB/s)"))
    t = _timeit(lambda: sha256(mb), 20)
    rows.append(("SHA-256 (1 MiB)", f"{t*1e3:.2f} ms"))
    t = _timeit(lambda: hmac_sha256(k, mb), 20)
    rows.append(("HMAC-SHA256 (1 MiB)", f"{t*1e3:.2f} ms"))
    t = _timeit(lambda: rsa_sign(rsa3072, b"x"), 20)
    rows.append(("RSA-3072 PSS sign", f"{t*1e3:.2f} ms"))
    sig = rsa_sign(rsa3072, b"x")
    t = _timeit(lambda: rsa_verify(rsa3072.public_key(), sig, b"x"), 50)
    rows.append(("RSA-3072 PSS verify", f"{t*1e3:.3f} ms"))
    wrapped = rsa_encrypt(rsa3072.public_key(), k)
    t = _timeit(lambda: rsa_decrypt(rsa3072, wrapped), 20)
    rows.append(("RSA-3072 OAEP unwrap", f"{t*1e3:.2f} ms"))
    t = _timeit(lambda: rsa_generate(2048), 3)
    rows.append(("RSA-2048 key generation (student enrollment)", f"{t*1e3:.0f} ms"))
    t = _timeit(lambda: verify_password("x", rec), 3)
    rows.append((f"PBKDF2-SHA256 ({config.PBKDF2_ITERATIONS:,} iter)",
                 f"{t*1e3:.0f} ms  (~{1/t:.1f} guesses/s per core for an attacker)"))

    for transport in ("socket", "https"):
        t = _timeit(lambda: sb.client(transport).close(), 10)
        rows.append((f"TLS 1.3 + RSA handshake ({transport})", f"{t*1e3:.1f} ms"))

        def full_flow():
            with sb.student("S1003", transport) as c:
                c.get_exam("CNS-MIDTERM-2026")
        t = _timeit(full_flow, 3)
        rows.append((f"Connect + login + fetch & verify paper ({transport})", f"{t*1e3:.0f} ms"))
    return rows


def end_to_end(sb: Sandbox, transport: str) -> list[tuple[str, bool]]:
    """Complete exam lifecycle, every step over `transport`."""
    steps = []
    tag = transport.upper()
    exam_id, sid, password = f"E2E-{tag}", f"E2E-{tag}-STUDENT", "Fresh#Student2026"
    now = int(time.time())
    exam = {"exam_id": exam_id, "title": f"End-to-end exam ({transport})", "duration_minutes": 15,
            "opens_at": now - 60, "closes_at": now + 3600,
            "questions": [{"id": "Q1", "text": "AES block size?", "options": {"A": "64", "B": "128"}},
                          {"id": "Q2", "text": "SHA-256 output?", "options": {"A": "256", "B": "512"},
                           "marks": 3},
                          {"id": "Q3", "text": "RSA-PSS provides?",
                           "options": {"A": "Signatures", "B": "Encryption"}}]}
    key = {"Q1": "B", "Q2": "A", "Q3": "A"}

    with sb.admin(transport) as a:
        steps.append((f"[{transport}] Examiner authenticated over TLS 1.3 + signed handshake", True))
        a.admin_action("CREATE_EXAM", {"exam": exam, "answer_key": key}, sb.admin_key)
        a.admin_action("PUBLISH_EXAM", {"exam_id": exam_id}, sb.admin_key)
        steps.append((f"[{transport}] Exam created and published via RSA-signed examiner actions", True))
        code = a.admin_action("ADD_STUDENT", {"student_id": sid, "name": "E2E Student"},
                              sb.admin_key)["enrollment_code"]
        steps.append((f"[{transport}] Student registered, one-time enrollment code issued", True))

    with sb.client(transport) as c:
        c.enroll(sid, code, password)
    steps.append((f"[{transport}] Student enrolled: key pair generated client-side, "
                  "proof-of-possession accepted", True))

    with sb.student(sid, transport, password) as c:
        paper = c.get_exam(exam_id)
        steps.append((f"[{transport}] Paper received; server signature + SHA-256 hash verified", True))
        answers = {"Q1": "B", "Q2": "A", "Q3": "B"}                  # 1 + 3 + 0 = 4 / 5
        out = c.submit(exam_id, answers, load_key_file(sid, password))
        steps.append((f"[{transport}] Answers RSA-PSS signed and submitted; receipt verified",
                      out["receipt"]["exam_hash"] == paper["exam_hash"]))
        try:
            c.get_result(exam_id)
            withheld = False
        except Exception:
            withheld = True
        steps.append((f"[{transport}] Result withheld until the examiner releases it", withheld))

    with sb.admin(transport) as a:
        cmds = AdminCommands(a, sb.admin_key)
        rec = a.call("ADMIN_GET_SUBMISSION", exam_id=exam_id, student_id=sid)
        sub = rec["record"]["submission"]
        try:
            rsa_verify(load_public_key(rec["student_public_key"].encode()),
                       b64d(rec["record"]["signature"]), canonical_json(sub))
            sig_ok = sha256_hex(canonical_json(sub)) == rec["record"]["submission_hash"]
        except IntegrityError:
            sig_ok = False
        steps.append((f"[{transport}] Examiner independently verified the student's signature", sig_ok))
        cmds.act("CLOSE_EXAM", exam_id=exam_id)
        cmds.act("RELEASE_RESULTS", exam_id=exam_id)
        export = a.verify_signed(cmds.act("EXPORT_RESULTS", exam_id=exam_id)["export"])
        steps.append((f"[{transport}] Exam closed, results released, signed export verified",
                      [r["score"] for r in export["results"]] == [4]))

    with sb.student(sid, transport, password) as c:
        result = c.get_result(exam_id)
    steps.append((f"[{transport}] Signed result verified: {result['score']}/{result['total']} "
                  "(marks-weighted)", (result["score"], result["total"]) == (4, 5)))
    return steps


def write_report(checks, tls, api, scan, bench, flow, attacks, audit_entries) -> None:
    REPORT.parent.mkdir(exist_ok=True)
    tick = lambda ok: "✅" if ok else "❌"
    lines = ["# Security Evaluation Report", "",
             f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} by `python -m secure_exam.evaluate` "
             "against a fresh sandbox (new keys and databases).", "",
             "## 1. End-to-end examination flow", "", "| Step | Result |", "|---|---|"]
    lines += [f"| {s} | {tick(ok)} |" for s, ok in flow]
    lines += ["", "## 2. Cryptographic primitive verification", "",
              "| Objective | Check | Result |", "|---|---|---|"]
    lines += [f"| {o} | {n} | {tick(ok)} |" for o, n, ok in checks]
    lines += ["", "## 3. Secure communication (TLS)", "",
              f"- Negotiated protocol: **{tls['version']}**",
              f"- Cipher suite: **{tls['cipher']}** ({tls['cipher_bits']}-bit)",
              f"- Server certificate subject: `{tls['server_cert_subject']}`",
              "- Certificate chain verified against the private CA; hostname checked against SAN",
              "- TLS 1.2 and plaintext connections refused on both transports (see section 6)",
              "", "## 4. HTTPS API hardening", "", "| Check | Result |", "|---|---|"]
    lines += [f"| {n} | {tick(ok)} |" for n, ok in api]
    lines += ["", "## 5. Confidentiality at rest", "",
              "Each stored file was scanned for known plaintext (names, e-mails, passwords, "
              "question text, exam ID).", "", "| File | No plaintext found / encrypted | ",
              "|---|---|"]
    lines += [f"| `{f}` | {tick(ok)} |" for f, ok in scan]
    lines += ["", f"Audit log: {audit_entries} hash-chained, HMAC-protected entries verified.",
              "", "## 6. Attack detection", "", "| Category | Attack | Outcome | Evidence |",
              "|---|---|---|---|"]
    lines += [f"| {r.category} | {r.name} | {'Blocked ✅' if r.blocked else 'NOT blocked ❌'} "
              f"| {r.detail.replace('|', '/')} |" for r in attacks]
    lines += ["", "## 7. Performance", "", "| Operation | Median time |", "|---|---|"]
    lines += [f"| {n} | {v} |" for n, v in bench]
    total = len(checks) + len(api) + len(scan) + len(attacks) + len(flow)
    passed = (sum(ok for *_, ok in checks) + sum(ok for _, ok in api) + sum(ok for _, ok in scan)
              + sum(r.blocked for r in attacks) + sum(ok for _, ok in flow))
    lines += ["", "## Summary", "", f"**{passed}/{total} checks passed.**", ""]
    REPORT.write_text("\n".join(lines))


def main() -> None:
    run_in_sandbox("secure_exam.evaluate")
    print("[*] Setting up sandbox (socket server + HTTPS API)…")
    sb = start_sandbox()
    try:
        # Attack scenarios rely on the demo students' initial state, so run them first.
        attacks = run_all(sb)

        print("\n== End-to-end exam lifecycle ==")
        flow = end_to_end(sb, "socket") + end_to_end(sb, "https")
        for s, ok in flow:
            print(f"  {'✓' if ok else '✗'} {s}")

        print("\n== Cryptographic primitives ==")
        checks = primitive_checks()
        for o, n, ok in checks:
            print(f"  {'✓' if ok else '✗'} [{o}] {n}")

        print("\n== TLS ==")
        tls = tls_inspection(sb)
        print(f"  {tls['version']}  {tls['cipher']}  ({tls['cipher_bits']}-bit)")

        print("\n== HTTPS API hardening ==")
        api = api_checks(sb)
        for n, ok in api:
            print(f"  {'✓' if ok else '✗'} {n}")

        print("\n== Data at rest ==")
        scan = at_rest_scan()
        for f, ok in scan:
            print(f"  {'✓' if ok else '✗'} {f}")

        print("\n== Attack simulations ==")
        print_results(attacks)
        audit_entries = sb.service.audit.verify()
        print(f"  Audit log verified: {audit_entries} entries")

        print("\n== Benchmarks ==")
        bench = benchmarks(sb)
        for n, v in bench:
            print(f"  {n:<48} {v}")
    finally:
        sb.stop()

    write_report(checks, tls, api, scan, bench, flow, attacks, audit_entries)
    print(f"\n[+] Report written to {REPORT}")
    ok = (all(ok for *_, ok in checks) and all(ok for _, ok in api) and all(ok for _, ok in scan)
          and all(r.blocked for r in attacks) and all(ok for _, ok in flow))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
