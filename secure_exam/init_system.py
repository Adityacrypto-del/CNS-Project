"""One-time setup: create the PKI, server keys, encrypted databases and demo data.

    python -m secure_exam.init_system [--force] [--no-demo]
"""

import argparse
import shutil
import sys
import time

from . import config
from .crypto_utils import (hash_password, private_key_to_pem, public_key_to_pem, rsa_generate,
                           sha256_hex)
from .pki import cert_to_pem, create_ca, issue_server_cert
from .service import validate_exam
from .storage import AuditLog, EncryptedStore, create_wrapped_key

ADMIN = ("examiner", "Dr. Meera Nair", "Secure#Exam2026")

DEMO_STUDENTS = [
    # (student_id, name, email, password) - already enrolled
    ("S1001", "Alice Kumar", "alice@university.edu", "Alice@Exam2026"),
    ("S1002", "Bala Raman", "bala@university.edu", "Bala@Exam2026"),
    ("S1003", "Chitra Iyer", "chitra@university.edu", "Chitra@Exam2026"),
]
# Registered by the examiner but not yet enrolled: activates with the printed code.
PENDING_STUDENT = ("S1004", "Dev Patel", "dev@university.edu")
PENDING_CODE = "DEMO-ENRL-CODE-2026"

EXAM_ID = "CNS-MIDTERM-2026"
QUESTIONS = [
    {"id": "Q1", "text": "Which AES key size is used in this system?",
     "options": {"A": "128-bit", "B": "192-bit", "C": "256-bit", "D": "512-bit"}},
    {"id": "Q2", "text": "RSA-OAEP is primarily used for:",
     "options": {"A": "Hashing", "B": "Key encryption / wrapping",
                 "C": "Compression", "D": "Random number generation"}},
    {"id": "Q3", "text": "What is the output length of SHA-256?",
     "options": {"A": "128 bits", "B": "160 bits", "C": "256 bits", "D": "512 bits"}},
    {"id": "Q4", "text": "Which property does a digital signature provide that an HMAC does not?",
     "options": {"A": "Confidentiality", "B": "Integrity",
                 "C": "Non-repudiation", "D": "Compression"}, "marks": 2},
    {"id": "Q5", "text": "A replay attack is best prevented by:",
     "options": {"A": "Longer passwords", "B": "Nonces / sequence numbers and timestamps",
                 "C": "Larger RSA keys", "D": "Using MD5"}, "marks": 2},
    {"id": "Q6", "text": "Which TLS version removed RSA key transport and mandates forward secrecy?",
     "options": {"A": "SSL 3.0", "B": "TLS 1.0", "C": "TLS 1.2", "D": "TLS 1.3"}},
]
ANSWER_KEY = {"Q1": "C", "Q2": "B", "Q3": "C", "Q4": "C", "Q5": "B", "Q6": "D"}

QUIZ_QUESTIONS = [
    {"id": "Q1", "text": "Which mode provides authenticated encryption?",
     "options": {"A": "ECB", "B": "CBC", "C": "GCM", "D": "CTR"}},
    {"id": "Q2", "text": "PBKDF2 slows down attackers by:",
     "options": {"A": "Using many iterations", "B": "Encrypting the password",
                 "C": "Compressing the hash", "D": "Using RSA"}},
    {"id": "Q3", "text": "HKDF is used to:",
     "options": {"A": "Sign messages", "B": "Derive keys from a secret",
                 "C": "Encrypt files", "D": "Exchange certificates"}},
]
QUIZ_KEY = {"Q1": "C", "Q2": "A", "Q3": "B"}


def demo_exams(now: int) -> list[tuple[dict, dict, str]]:
    """(exam definition, answer key, status) for the demo."""
    day = 24 * 3600
    return [
        ({"exam_id": EXAM_ID, "title": "Cryptography & Network Security - Mid-Term",
          "description": "Answer all questions. Q4 and Q5 carry 2 marks.",
          "duration_minutes": 30, "opens_at": now - 3600, "closes_at": now + 7 * day,
          "questions": QUESTIONS}, ANSWER_KEY, "published"),
        ({"exam_id": "CNS-QUIZ-1", "title": "Quiz 1 - Symmetric crypto & KDFs",
          "description": "Short quiz.", "duration_minutes": 10,
          "opens_at": now - 3600, "closes_at": now + 7 * day,
          "questions": QUIZ_QUESTIONS}, QUIZ_KEY, "published"),
        ({"exam_id": "CNS-FINAL-2026", "title": "Cryptography & Network Security - Final",
          "description": "Draft - not yet visible to students.", "duration_minutes": 90,
          "opens_at": now + 30 * day, "closes_at": now + 30 * day + 3 * 3600,
          "questions": QUESTIONS}, ANSWER_KEY, "draft"),
    ]


def initialise(force: bool = False, quiet: bool = False, demo: bool = True) -> None:
    say = (lambda *a: None) if quiet else print

    if config.SERVER_DIR.exists() or config.PKI_DIR.exists():
        if not force:
            sys.exit(f"{config.DATA_DIR} already initialised; use --force to recreate.")
        for d in (config.PKI_DIR, config.SERVER_DIR, config.CLIENT_DIR):
            shutil.rmtree(d, ignore_errors=True)
    for d in (config.PKI_DIR, config.SERVER_DIR, config.CLIENT_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # 1. PKI: root CA + TLS server certificate.
    say("[+] Creating root CA and TLS server certificate")
    ca_key, ca_cert = create_ca()
    config.CA_KEY.write_bytes(private_key_to_pem(ca_key))
    config.CA_CERT.write_bytes(cert_to_pem(ca_cert))
    tls_key, tls_cert = issue_server_cert(ca_key, ca_cert, config.SERVER_HOSTNAME)
    config.SERVER_TLS_KEY.write_bytes(private_key_to_pem(tls_key))
    config.SERVER_TLS_CERT.write_bytes(cert_to_pem(tls_cert))

    # 2. Server application key: signs papers/receipts/results, unwraps session keys.
    say("[+] Creating server RSA-3072 signing / key-exchange key pair")
    server_key = rsa_generate()
    config.SERVER_SIGN_KEY.write_bytes(private_key_to_pem(server_key))
    config.SERVER_SIGN_PUB.write_bytes(public_key_to_pem(server_key.public_key()))
    for p in (config.CA_KEY, config.SERVER_TLS_KEY, config.SERVER_SIGN_KEY):
        p.chmod(0o600)

    # 3. Storage + audit keys (AES-256 / HMAC), RSA-OAEP wrapped.
    say("[+] Creating AES-256 storage key and audit HMAC key (RSA-OAEP wrapped)")
    storage_key = create_wrapped_key(server_key.public_key(), config.STORAGE_KEY_WRAPPED)
    audit_key = create_wrapped_key(server_key.public_key(), config.AUDIT_KEY_WRAPPED)
    store = lambda path: EncryptedStore(path, storage_key)  # noqa: E731

    # 4. Examiner account: password + RSA key for signing administrative actions.
    admin_id, admin_name, admin_pw = ADMIN
    say(f"[+] Creating examiner account '{admin_id}'")
    admin_key = rsa_generate(config.STUDENT_RSA_KEY_BITS)
    (config.CLIENT_DIR / f"{admin_id}_key.pem").write_bytes(
        private_key_to_pem(admin_key, admin_pw.encode()))
    store(config.ADMINS_DB).save({admin_id: {
        "name": admin_name, "password": hash_password(admin_pw),
        "public_key": public_key_to_pem(admin_key.public_key()).decode()}})

    students, exams, keys, subs = {}, {}, {}, {}
    now = int(time.time())
    if demo:
        for sid, name, email, password in DEMO_STUDENTS:
            say(f"[+] Enrolling demo student {sid} ({name})")
            key = rsa_generate(config.STUDENT_RSA_KEY_BITS)
            # The private key lives only on the client, encrypted with the student's password.
            (config.CLIENT_DIR / f"{sid}_key.pem").write_bytes(
                private_key_to_pem(key, password.encode()))
            students[sid] = {"name": name, "email": email, "status": "active",
                             "password": hash_password(password),
                             "public_key": public_key_to_pem(key.public_key()).decode(),
                             "enrollment": None, "created_at": now, "enrolled_at": now}
        sid, name, email = PENDING_STUDENT
        say(f"[+] Registering pending student {sid} ({name})")
        students[sid] = {"name": name, "email": email, "status": "pending", "password": None,
                         "public_key": None, "created_at": now,
                         "enrollment": {"code_hash": sha256_hex(PENDING_CODE.encode()),
                                        "expires_at": now + config.ENROLLMENT_CODE_TTL}}

        for definition, answer_key, status in demo_exams(now):
            say(f"[+] Creating exam {definition['exam_id']} ({status})")
            exam = validate_exam(definition, answer_key)
            exam.update(status=status, results_released=False, created_by=admin_id,
                        created_at=now, **({"published_at": now} if status == "published" else {}))
            exams[exam["exam_id"]] = exam
            keys[exam["exam_id"]] = answer_key

    for path, data in ((config.STUDENTS_DB, students), (config.EXAMS_DB, exams),
                       (config.ANSWER_KEYS_DB, keys), (config.SUBMISSIONS_DB, subs)):
        store(path).save(data)
    AuditLog(config.AUDIT_LOG, audit_key).record("SYSTEM_INITIALISED", students=len(students),
                                                 exams=sorted(exams))
    say(f"[+] Done. Data written to {config.DATA_DIR}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="wipe and recreate all data")
    parser.add_argument("--no-demo", action="store_true",
                        help="only create keys and the examiner account")
    args = parser.parse_args()
    initialise(force=args.force, demo=not args.no_demo)
    print(f"\nExaminer:  {ADMIN[0]:<8} password: {ADMIN[2]}")
    if not args.no_demo:
        print("Students:")
        for sid, name, _, password in DEMO_STUDENTS:
            print(f"  {sid}  {name:<14} password: {password}")
        print(f"  {PENDING_STUDENT[0]}  {PENDING_STUDENT[1]:<14} not enrolled - enrollment code: "
              f"{PENDING_CODE}")


if __name__ == "__main__":
    main()
