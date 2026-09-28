"""Test-suite: python -W error::ResourceWarning -m unittest discover -s tests -t . -v"""

import json
import os
import shutil
import tempfile
import time
import unittest

# Point the system at a throw-away data directory *before* importing it.
_TMP = tempfile.mkdtemp(prefix="secure-exam-test-")
os.environ["SECURE_EXAM_DATA"] = _TMP

from secure_exam import attacks, config  # noqa: E402
from secure_exam.admin import parse_time, verify_export  # noqa: E402
from secure_exam.client import ServerError, load_key_file, verify_receipt_file  # noqa: E402
from secure_exam.crypto_utils import (IntegrityError, aes_cbc_decrypt, aes_cbc_encrypt,  # noqa: E402
                                      aes_gcm_decrypt, aes_gcm_encrypt, canonical_json, hkdf,
                                      hmac_sha256, sha256)
from secure_exam.protocol import ReplayError, SecureChannel  # noqa: E402
from secure_exam.service import ServiceError, check_password_policy, validate_exam  # noqa: E402
from secure_exam.storage import AuditLog  # noqa: E402

SB: attacks.Sandbox


def setUpModule():
    global SB
    SB = attacks.start_sandbox()


def tearDownModule():
    SB.stop()
    shutil.rmtree(_TMP, ignore_errors=True)


def _exam(exam_id: str, opens_offset: int = -60, closes_offset: int = 3600) -> tuple[dict, dict]:
    now = int(time.time())
    return ({"exam_id": exam_id, "title": "Test exam", "duration_minutes": 10,
             "opens_at": now + opens_offset, "closes_at": now + closes_offset,
             "questions": [{"id": "Q1", "text": "1+1?", "options": {"A": "2", "B": "3"}},
                           {"id": "Q2", "text": "2+2?", "options": {"A": "4", "B": "5"}, "marks": 2}]},
            {"Q1": "A", "Q2": "A"})


class TestPrimitives(unittest.TestCase):
    def test_sha256_kat(self):
        self.assertEqual(sha256(b"abc").hex(),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_hmac_kat(self):
        self.assertEqual(hmac_sha256(b"\x0b" * 20, b"Hi There").hex(),
                         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

    def test_hkdf_kat(self):
        self.assertEqual(
            hkdf(b"\x0b" * 22, salt=bytes(range(13)), info=bytes(range(0xf0, 0xfa)), length=42).hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_aes_cbc_roundtrip(self):
        k = os.urandom(32)
        iv, ct = aes_cbc_encrypt(k, b"secret answers")
        self.assertEqual(aes_cbc_decrypt(k, iv, ct), b"secret answers")

    def test_aes_gcm_detects_tampering(self):
        k = os.urandom(32)
        blob = bytearray(aes_gcm_encrypt(k, b"exam"))
        blob[-1] ^= 1
        with self.assertRaises(IntegrityError):
            aes_gcm_decrypt(k, bytes(blob))


class TestSecureChannel(unittest.TestCase):
    def setUp(self):
        k_enc, k_mac = os.urandom(32), os.urandom(32)
        self.client = SecureChannel(None, k_enc, k_mac, is_server=False)
        self.server = SecureChannel(None, k_enc, k_mac, is_server=True)

    def test_roundtrip(self):
        self.assertEqual(self.server.open(self.client.seal({"a": 1})), {"a": 1})

    def test_replay_rejected(self):
        env = self.client.seal({"a": 1})
        self.server.open(env)
        with self.assertRaises(ReplayError):
            self.server.open(env)

    def test_reflection_rejected(self):
        # A server->client message cannot be reflected back to the server.
        env = self.server.seal({"a": 1})
        with self.assertRaises(IntegrityError):
            self.server.open(env)


class TestValidation(unittest.TestCase):
    def test_password_policy(self):
        for weak in ("short1A!", "alllowercaseletters", "S1001#Strong2026"):
            with self.assertRaises(ServiceError):
                check_password_policy(weak, "S1001")
        check_password_policy("Correct#Horse9", "S1001")

    def test_validate_exam(self):
        exam, key = _exam("VALID-1")
        self.assertEqual(validate_exam(exam, key)["questions"][1]["marks"], 2)
        bad_cases = [
            ({**exam, "exam_id": "bad id"}, key),
            ({**exam, "closes_at": exam["opens_at"]}, key),
            (exam, {"Q1": "A", "Q2": "Z"}),                       # answer not an option
            (exam, {"Q1": "A"}),                                 # missing answer
            ({**exam, "questions": exam["questions"] * 2}, key),  # duplicate ids
        ]
        for e, k in bad_cases:
            with self.assertRaises(ServiceError):
                validate_exam(e, k)

    def test_parse_time(self):
        self.assertEqual(parse_time("now", 1000), 1000)
        self.assertEqual(parse_time("+2d", 1000), 1000 + 2 * 86400)
        self.assertEqual(parse_time("+30m", 1000), 1000 + 1800)
        self.assertEqual(parse_time(1234), 1234)
        self.assertIsInstance(parse_time("2026-10-01T09:00"), int)

    def test_audit_log_detects_modification(self):
        path = config.DATA_DIR / "test_audit.log"
        log = AuditLog(path, os.urandom(32))
        for i in range(3):
            log.record("EVENT", i=i)
        self.assertEqual(log.verify(), 3)
        path.write_text(path.read_text().replace('"i": 1', '"i": 7'))
        with self.assertRaises(IntegrityError):
            log.verify()
        path.unlink()


class TestExamLifecycle(unittest.TestCase):
    """Order-independent: each test uses its own exam and student."""

    def _new_student(self, sid: str, transport: str = "socket", password: str = "Test#Student2026"):
        with SB.admin(transport) as a:
            code = a.admin_action("ADD_STUDENT", {"student_id": sid, "name": sid},
                                  SB.admin_key)["enrollment_code"]
        with SB.client(transport) as c:
            c.enroll(sid, code.lower(), password)             # codes are case-insensitive
        return password

    def _new_exam(self, exam_id: str, publish: bool = True, **kw):
        exam, key = _exam(exam_id, **kw)
        with SB.admin() as a:
            a.admin_action("CREATE_EXAM", {"exam": exam, "answer_key": key}, SB.admin_key)
            if publish:
                a.admin_action("PUBLISH_EXAM", {"exam_id": exam_id}, SB.admin_key)

    def _lifecycle(self, transport: str):
        exam_id, sid = f"LIFE-{transport.upper()}", f"T-{transport}"
        self._new_exam(exam_id)
        pw = self._new_student(sid, transport)
        with SB.student(sid, transport, pw) as c:
            listed = {e["exam_id"]: e for e in c.list_exams()}
            self.assertEqual(listed[exam_id]["state"], "open")
            paper = c.get_exam(exam_id)
            self.assertEqual(paper["exam"]["total_marks"], 3)
            out = c.submit(exam_id, {"Q1": "A", "Q2": "B"}, load_key_file(sid, pw))
            receipt_file = config.DATA_DIR / f"{sid}_receipt.json"
            receipt_file.write_text(canonical_json(out).decode())
            self.assertEqual(verify_receipt_file(receipt_file)["exam_id"], exam_id)
            self.assertEqual({e["exam_id"]: e for e in c.list_exams()}[exam_id]["state"], "submitted")
        with SB.admin(transport) as a:
            a.admin_action("RELEASE_RESULTS", {"exam_id": exam_id}, SB.admin_key)
            export = a.admin_action("EXPORT_RESULTS", {"exam_id": exam_id}, SB.admin_key)["export"]
        export_file = config.DATA_DIR / f"{exam_id}_export.json"
        export_file.write_text(json.dumps(export))
        self.assertEqual(verify_export(export_file)["results"][0]["student_id"], sid)
        export["body"]["results"][0]["score"] = 3                # doctor the exported grade
        export_file.write_text(json.dumps(export))
        with self.assertRaises(IntegrityError):
            verify_export(export_file)
        with SB.student(sid, transport, pw) as c:
            result = c.get_result(exam_id)
            self.assertEqual((result["score"], result["total"]), (1, 3))

    def test_lifecycle_socket(self):
        self._lifecycle("socket")

    def test_lifecycle_https(self):
        self._lifecycle("https")

    def test_question_order_is_per_student_but_stable(self):
        exam, key = _exam("ORDER-1")
        exam["questions"] = [{"id": f"Q{i}", "text": f"q{i}", "options": {"A": "a", "B": "b"}}
                             for i in range(12)]
        key = {f"Q{i}": "A" for i in range(12)}
        with SB.admin() as a:
            a.admin_action("CREATE_EXAM", {"exam": exam, "answer_key": key}, SB.admin_key)
            a.admin_action("PUBLISH_EXAM", {"exam_id": "ORDER-1"}, SB.admin_key)
        orders = []
        for sid in ("S1001", "S1002", "S1001"):
            with SB.student(sid) as c:
                orders.append([q["id"] for q in c.get_exam("ORDER-1")["exam"]["questions"]])
        self.assertEqual(orders[0], orders[2])
        self.assertNotEqual(orders[0], orders[1])

    def test_change_password_rewraps_key(self):
        old, new = self._new_student("T-pwchange"), "Changed#Pass2026"
        with SB.student("T-pwchange", password=old) as c:
            c.change_password(old, new)
        load_key_file("T-pwchange", new)
        with self.assertRaises((ValueError, TypeError)):
            load_key_file("T-pwchange", old)
        with SB.student("T-pwchange", password=new):
            pass

    def test_disabled_student_cannot_login(self):
        pw = self._new_student("T-disabled")
        with SB.admin() as a:
            a.admin_action("SET_STUDENT_STATUS", {"student_id": "T-disabled", "status": "disabled"},
                           SB.admin_key)
        with SB.client() as c, self.assertRaises(ServerError) as ctx:
            c.login("T-disabled", pw)
        self.assertEqual(ctx.exception.code, "ACCOUNT_INACTIVE")

    def test_reissue_revokes_old_credentials(self):
        pw = self._new_student("T-reissue")
        with SB.admin() as a:
            code = a.admin_action("REISSUE_ENROLLMENT", {"student_id": "T-reissue"},
                                  SB.admin_key)["enrollment_code"]
        with SB.client() as c, self.assertRaises(ServerError):
            c.login("T-reissue", pw)
        with SB.client() as c:
            c.enroll("T-reissue", code, "Brand#New2026x")
        with SB.student("T-reissue", password="Brand#New2026x"):
            pass

    def test_closed_exam_rejects_new_attempts(self):
        self._new_exam("CLOSE-1")
        with SB.admin() as a:
            a.admin_action("CLOSE_EXAM", {"exam_id": "CLOSE-1"}, SB.admin_key)
        with SB.student("S1001") as c, self.assertRaises(ServerError) as ctx:
            c.get_exam("CLOSE-1")
        self.assertEqual(ctx.exception.code, "EXAM_NOT_OPEN")

    def test_audit_view_verifies_chain(self):
        with SB.admin() as a:
            r = a.call("ADMIN_AUDIT", limit=5)
        self.assertIsNone(r["integrity_error"])
        self.assertEqual(len(r["entries"]), 5)


class TestAttacks(unittest.TestCase):
    """One test per attack scenario, run in the suite's order (some depend on earlier state)."""


def _make_attack_test(fn):
    def test(self):
        result = fn(SB)
        self.assertTrue(result.blocked, f"{result.name}: {result.detail}")
    test.__doc__ = fn.__name__
    return test


for _i, _fn in enumerate(attacks.ALL_ATTACKS):
    setattr(TestAttacks, f"test_{_i:02d}_{_fn.__name__}", _make_attack_test(_fn))


if __name__ == "__main__":
    unittest.main()
