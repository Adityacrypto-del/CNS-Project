"""Examination business logic, independent of the transport.

Both the TLS socket server (server.py) and the HTTPS JSON API (api.py) decrypt a request
through their SecureChannel and hand the plaintext dict to ExamService.dispatch().

Roles
  * anonymous - may only LOGIN or ENROLL
  * student   - list/sit exams, submit signed answers, fetch released results
  * admin     - manage students and exams. Every state-changing admin operation must be
                wrapped in an ADMIN_ACTION signed with the examiner's RSA key, so
                there is a non-repudiable record of who created an exam, released results etc.
"""

import os
import re
import threading
import time

from . import config
from .crypto_utils import (IntegrityError, b64d, b64e, canonical_json, hash_password, hkdf,
                           hmac_sha256, load_private_key, load_public_key, rsa_sign, rsa_verify,
                           sha256_hex, verify_password)
from .storage import (AuditLog, EncryptedStore, load_wrapped_key, rotate_storage_key)

EXAM_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,39}$")
STUDENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{2,32}$")
_DUMMY_PASSWORD = {"salt": b64e(b"\0" * 16), "hash": b64e(b"\0" * 32),
                   "iterations": config.PBKDF2_ITERATIONS}


class ServiceError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, detail


class Session:
    """Per-connection (socket) or per-session-id (HTTPS) authentication state."""

    def __init__(self, peer: str):
        self.peer = peer
        self.user_id: str | None = None
        self.role: str | None = None
        self.authenticated_at: float | None = None


def check_password_policy(password: str, user_id: str) -> None:
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if len(password) < config.PASSWORD_MIN_LENGTH or classes < 3:
        raise ServiceError("WEAK_PASSWORD", f"use at least {config.PASSWORD_MIN_LENGTH} characters "
                           "and 3 of: lowercase, uppercase, digit, symbol")
    if user_id.lower() in password.lower():
        raise ServiceError("WEAK_PASSWORD", "password must not contain your user ID")


def validate_exam(exam: dict, answer_key: dict) -> dict:
    """Validate an exam definition from an examiner and return the normalised form."""
    def need(cond, msg):
        if not cond:
            raise ServiceError("INVALID_EXAM", msg)

    need(isinstance(exam, dict) and isinstance(answer_key, dict), "exam and answer_key must be objects")
    exam_id = exam.get("exam_id", "")
    need(isinstance(exam_id, str) and EXAM_ID_RE.match(exam_id),
         "exam_id must be 3-40 chars of A-Z, 0-9 and '-'")
    need(isinstance(exam.get("title"), str) and exam["title"].strip(), "title required")
    duration = exam.get("duration_minutes")
    need(isinstance(duration, int) and 1 <= duration <= 600, "duration_minutes must be 1..600")
    opens, closes = exam.get("opens_at"), exam.get("closes_at")
    need(isinstance(opens, int) and isinstance(closes, int) and opens < closes,
         "opens_at/closes_at must be epoch seconds with opens_at < closes_at")
    questions = exam.get("questions")
    need(isinstance(questions, list) and 1 <= len(questions) <= 200, "1..200 questions required")

    seen, normalised = set(), []
    for q in questions:
        need(isinstance(q, dict), "each question must be an object")
        qid, options = q.get("id"), q.get("options")
        need(isinstance(qid, str) and qid and qid not in seen, f"question id {qid!r} missing or duplicate")
        seen.add(qid)
        need(isinstance(q.get("text"), str) and q["text"].strip(), f"{qid}: text required")
        need(isinstance(options, dict) and 2 <= len(options) <= 8
             and all(isinstance(k, str) and isinstance(v, str) for k, v in options.items()),
             f"{qid}: 2..8 string options required")
        marks = q.get("marks", 1)
        need(isinstance(marks, int) and 1 <= marks <= 100, f"{qid}: marks must be 1..100")
        need(answer_key.get(qid) in options, f"{qid}: answer key missing or not one of the options")
        normalised.append({"id": qid, "text": q["text"], "options": options, "marks": marks})
    need(set(answer_key) == seen, "answer key has entries for unknown questions")

    return {"exam_id": exam_id, "title": exam["title"].strip(),
            "description": str(exam.get("description", "")), "duration_minutes": duration,
            "opens_at": opens, "closes_at": closes, "questions": normalised}


class ExamService:
    def __init__(self):
        self.sign_key = load_private_key(config.SERVER_SIGN_KEY.read_bytes())
        storage_key = load_wrapped_key(self.sign_key, config.STORAGE_KEY_WRAPPED)
        audit_key = load_wrapped_key(self.sign_key, config.AUDIT_KEY_WRAPPED)
        self.students_db = EncryptedStore(config.STUDENTS_DB, storage_key)
        self.admins_db = EncryptedStore(config.ADMINS_DB, storage_key)
        self.exams_db = EncryptedStore(config.EXAMS_DB, storage_key)
        self.answers_db = EncryptedStore(config.ANSWER_KEYS_DB, storage_key)
        self.submissions_db = EncryptedStore(config.SUBMISSIONS_DB, storage_key)
        self.stores = [self.students_db, self.admins_db, self.exams_db, self.answers_db,
                       self.submissions_db]
        self.audit = AuditLog(config.AUDIT_LOG, audit_key)
        self._shuffle_key = hkdf(audit_key, salt=b"", info=b"question-order", length=32)

        self.lock = threading.RLock()                        # guards every read-modify-write
        self.failed: dict[str, list[float]] = {}             # "role:user" -> failure times
        self.active: set[tuple[str, str]] = set()            # (role, user) currently logged in
        self.seen_action_nonces: dict[str, float] = {}

        self.handlers = {
            # op                      handler                       role required
            "LOGIN":                  (self.login,                  None),
            "ENROLL":                 (self.enroll,                 None),
            "WHOAMI":                 (self.whoami,                 "any"),
            "LOGOUT":                 (self.logout,                 "any"),
            "CHANGE_PASSWORD":        (self.change_password,        "any"),
            "LIST_EXAMS":             (self.list_exams,             "student"),
            "GET_EXAM":               (self.get_exam,               "student"),
            "SUBMIT":                 (self.submit,                 "student"),
            "GET_RESULT":             (self.get_result,             "student"),
            "ADMIN_LIST_STUDENTS":    (self.admin_list_students,    "admin"),
            "ADMIN_LIST_EXAMS":       (self.admin_list_exams,       "admin"),
            "ADMIN_GET_EXAM":         (self.admin_get_exam,         "admin"),
            "ADMIN_LIST_SUBMISSIONS": (self.admin_list_submissions, "admin"),
            "ADMIN_GET_SUBMISSION":   (self.admin_get_submission,   "admin"),
            "ADMIN_AUDIT":            (self.admin_audit,            "admin"),
            "ADMIN_ACTION":           (self.admin_action,           "admin"),
        }
        # Operations that change state: only reachable through a signed ADMIN_ACTION.
        self.admin_actions = {
            "ADD_STUDENT": self._act_add_student,
            "REISSUE_ENROLLMENT": self._act_reissue_enrollment,
            "SET_STUDENT_STATUS": self._act_set_student_status,
            "UNLOCK_ACCOUNT": self._act_unlock,
            "CREATE_EXAM": self._act_create_exam,
            "PUBLISH_EXAM": self._act_publish_exam,
            "CLOSE_EXAM": self._act_close_exam,
            "RELEASE_RESULTS": self._act_release_results,
            "EXPORT_RESULTS": self._act_export_results,
            "ROTATE_STORAGE_KEY": self._act_rotate_storage_key,
        }

    # ======================================================================
    # Dispatch
    # ======================================================================

    def dispatch(self, req: dict, session: Session) -> dict:
        op = req.get("type")
        entry = self.handlers.get(op)
        try:
            if entry is None:
                raise ServiceError("UNKNOWN_REQUEST", f"unknown request type {op!r}")
            handler, role = entry
            if role is not None:
                self._require_session(session)
                if role != "any" and session.role != role:
                    self.audit.record("FORBIDDEN", peer=session.peer, user=session.user_id,
                                      role=session.role, request=op)
                    raise ServiceError("FORBIDDEN", f"{op} requires role {role}")
            return {"ok": True, **handler(req, session)}
        except ServiceError as exc:
            if exc.code == "UNAUTHORIZED":
                self.audit.record("UNAUTHORIZED_REQUEST", peer=session.peer, request=op)
            return {"ok": False, "error": exc.code, "detail": exc.detail}
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            return {"ok": False, "error": "BAD_REQUEST", "detail": f"malformed request: {exc}"}

    def _require_session(self, session: Session) -> None:
        if session.user_id is None:
            raise ServiceError("UNAUTHORIZED", "not authenticated")
        if time.time() - session.authenticated_at > config.SESSION_TTL:
            self.audit.record("SESSION_EXPIRED", user=session.user_id)
            self.release(session)
            raise ServiceError("SESSION_EXPIRED", "please log in again")

    def release(self, session: Session) -> None:
        """Forget a session's login (called on logout, disconnect and API session expiry)."""
        with self.lock:
            if session.user_id:
                self.active.discard((session.role, session.user_id))
        session.user_id = session.role = session.authenticated_at = None

    def _signed(self, body: dict) -> dict:
        return {"body": body, "signature": b64e(rsa_sign(self.sign_key, canonical_json(body)))}

    # --- brute-force protection ------------------------------------------------

    def _check_lockout(self, key: str) -> None:
        with self.lock:
            now = time.time()
            recent = [t for t in self.failed.get(key, []) if now - t < config.LOCKOUT_SECONDS]
            self.failed[key] = recent
            if len(recent) >= config.MAX_FAILED_LOGINS:
                self.audit.record("ACCOUNT_LOCKED_OUT", account=key)
                raise ServiceError("ACCOUNT_LOCKED",
                                   f"too many failed attempts; retry in {config.LOCKOUT_SECONDS}s")

    def _record_failure(self, key: str) -> None:
        with self.lock:
            self.failed.setdefault(key, []).append(time.time())

    # ======================================================================
    # Authentication
    # ======================================================================

    def login(self, req: dict, session: Session) -> dict:
        if session.user_id:
            raise ServiceError("ALREADY_AUTHENTICATED")
        role = req.get("role", "student")
        if role not in ("student", "admin"):
            raise ServiceError("BAD_REQUEST", "role must be student or admin")
        user_id, password = str(req["user_id"]), str(req["password"])
        key = f"{role}:{user_id}"
        self._check_lockout(key)

        db = self.students_db if role == "student" else self.admins_db
        with self.lock:
            user = db.load({}).get(user_id)
        record = (user or {}).get("password") or _DUMMY_PASSWORD
        # PBKDF2 always runs (outside the lock) so timing does not reveal unknown IDs.
        password_ok = verify_password(password, record) and user is not None
        if not password_ok:
            self._record_failure(key)
            self.audit.record("LOGIN_FAILED", peer=session.peer, role=role, user=user_id)
            raise ServiceError("INVALID_CREDENTIALS")
        if role == "student" and user.get("status") != "active":
            self.audit.record("LOGIN_REJECTED_INACTIVE", peer=session.peer, user=user_id)
            raise ServiceError("ACCOUNT_INACTIVE", f"account is {user.get('status')}")

        with self.lock:
            if (role, user_id) in self.active:
                self.audit.record("LOGIN_REJECTED_CONCURRENT", peer=session.peer, user=user_id)
                raise ServiceError("SESSION_ACTIVE", "this account is already logged in elsewhere")
            self.failed.pop(key, None)
            self.active.add((role, user_id))
        session.user_id, session.role, session.authenticated_at = user_id, role, time.time()
        self.audit.record("LOGIN_SUCCESS", peer=session.peer, role=role, user=user_id)
        return {"user_id": user_id, "role": role, "name": user["name"],
                "server_time": int(time.time()), "session_ttl": config.SESSION_TTL}

    def enroll(self, req: dict, session: Session) -> dict:
        """First-time activation: the student proves possession of the one-time code and of
        the private key matching the public key being registered."""
        sid, code = str(req["student_id"]), str(req["enrollment_code"])
        password, pub_pem = str(req["password"]), str(req["public_key"])
        key = f"enroll:{sid}"
        self._check_lockout(key)

        with self.lock:
            students = self.students_db.load({})
            student = students.get(sid)
            enrollment = (student or {}).get("enrollment")
            valid = (student is not None and student["status"] == "pending" and enrollment
                     and time.time() < enrollment["expires_at"]
                     and sha256_hex(code.strip().upper().encode()) == enrollment["code_hash"])
            if not valid:
                self._record_failure(key)
                self.audit.record("ENROLL_FAILED", peer=session.peer, user=sid)
                raise ServiceError("INVALID_ENROLLMENT", "unknown student, bad or expired code")

            check_password_policy(password, sid)
            try:
                public_key = load_public_key(pub_pem.encode())
                if public_key.key_size < config.STUDENT_RSA_KEY_BITS:
                    raise ValueError("key too small")
                rsa_verify(public_key, b64d(req["proof"]),
                           canonical_json({"student_id": sid, "public_key": pub_pem,
                                           "purpose": "enroll"}))
            except (ValueError, TypeError, IntegrityError) as exc:
                raise ServiceError("INVALID_PUBLIC_KEY",
                                   f"RSA key >= {config.STUDENT_RSA_KEY_BITS} bits with valid "
                                   f"proof-of-possession signature required ({exc})")

            student.update(status="active", password=hash_password(password),
                           public_key=pub_pem, enrollment=None, enrolled_at=int(time.time()))
            self.students_db.save(students)
            self.failed.pop(key, None)
        self.audit.record("STUDENT_ENROLLED", peer=session.peer, user=sid,
                          key_fingerprint=sha256_hex(pub_pem.encode())[:32])
        return {"student_id": sid, "status": "active"}

    def whoami(self, req: dict, session: Session) -> dict:
        return {"user_id": session.user_id, "role": session.role,
                "session_expires_at": int(session.authenticated_at + config.SESSION_TTL)}

    def logout(self, req: dict, session: Session) -> dict:
        self.audit.record("LOGOUT", role=session.role, user=session.user_id)
        self.release(session)
        return {}

    def change_password(self, req: dict, session: Session) -> dict:
        db = self.students_db if session.role == "student" else self.admins_db
        old, new = str(req["old_password"]), str(req["new_password"])
        with self.lock:
            users = db.load({})
            user = users[session.user_id]
            if not verify_password(old, user["password"]):
                self.audit.record("PASSWORD_CHANGE_FAILED", user=session.user_id)
                raise ServiceError("INVALID_CREDENTIALS", "current password is wrong")
            check_password_policy(new, session.user_id)
            user["password"] = hash_password(new)
            db.save(users)
        self.audit.record("PASSWORD_CHANGED", role=session.role, user=session.user_id)
        return {}

    # ======================================================================
    # Student operations
    # ======================================================================

    def _exam_view(self, exam: dict, sid: str) -> dict:
        """The paper as a particular student sees it: no internal fields, and questions in a
        per-student order (deterministic, so the hash can be recomputed on submission)."""
        order = sorted(exam["questions"], key=lambda q: hmac_sha256(
            self._shuffle_key, f"{exam['exam_id']}|{sid}|{q['id']}".encode()))
        return {"exam_id": exam["exam_id"], "title": exam["title"],
                "description": exam["description"], "duration_minutes": exam["duration_minutes"],
                "total_marks": sum(q["marks"] for q in exam["questions"]), "questions": order}

    @staticmethod
    def _student_state(exam: dict, bucket: dict, sid: str, now: float) -> str:
        if sid in bucket["submissions"]:
            return "submitted"
        attempt = bucket["attempts"].get(sid)
        if attempt:
            in_time = now <= attempt["deadline"] + config.SUBMISSION_GRACE_SECONDS
            return "in_progress" if in_time and exam["status"] == "published" else "missed"
        if exam["status"] == "closed" or now >= exam["closes_at"]:
            return "closed"
        return "upcoming" if now < exam["opens_at"] else "open"

    def list_exams(self, req: dict, session: Session) -> dict:
        sid, now = session.user_id, time.time()
        with self.lock:
            exams, subs = self.exams_db.load({}), self.submissions_db.load({})
        out = []
        for exam in exams.values():
            if exam["status"] == "draft":
                continue
            bucket = subs.get(exam["exam_id"], {"attempts": {}, "submissions": {}})
            out.append({"exam_id": exam["exam_id"], "title": exam["title"],
                        "duration_minutes": exam["duration_minutes"],
                        "opens_at": exam["opens_at"], "closes_at": exam["closes_at"],
                        "state": self._student_state(exam, bucket, sid, now),
                        "result_available": exam["results_released"]
                        and sid in bucket["submissions"]})
        return {"exams": sorted(out, key=lambda e: e["opens_at"])}

    def get_exam(self, req: dict, session: Session) -> dict:
        sid, exam_id, now = session.user_id, str(req["exam_id"]), int(time.time())
        with self.lock:
            exam = self.exams_db.load({}).get(exam_id)
            if exam is None or exam["status"] == "draft":
                raise ServiceError("NO_SUCH_EXAM")
            subs = self.submissions_db.load({})
            bucket = subs.setdefault(exam_id, {"attempts": {}, "submissions": {}})
            if sid in bucket["submissions"]:
                raise ServiceError("ALREADY_SUBMITTED")
            attempt = bucket["attempts"].get(sid)
            if attempt is None:
                if exam["status"] != "published" or not exam["opens_at"] <= now < exam["closes_at"]:
                    self.audit.record("EXAM_ACCESS_OUTSIDE_WINDOW", user=sid, exam_id=exam_id)
                    raise ServiceError("EXAM_NOT_OPEN", "the exam is not open at this time")
                attempt = {"started_at": now,
                           "deadline": min(now + exam["duration_minutes"] * 60, exam["closes_at"])}
                bucket["attempts"][sid] = attempt
                self.submissions_db.save(subs)
                self.audit.record("EXAM_STARTED", user=sid, exam_id=exam_id)
            elif now > attempt["deadline"] + config.SUBMISSION_GRACE_SECONDS:
                raise ServiceError("DEADLINE_PASSED")
        view = self._exam_view(exam, sid)
        paper = {"exam": view, "exam_hash": sha256_hex(canonical_json(view)), "issued_to": sid,
                 "started_at": attempt["started_at"], "deadline": attempt["deadline"],
                 "issued_at": now}
        return {"paper": self._signed(paper)}

    def submit(self, req: dict, session: Session) -> dict:
        sid = session.user_id
        submission, signature = req["submission"], b64d(req["signature"])
        if not isinstance(submission, dict):
            raise ServiceError("BAD_REQUEST", "submission must be an object")
        if submission.get("student_id") != sid:
            self.audit.record("IMPERSONATION_ATTEMPT", peer=session.peer, user=sid,
                              claimed=submission.get("student_id"))
            raise ServiceError("UNAUTHORIZED", "submission student_id does not match authenticated user")
        exam_id = str(submission.get("exam_id"))

        with self.lock:
            exam = self.exams_db.load({}).get(exam_id)
            if exam is None or exam["status"] == "draft":
                raise ServiceError("NO_SUCH_EXAM")
            student = self.students_db.load({})[sid]
            if submission.get("exam_hash") != sha256_hex(canonical_json(self._exam_view(exam, sid))):
                raise ServiceError("EXAM_HASH_MISMATCH",
                                   "answers were given against a different or modified paper")
            # Non-repudiation: only the student's private key could produce this signature.
            try:
                rsa_verify(load_public_key(student["public_key"].encode()), signature,
                           canonical_json(submission))
            except IntegrityError:
                self.audit.record("SUBMISSION_BAD_SIGNATURE", peer=session.peer, user=sid,
                                  exam_id=exam_id)
                raise ServiceError("INVALID_SIGNATURE", "submission signature does not verify")

            answers = submission.get("answers")
            options = {q["id"]: q["options"] for q in exam["questions"]}
            if not isinstance(answers, dict) or any(
                    q not in options or a not in options[q] for q, a in answers.items()):
                raise ServiceError("BAD_REQUEST", "unknown question id or option")

            now = int(time.time())
            subs = self.submissions_db.load({})
            bucket = subs.setdefault(exam_id, {"attempts": {}, "submissions": {}})
            attempt = bucket["attempts"].get(sid)
            if attempt is None:
                raise ServiceError("EXAM_NOT_STARTED")
            if sid in bucket["submissions"]:
                self.audit.record("DUPLICATE_SUBMISSION", peer=session.peer, user=sid, exam_id=exam_id)
                raise ServiceError("ALREADY_SUBMITTED")
            if exam["status"] != "published" or now > attempt["deadline"] + config.SUBMISSION_GRACE_SECONDS:
                self.audit.record("LATE_SUBMISSION", user=sid, exam_id=exam_id)
                raise ServiceError("DEADLINE_PASSED")

            key = self.answers_db.load({})[exam_id]
            marks = {q["id"]: q["marks"] for q in exam["questions"]}
            score = sum(marks[q] for q, a in answers.items() if key[q] == a)
            submission_hash = sha256_hex(canonical_json(submission))
            receipt = self._signed({"student_id": sid, "exam_id": exam_id,
                                    "exam_hash": submission["exam_hash"],
                                    "submission_hash": submission_hash, "received_at": now})
            bucket["submissions"][sid] = {
                "submission": submission, "signature": b64e(signature),
                "submission_hash": submission_hash, "received_at": now, "score": score,
                "total": sum(marks.values()), "receipt": receipt}
            self.submissions_db.save(subs)
        self.audit.record("SUBMISSION_ACCEPTED", user=sid, exam_id=exam_id,
                          submission_hash=submission_hash)
        return {"receipt": receipt}

    def get_result(self, req: dict, session: Session) -> dict:
        sid, exam_id = session.user_id, str(req["exam_id"])
        with self.lock:
            exam = self.exams_db.load({}).get(exam_id)
            record = self.submissions_db.load({}).get(exam_id, {}).get("submissions", {}).get(sid)
        if exam is None or exam["status"] == "draft":
            raise ServiceError("NO_SUCH_EXAM")
        if record is None:
            raise ServiceError("NO_SUBMISSION")
        if not exam["results_released"]:
            raise ServiceError("RESULTS_NOT_RELEASED", "results have not been published yet")
        # The answer key is deliberately not revealed.
        result = {"student_id": sid, "exam_id": exam_id, "score": record["score"],
                  "total": record["total"],
                  "percentage": round(100 * record["score"] / record["total"], 2),
                  "submission_hash": record["submission_hash"], "issued_at": int(time.time())}
        self.audit.record("RESULT_ISSUED", user=sid, exam_id=exam_id)
        return {"result": self._signed(result)}

    # ======================================================================
    # Admin: read-only
    # ======================================================================

    def admin_list_students(self, req: dict, session: Session) -> dict:
        with self.lock:
            students = self.students_db.load({})
        now = time.time()
        locked = {k.split(":", 1)[1] for k, v in self.failed.items()
                  if k.startswith("student:")
                  and len([t for t in v if now - t < config.LOCKOUT_SECONDS]) >= config.MAX_FAILED_LOGINS}
        return {"students": [
            {"student_id": sid, "name": s["name"], "email": s["email"], "status": s["status"],
             "locked_out": sid in locked,
             "key_fingerprint": sha256_hex(s["public_key"].encode())[:32] if s.get("public_key") else None}
            for sid, s in sorted(students.items())]}

    def admin_list_exams(self, req: dict, session: Session) -> dict:
        with self.lock:
            exams, subs = self.exams_db.load({}), self.submissions_db.load({})
        return {"exams": [
            {k: e[k] for k in ("exam_id", "title", "status", "opens_at", "closes_at",
                               "duration_minutes", "results_released", "created_by")}
            | {"questions": len(e["questions"]),
               "started": len(subs.get(eid, {}).get("attempts", {})),
               "submitted": len(subs.get(eid, {}).get("submissions", {}))}
            for eid, e in sorted(exams.items())]}

    def admin_get_exam(self, req: dict, session: Session) -> dict:
        exam_id = str(req["exam_id"])
        with self.lock:
            exam = self.exams_db.load({}).get(exam_id)
            key = self.answers_db.load({}).get(exam_id)
        if exam is None:
            raise ServiceError("NO_SUCH_EXAM")
        return {"exam": exam, "answer_key": key}

    def admin_list_submissions(self, req: dict, session: Session) -> dict:
        exam_id = str(req["exam_id"])
        with self.lock:
            bucket = self.submissions_db.load({}).get(exam_id, {"attempts": {}, "submissions": {}})
        return {"exam_id": exam_id, "submissions": [
            {"student_id": sid, "score": r["score"], "total": r["total"],
             "received_at": r["received_at"], "submission_hash": r["submission_hash"]}
            for sid, r in sorted(bucket["submissions"].items())],
            "not_submitted": sorted(set(bucket["attempts"]) - set(bucket["submissions"]))}

    def admin_get_submission(self, req: dict, session: Session) -> dict:
        """Everything needed to verify a submission independently of the server."""
        exam_id, sid = str(req["exam_id"]), str(req["student_id"])
        with self.lock:
            record = self.submissions_db.load({}).get(exam_id, {}).get("submissions", {}).get(sid)
            student = self.students_db.load({}).get(sid)
        if record is None:
            raise ServiceError("NO_SUBMISSION")
        return {"record": record, "student_public_key": student["public_key"]}

    def admin_audit(self, req: dict, session: Session) -> dict:
        limit = max(1, min(int(req.get("limit", 50)), 1000))
        try:
            verified, error = self.audit.verify(), None
        except IntegrityError as exc:
            verified, error = None, str(exc)
        entries = self.audit.entries()[-limit:]
        return {"verified_entries": verified, "integrity_error": error,
                "entries": [{k: e[k] for k in ("ts", "event", "details")} for e in entries]}

    # ======================================================================
    # Admin: signed state-changing actions
    # ======================================================================

    def admin_action(self, req: dict, session: Session) -> dict:
        action, signature = req["action"], b64d(req["signature"])
        if not isinstance(action, dict) or action.get("admin_id") != session.user_id:
            raise ServiceError("FORBIDDEN", "action must be signed by the logged-in examiner")
        if abs(time.time() - int(action["ts"])) > config.MAX_CLOCK_SKEW:
            raise ServiceError("STALE_ACTION", "action timestamp outside allowed window")
        with self.lock:
            now = time.time()
            self.seen_action_nonces = {n: t for n, t in self.seen_action_nonces.items()
                                       if now - t < 2 * config.MAX_CLOCK_SKEW}
            nonce = str(action["nonce"])
            if nonce in self.seen_action_nonces:
                self.audit.record("ADMIN_ACTION_REPLAY", user=session.user_id)
                raise ServiceError("REPLAYED_ACTION")
            admin = self.admins_db.load({})[session.user_id]
        try:
            rsa_verify(load_public_key(admin["public_key"].encode()), signature, canonical_json(action))
        except IntegrityError:
            self.audit.record("ADMIN_ACTION_BAD_SIGNATURE", peer=session.peer, user=session.user_id,
                              op=action.get("op"))
            raise ServiceError("INVALID_SIGNATURE", "admin action signature does not verify")
        handler = self.admin_actions.get(action.get("op"))
        if handler is None:
            raise ServiceError("UNKNOWN_ACTION", f"unknown admin action {action.get('op')!r}")
        with self.lock:
            if nonce in self.seen_action_nonces:                  # concurrent duplicate
                raise ServiceError("REPLAYED_ACTION")
            self.seen_action_nonces[nonce] = time.time()
        params = action.get("params") or {}
        result = handler(params, session)
        # The audit log keeps the signature, so the action is attributable to this examiner.
        self.audit.record("ADMIN_ACTION", user=session.user_id, op=action["op"],
                          action_hash=sha256_hex(canonical_json(action)), signature=b64e(signature))
        return result

    def _act_add_student(self, p: dict, session: Session) -> dict:
        sid = str(p["student_id"])
        if not STUDENT_ID_RE.match(sid):
            raise ServiceError("BAD_REQUEST", "student_id must be 2-32 chars of A-Z a-z 0-9 _ -")
        with self.lock:
            students = self.students_db.load({})
            if sid in students:
                raise ServiceError("ALREADY_EXISTS", f"student {sid} already exists")
            code, enrollment = self._new_enrollment()
            students[sid] = {"name": str(p["name"]), "email": str(p.get("email", "")),
                             "status": "pending", "password": None, "public_key": None,
                             "enrollment": enrollment, "created_at": int(time.time())}
            self.students_db.save(students)
        return {"student_id": sid, "enrollment_code": code, "expires_at": enrollment["expires_at"]}

    def _act_reissue_enrollment(self, p: dict, session: Session) -> dict:
        """Reset a student (e.g. lost key): new code, old key and password revoked."""
        sid = str(p["student_id"])
        with self.lock:
            students = self.students_db.load({})
            if sid not in students:
                raise ServiceError("NO_SUCH_STUDENT")
            code, enrollment = self._new_enrollment()
            students[sid].update(status="pending", password=None, public_key=None,
                                 enrollment=enrollment)
            self.students_db.save(students)
        return {"student_id": sid, "enrollment_code": code, "expires_at": enrollment["expires_at"]}

    @staticmethod
    def _new_enrollment() -> tuple[str, dict]:
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"                 # no 0/O/1/I
        raw = "".join(alphabet[b % len(alphabet)] for b in os.urandom(16))  # 80 bits
        code = "-".join(raw[i:i + 4] for i in range(0, 16, 4))
        return code, {"code_hash": sha256_hex(code.encode()),
                      "expires_at": int(time.time()) + config.ENROLLMENT_CODE_TTL}

    def _act_set_student_status(self, p: dict, session: Session) -> dict:
        sid, status = str(p["student_id"]), p["status"]
        if status not in ("active", "disabled"):
            raise ServiceError("BAD_REQUEST", "status must be active or disabled")
        with self.lock:
            students = self.students_db.load({})
            student = students.get(sid)
            if student is None:
                raise ServiceError("NO_SUCH_STUDENT")
            if status == "active" and not student.get("public_key"):
                raise ServiceError("NOT_ENROLLED", "student has not enrolled yet")
            student["status"] = status
            self.students_db.save(students)
        return {"student_id": sid, "status": status}

    def _act_unlock(self, p: dict, session: Session) -> dict:
        user = str(p["user_id"])
        with self.lock:
            for key in (f"student:{user}", f"admin:{user}", f"enroll:{user}"):
                self.failed.pop(key, None)
        return {"user_id": user, "unlocked": True}

    def _act_create_exam(self, p: dict, session: Session) -> dict:
        exam = validate_exam(p["exam"], p["answer_key"])
        with self.lock:
            exams = self.exams_db.load({})
            if exam["exam_id"] in exams:
                raise ServiceError("ALREADY_EXISTS", f"exam {exam['exam_id']} already exists")
            exam.update(status="draft", results_released=False, created_by=session.user_id,
                        created_at=int(time.time()))
            exams[exam["exam_id"]] = exam
            keys = self.answers_db.load({})
            keys[exam["exam_id"]] = dict(p["answer_key"])
            self.answers_db.save(keys)
            self.exams_db.save(exams)
        return {"exam_id": exam["exam_id"], "status": "draft"}

    def _update_exam(self, exam_id: str, allowed_from: tuple, **changes) -> dict:
        with self.lock:
            exams = self.exams_db.load({})
            exam = exams.get(exam_id)
            if exam is None:
                raise ServiceError("NO_SUCH_EXAM")
            if exam["status"] not in allowed_from:
                raise ServiceError("INVALID_STATE", f"exam is {exam['status']}")
            exam.update(changes)
            self.exams_db.save(exams)
        return exam

    def _act_publish_exam(self, p: dict, session: Session) -> dict:
        exam = self._update_exam(str(p["exam_id"]), ("draft",), status="published",
                                 published_at=int(time.time()))
        return {"exam_id": exam["exam_id"], "status": exam["status"]}

    def _act_close_exam(self, p: dict, session: Session) -> dict:
        exam = self._update_exam(str(p["exam_id"]), ("published",), status="closed",
                                 closed_at=int(time.time()))
        return {"exam_id": exam["exam_id"], "status": exam["status"]}

    def _act_release_results(self, p: dict, session: Session) -> dict:
        exam = self._update_exam(str(p["exam_id"]), ("published", "closed"), results_released=True)
        return {"exam_id": exam["exam_id"], "results_released": True}

    def _act_export_results(self, p: dict, session: Session) -> dict:
        exam_id = str(p["exam_id"])
        with self.lock:
            exam = self.exams_db.load({}).get(exam_id)
            bucket = self.submissions_db.load({}).get(exam_id, {"attempts": {}, "submissions": {}})
            students = self.students_db.load({})
        if exam is None:
            raise ServiceError("NO_SUCH_EXAM")
        rows = [{"student_id": sid, "name": students[sid]["name"], "score": r["score"],
                 "total": r["total"], "percentage": round(100 * r["score"] / r["total"], 2),
                 "submission_hash": r["submission_hash"], "received_at": r["received_at"]}
                for sid, r in sorted(bucket["submissions"].items())]
        absent = sorted(sid for sid, s in students.items()
                        if s["status"] == "active" and sid not in bucket["submissions"])
        return {"export": self._signed({"exam_id": exam_id, "title": exam["title"],
                                        "generated_at": int(time.time()),
                                        "generated_for": session.user_id,
                                        "results": rows, "no_submission": absent})}

    def _act_rotate_storage_key(self, p: dict, session: Session) -> dict:
        with self.lock:
            rotate_storage_key(self.stores, self.sign_key.public_key(), config.STORAGE_KEY_WRAPPED)
        return {"rotated": True, "stores": [s.path.name for s in self.stores]}
