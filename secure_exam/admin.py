"""Examiner (admin) command-line tool.

    python -m secure_exam.admin [--user examiner] <command> ...
    python -m secure_exam.admin shell                     # interactive session

Commands
  students list | add ID "NAME" [--email E] | reissue ID | disable ID | enable ID
  unlock USER_ID
  exams list | show ID | create FILE.json | publish ID | close ID | release ID
  submissions list EXAM_ID | verify EXAM_ID STUDENT_ID
  results export EXAM_ID [--out FILE.json] [--csv FILE.csv]
  verify-export FILE.json                                (offline, no login needed)
  audit [--limit N]
  rotate-key

Every state-changing command is sent as an ADMIN_ACTION signed with the examiner's RSA key.
"""

import argparse
import csv
import datetime
import getpass
import json
import re
import shlex
import sys
import time
from pathlib import Path

from . import config
from .client import ExamClient, ServerError, load_key_file
from .crypto_utils import (IntegrityError, b64d, canonical_json, load_public_key, rsa_verify,
                           sha256_hex)

OFFLINE_COMMANDS = {"verify-export"}



def _csv_safe(value):
    """Neutralise spreadsheet formulas (CSV injection), e.g. a student named "=HYPERLINK(...)"."""
    return f"'{value}" if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r") else value

def parse_time(value, now: int | None = None) -> int:
    """Accept epoch seconds, 'now', relative '+30m' / '+3h' / '+2d', or ISO-8601 local time."""
    now = now or int(time.time())
    if isinstance(value, int):
        return value
    value = str(value).strip()
    if value == "now":
        return now
    m = re.fullmatch(r"\+(\d+)([mhd])", value)
    if m:
        return now + int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400}[m.group(2)]
    return int(datetime.datetime.fromisoformat(value).timestamp())


def _fmt(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


def _table(rows: list[dict], cols: list[str]) -> None:
    if not rows:
        print("  (none)")
        return
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    print("  " + "  ".join(c.upper().ljust(widths[c]) for c in cols))
    for r in rows:
        print("  " + "  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def verify_export(path: str) -> dict:
    signed = json.loads(Path(path).read_text())
    rsa_verify(load_public_key(config.SERVER_SIGN_PUB.read_bytes()), b64d(signed["signature"]),
               canonical_json(signed["body"]))
    return signed["body"]


class AdminCommands:
    def __init__(self, client: ExamClient, key):
        self.c, self.key = client, key

    def act(self, op: str, **params) -> dict:
        return self.c.admin_action(op, params, self.key)

    # --- students ---------------------------------------------------------------

    def students(self, a):
        if a.action == "list":
            _table(self.c.call("ADMIN_LIST_STUDENTS")["students"],
                   ["student_id", "name", "email", "status", "locked_out", "key_fingerprint"])
        elif a.action == "add":
            r = self.act("ADD_STUDENT", student_id=a.id, name=a.name, email=a.email or "")
            print(f"[✓] Student {r['student_id']} registered.")
            print(f"    Enrollment code: {r['enrollment_code']}  (valid until {_fmt(r['expires_at'])})")
            print("    Give this code to the student out-of-band; they run: "
                  "python -m secure_exam.client enroll")
        elif a.action == "reissue":
            r = self.act("REISSUE_ENROLLMENT", student_id=a.id)
            print(f"[✓] Old key and password revoked. New enrollment code: {r['enrollment_code']}")
        elif a.action in ("disable", "enable"):
            r = self.act("SET_STUDENT_STATUS", student_id=a.id,
                         status="disabled" if a.action == "disable" else "active")
            print(f"[✓] {r['student_id']} is now {r['status']}")

    def unlock(self, a):
        self.act("UNLOCK_ACCOUNT", user_id=a.user_id)
        print(f"[✓] Failed-login counter cleared for {a.user_id}")

    # --- exams -------------------------------------------------------------------

    def exams(self, a):
        if a.action == "list":
            rows = self.c.call("ADMIN_LIST_EXAMS")["exams"]
            for r in rows:
                r["opens_at"], r["closes_at"] = _fmt(r["opens_at"]), _fmt(r["closes_at"])
            _table(rows, ["exam_id", "status", "opens_at", "closes_at", "duration_minutes",
                          "questions", "started", "submitted", "results_released"])
        elif a.action == "show":
            r = self.c.call("ADMIN_GET_EXAM", exam_id=a.id)
            e, key = r["exam"], r["answer_key"]
            print(f"{e['exam_id']}  {e['title']}  [{e['status']}]")
            print(f"  window {_fmt(e['opens_at'])} -> {_fmt(e['closes_at'])}, "
                  f"{e['duration_minutes']} min, created by {e['created_by']}")
            for q in e["questions"]:
                print(f"  {q['id']} ({q['marks']}) {q['text']}   answer: {key[q['id']]}")
        elif a.action == "create":
            spec = json.loads(Path(a.file).read_text())
            exam = dict(spec["exam"])
            now = int(time.time())
            exam["opens_at"] = parse_time(exam["opens_at"], now)
            exam["closes_at"] = parse_time(exam["closes_at"], now)
            r = self.act("CREATE_EXAM", exam=exam, answer_key=spec["answer_key"])
            print(f"[✓] Exam {r['exam_id']} created as draft. Publish with: exams publish {r['exam_id']}")
        elif a.action in ("publish", "close", "release"):
            op = {"publish": "PUBLISH_EXAM", "close": "CLOSE_EXAM", "release": "RELEASE_RESULTS"}
            self.act(op[a.action], exam_id=a.id)
            done = {"publish": "published - students can now see it",
                    "close": "closed - no new attempts or submissions",
                    "release": "results released - students can fetch signed results"}
            print(f"[✓] {a.id} {done[a.action]}")

    # --- submissions / results -----------------------------------------------------

    def submissions(self, a):
        if a.action == "list":
            r = self.c.call("ADMIN_LIST_SUBMISSIONS", exam_id=a.exam_id)
            for row in r["submissions"]:
                row["received_at"] = _fmt(row["received_at"])
                row["submission_hash"] = row["submission_hash"][:16] + "…"
            _table(r["submissions"], ["student_id", "score", "total", "received_at", "submission_hash"])
            if r["not_submitted"]:
                print(f"  Started but not submitted: {', '.join(r['not_submitted'])}")
        elif a.action == "verify":
            self._verify_submission(a.exam_id, a.student_id)

    def _verify_submission(self, exam_id: str, student_id: str):
        """Independent non-repudiation check, done on the examiner's machine."""
        r = self.c.call("ADMIN_GET_SUBMISSION", exam_id=exam_id, student_id=student_id)
        rec, pub_pem = r["record"], r["student_public_key"]
        sub = rec["submission"]
        checks = []
        try:
            rsa_verify(load_public_key(pub_pem.encode()), b64d(rec["signature"]), canonical_json(sub))
            checks.append(("Student RSA-PSS signature over submission", True))
        except IntegrityError:
            checks.append(("Student RSA-PSS signature over submission", False))
        checks.append(("SHA-256(submission) matches stored hash",
                       sha256_hex(canonical_json(sub)) == rec["submission_hash"]))
        try:
            body = self.c.verify_signed(rec["receipt"])
            checks.append(("Server receipt signature", True))
            checks.append(("Receipt covers this submission",
                           body["submission_hash"] == rec["submission_hash"]))
        except IntegrityError:
            checks.append(("Server receipt signature", False))
        print(f"Submission by {student_id} for {exam_id}")
        print(f"  student key fingerprint : {sha256_hex(pub_pem.encode())[:32]}")
        print(f"  submitted_at (client)   : {_fmt(sub['submitted_at'])}")
        print(f"  received_at  (server)   : {_fmt(rec['received_at'])}")
        print(f"  answers                 : {sub['answers']}")
        for name, ok in checks:
            print(f"  {'✓' if ok else '✗'} {name}")
        verdict = all(ok for _, ok in checks)
        print("  => " + ("NON-REPUDIABLE: only the holder of the student's private key could "
                         "have produced this submission." if verdict else "VERIFICATION FAILED"))

    def results(self, a):
        signed = self.act("EXPORT_RESULTS", exam_id=a.exam_id)["export"]
        body = self.c.verify_signed(signed)
        rows = body["results"]
        _table(rows, ["student_id", "name", "score", "total", "percentage"])
        if body["no_submission"]:
            print(f"  No submission: {', '.join(body['no_submission'])}")
        if a.out:
            Path(a.out).write_text(json.dumps(signed, indent=2))
            print(f"[✓] Signed export written to {a.out} (verify with: verify-export {a.out})")
        if a.csv:
            with open(a.csv, "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["student_id"])
                w.writeheader()
                w.writerows({k: _csv_safe(v) for k, v in r.items()} for r in rows)
            print(f"[✓] CSV written to {a.csv} (unsigned convenience copy)")

    # --- audit / keys ----------------------------------------------------------------

    def audit(self, a):
        r = self.c.call("ADMIN_AUDIT", limit=a.limit)
        if r["integrity_error"]:
            print(f"[!] AUDIT LOG TAMPERED: {r['integrity_error']}")
        else:
            print(f"[✓] Audit log intact: {r['verified_entries']} entries verified (hash chain + HMAC)")
        for e in r["entries"]:
            details = ", ".join(f"{k}={v}" for k, v in e["details"].items()
                                if k not in ("signature",))
            print(f"  {_fmt(e['ts'])}  {e['event']:<28} {details[:110]}")

    def rotate_key(self, a):
        r = self.act("ROTATE_STORAGE_KEY")
        print(f"[✓] Storage key rotated; re-encrypted: {', '.join(r['stores'])}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secure_exam.admin", description="Examiner tool",
                                exit_on_error=False)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("students").add_subparsers(dest="action", required=True)
    s.add_parser("list")
    add = s.add_parser("add")
    add.add_argument("id")
    add.add_argument("name")
    add.add_argument("--email")
    for name in ("reissue", "disable", "enable"):
        s.add_parser(name).add_argument("id")

    sub.add_parser("unlock").add_argument("user_id")

    e = sub.add_parser("exams").add_subparsers(dest="action", required=True)
    e.add_parser("list")
    e.add_parser("create").add_argument("file")
    for name in ("show", "publish", "close", "release"):
        e.add_parser(name).add_argument("id")

    sb = sub.add_parser("submissions").add_subparsers(dest="action", required=True)
    sb.add_parser("list").add_argument("exam_id")
    v = sb.add_parser("verify")
    v.add_argument("exam_id")
    v.add_argument("student_id")

    r = sub.add_parser("results").add_subparsers(dest="action", required=True)
    ex = r.add_parser("export")
    ex.add_argument("exam_id")
    ex.add_argument("--out")
    ex.add_argument("--csv")

    sub.add_parser("verify-export").add_argument("file")
    sub.add_parser("audit").add_argument("--limit", type=int, default=25)
    sub.add_parser("rotate-key")
    sub.add_parser("shell")
    return p


def run_command(cmds: AdminCommands, args) -> None:
    handler = {"students": cmds.students, "unlock": cmds.unlock, "exams": cmds.exams,
               "submissions": cmds.submissions, "results": cmds.results, "audit": cmds.audit,
               "rotate-key": cmds.rotate_key}[args.command]
    handler(args)


def main() -> None:
    top = argparse.ArgumentParser(add_help=False)
    top.add_argument("--user", default="examiner")
    top.add_argument("--host", default=config.HOST)
    top.add_argument("--port", type=int, default=None)
    top.add_argument("--transport", choices=["socket", "https"], default="socket")
    conn_args, rest = top.parse_known_args()
    parser = build_parser()
    try:
        args = parser.parse_args(rest)
    except argparse.ArgumentError as exc:
        parser.print_usage()
        raise SystemExit(str(exc))

    if args.command == "verify-export":
        try:
            body = verify_export(args.file)
        except IntegrityError as exc:
            raise SystemExit(f"[!] Export INVALID: {exc}")
        print(f"[✓] Authentic server-signed export of {body['exam_id']} generated "
              f"{_fmt(body['generated_at'])} for {body['generated_for']}: {len(body['results'])} results")
        return

    password = getpass.getpass(f"Password for {conn_args.user}: ")
    try:
        key = load_key_file(conn_args.user, password)
    except (FileNotFoundError, ValueError, TypeError):
        raise SystemExit("Could not unlock the examiner signing key (wrong password or missing key).")

    try:
        with ExamClient(conn_args.host, conn_args.port, conn_args.transport) as client:
            client.login(conn_args.user, password, role="admin")
            cmds = AdminCommands(client, key)
            if args.command != "shell":
                run_command(cmds, args)
                return
            print(f"Logged in as {conn_args.user}. Type 'help' for commands, 'quit' to exit.")
            while True:
                try:
                    line = input("admin> ").strip()
                except EOFError:
                    break
                if line in ("quit", "exit"):
                    break
                if line in ("help", "?"):
                    print(__doc__.split("Commands", 1)[1].split("Every state", 1)[0])
                    continue
                if not line:
                    continue
                try:
                    run_command(cmds, parser.parse_args(shlex.split(line)))
                except (argparse.ArgumentError, SystemExit, KeyError) as exc:
                    print(f"  usage error: {exc}")
                except ServerError as exc:
                    print(f"[!] {exc}")
    except ServerError as exc:
        raise SystemExit(f"[!] {exc}")
    except IntegrityError as exc:
        raise SystemExit(f"[!] SECURITY ALERT: {exc}")
    except (ConnectionError, OSError) as exc:
        raise SystemExit(f"[!] Connection problem: {exc}")


if __name__ == "__main__":
    sys.exit(main())
