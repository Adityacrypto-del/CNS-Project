"""Encrypted-at-rest storage and a tamper-evident audit log.

Random 256-bit keys protect the server's data:
  * the storage key encrypts every database with AES-256-GCM;
  * the audit key authenticates audit-log entries with HMAC-SHA256.
Neither key is ever written in the clear: each is wrapped with the server's RSA public
key (RSA-OAEP) and can only be unwrapped with the server's private key. The storage key
can be rotated without touching the audit log.
"""

import json
import os
import threading
import time
from pathlib import Path

from .crypto_utils import (IntegrityError, aes_gcm_decrypt, aes_gcm_encrypt, b64d, b64e,
                           canonical_json, hmac_sha256, hmac_verify, rsa_decrypt, rsa_encrypt,
                           sha256_hex)


def create_wrapped_key(server_public_key, path: Path) -> bytes:
    key = os.urandom(32)
    write_wrapped_key(server_public_key, path, key)
    return key


def write_wrapped_key(server_public_key, path: Path, key: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(rsa_encrypt(server_public_key, key))
    os.replace(tmp, path)


def load_wrapped_key(server_private_key, path: Path) -> bytes:
    return rsa_decrypt(server_private_key, path.read_bytes())


class EncryptedStore:
    """A JSON document encrypted with AES-256-GCM.

    The file name is bound in as associated data, so an attacker with disk access
    cannot swap one encrypted database for another (e.g. exams.enc <-> answer_keys.enc).
    """

    def __init__(self, path: Path, key: bytes):
        self.path = path
        self.key = key
        self.aad = path.name.encode()

    def load(self, default=None):
        if not self.path.exists():
            return default
        return json.loads(aes_gcm_decrypt(self.key, self.path.read_bytes(), self.aad))

    def save(self, obj) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_bytes(aes_gcm_encrypt(self.key, canonical_json(obj), self.aad))
        os.replace(tmp, self.path)


def rotate_storage_key(stores: list[EncryptedStore], server_public_key, wrapped_path: Path) -> bytes:
    """Re-encrypt every store under a fresh key, then replace the wrapped key.

    Data is decrypted with the old key first, so a failure part-way leaves the old key
    file in place and the stores readable by whichever key they were last written with.
    """
    contents = [s.load() for s in stores]
    new_key = os.urandom(32)
    backup = wrapped_path.read_bytes()
    try:
        for store, data in zip(stores, contents):
            store.key = new_key
            if data is not None:
                store.save(data)
        write_wrapped_key(server_public_key, wrapped_path, new_key)
    except Exception:
        wrapped_path.write_bytes(backup)
        raise
    return new_key


class AuditLog:
    """Append-only log where every entry is hash-chained and HMAC-protected.

    Deleting, re-ordering or editing any entry breaks the chain, which verify() detects.
    """

    def __init__(self, path: Path, key: bytes):
        self.path = path
        self.key = key
        self.lock = threading.Lock()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        lines = self.path.read_text().strip().splitlines()
        return sha256_hex(lines[-1].encode()) if lines else "0" * 64

    def record(self, event: str, **details) -> None:
        with self.lock:
            entry = {"ts": round(time.time(), 3), "event": event, "details": details,
                     "prev": self._last_hash()}
            entry["mac"] = b64e(hmac_sha256(self.key, canonical_json(entry)))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().strip().splitlines() if line]

    def verify(self) -> int:
        """Return the number of valid entries; raise IntegrityError on tampering."""
        if not self.path.exists():
            return 0
        prev = "0" * 64
        lines = self.path.read_text().strip().splitlines()
        for i, line in enumerate(lines):
            entry = json.loads(line)
            mac = b64d(entry.pop("mac"))
            if entry["prev"] != prev:
                raise IntegrityError(f"audit log chain broken at entry {i}")
            try:
                hmac_verify(self.key, canonical_json(entry), mac)
            except IntegrityError as exc:
                raise IntegrityError(f"audit log entry {i} has an invalid HMAC") from exc
            prev = sha256_hex(line.encode())
        return len(lines)
