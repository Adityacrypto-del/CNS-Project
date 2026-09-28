"""Wire protocol: length-prefixed JSON frames plus an application-layer secure channel.

The transport is TLS. On top of TLS, every session runs a hybrid handshake:

  1. Client -> HELLO     {client_nonce, wrapped_master = RSA-OAEP(server_pub, master)}
  2. Server -> HELLO_OK  {server_nonce, signature = RSA-PSS(server_priv, transcript)}
     The client verifies the signature with the pinned server public key, which
     authenticates the server independently of TLS.
  3. Both sides derive  k_enc || k_mac = HKDF(master, client_nonce || server_nonce)
     Fresh server_nonce per session means a replayed HELLO yields different keys.

Every subsequent message is a SecureChannel envelope:

    {seq, ts, iv, ct, mac}
    ct  = AES-256-CBC(k_enc, iv, plaintext_json)
    mac = HMAC-SHA256(k_mac, direction || seq || ts || iv || ct)

The receiver checks the MAC first (encrypt-then-MAC), then enforces a strictly
increasing sequence number and a timestamp window, rejecting replays and
re-ordered or stale messages.
"""

import json
import os
import socket
import struct
import time

from . import config
from .crypto_utils import (IntegrityError, aes_cbc_decrypt, aes_cbc_encrypt, b64d, b64e,
                           canonical_json, hkdf, hmac_sha256, hmac_verify, rsa_decrypt,
                           rsa_encrypt, rsa_sign, rsa_verify)


class ProtocolError(Exception):
    """Malformed frame or protocol violation."""


class ReplayError(Exception):
    """Message replayed, re-ordered or outside the freshness window."""


# --- Framing ---------------------------------------------------------------

def send_frame(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def send_raw_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_raw_frame(sock: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > config.MAX_FRAME_BYTES:
        raise ProtocolError("frame too large")
    return _recv_exact(sock, length)


def recv_frame(sock: socket.socket) -> dict:
    try:
        obj = json.loads(recv_raw_frame(sock))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError("invalid JSON frame") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("frame must be a JSON object")
    return obj


# --- Handshake helpers -----------------------------------------------------

def handshake_transcript(client_nonce: bytes, server_nonce: bytes, wrapped_master: bytes) -> bytes:
    return b"SECURE-EXAM-HELLO|" + client_nonce + server_nonce + wrapped_master


def derive_session_keys(master: bytes, client_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    okm = hkdf(master, salt=client_nonce + server_nonce, info=b"secure-exam session v1", length=64)
    return okm[:32], okm[32:]


def server_handshake(sign_key, hello: dict) -> tuple[dict, bytes, bytes]:
    """Process a client HELLO. Returns (HELLO_OK reply, k_enc, k_mac)."""
    if hello.get("type") != "HELLO":
        raise ProtocolError("expected HELLO")
    try:
        client_nonce = b64d(hello["client_nonce"])
        wrapped = b64d(hello["wrapped_master"])
        master = rsa_decrypt(sign_key, wrapped)
    except Exception as exc:
        raise ProtocolError("invalid HELLO") from exc
    if len(client_nonce) != 32 or len(master) != 32:
        raise ProtocolError("invalid HELLO parameters")
    server_nonce = new_nonce()
    signature = rsa_sign(sign_key, handshake_transcript(client_nonce, server_nonce, wrapped))
    k_enc, k_mac = derive_session_keys(master, client_nonce, server_nonce)
    reply = {"type": "HELLO_OK", "server_nonce": b64e(server_nonce), "signature": b64e(signature)}
    return reply, k_enc, k_mac


def client_hello(server_pub) -> tuple[dict, bytes, bytes]:
    """Build a client HELLO. Returns (frame, client_nonce, master)."""
    client_nonce, master = new_nonce(), os.urandom(32)
    wrapped = rsa_encrypt(server_pub, master)
    frame = {"type": "HELLO", "client_nonce": b64e(client_nonce), "wrapped_master": b64e(wrapped)}
    return frame, client_nonce, master


def client_finish(server_pub, hello: dict, client_nonce: bytes, master: bytes,
                  reply: dict) -> tuple[bytes, bytes]:
    """Verify the server's HELLO_OK signature and derive the session keys."""
    if reply.get("type") != "HELLO_OK":
        raise ProtocolError("unexpected handshake reply")
    server_nonce = b64d(reply["server_nonce"])
    # Only the holder of the server private key could have produced this signature,
    # and only it could have unwrapped `master`.
    rsa_verify(server_pub, b64d(reply["signature"]),
               handshake_transcript(client_nonce, server_nonce, b64d(hello["wrapped_master"])))
    return derive_session_keys(master, client_nonce, server_nonce)


# --- Secure channel --------------------------------------------------------

class SecureChannel:
    """AES-CBC + HMAC-SHA256 channel with sequence numbers and timestamps."""

    def __init__(self, sock: socket.socket, k_enc: bytes, k_mac: bytes, is_server: bool):
        self.sock = sock
        self.k_enc = k_enc
        self.k_mac = k_mac
        self.send_dir = b"S2C" if is_server else b"C2S"
        self.recv_dir = b"C2S" if is_server else b"S2C"
        self.send_seq = 0
        self.last_recv_seq = -1

    @staticmethod
    def _mac_input(direction: bytes, seq: int, ts: int, iv: bytes, ct: bytes) -> bytes:
        return direction + struct.pack(">QQ", seq, ts) + iv + ct

    def seal(self, payload: dict) -> dict:
        """Encrypt and authenticate a payload, returning the envelope (does not send)."""
        seq, ts = self.send_seq, int(time.time())
        self.send_seq += 1
        iv, ct = aes_cbc_encrypt(self.k_enc, canonical_json(payload))
        mac = hmac_sha256(self.k_mac, self._mac_input(self.send_dir, seq, ts, iv, ct))
        return {"seq": seq, "ts": ts, "iv": b64e(iv), "ct": b64e(ct), "mac": b64e(mac)}

    def open(self, env: dict) -> dict:
        """Verify and decrypt an envelope. Raises IntegrityError / ReplayError."""
        try:
            seq, ts = int(env["seq"]), int(env["ts"])
            iv, ct, mac = b64d(env["iv"]), b64d(env["ct"]), b64d(env["mac"])
        except (KeyError, ValueError, TypeError) as exc:
            raise ProtocolError("malformed envelope") from exc

        # 1. Integrity (before touching the ciphertext: encrypt-then-MAC).
        hmac_verify(self.k_mac, self._mac_input(self.recv_dir, seq, ts, iv, ct), mac)
        # 2. Replay / re-order protection.
        if seq <= self.last_recv_seq:
            raise ReplayError(f"sequence number {seq} already seen (last={self.last_recv_seq})")
        # 3. Freshness.
        if abs(time.time() - ts) > config.MAX_CLOCK_SKEW:
            raise ReplayError("message timestamp outside allowed window")

        self.last_recv_seq = seq
        try:
            return json.loads(aes_cbc_decrypt(self.k_enc, iv, ct))
        except ValueError as exc:
            raise IntegrityError("decryption failed") from exc

    def send(self, payload: dict) -> dict:
        env = self.seal(payload)
        send_frame(self.sock, env)
        return env

    def recv(self) -> dict:
        return self.open(recv_frame(self.sock))


def new_nonce() -> bytes:
    return os.urandom(32)
