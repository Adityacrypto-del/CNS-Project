"""Cryptographic primitives used throughout the system.

  * AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)  -> secure channel messages
  * AES-256-GCM                                   -> data encrypted at rest
  * RSA-OAEP (SHA-256)                            -> key wrapping / key exchange
  * RSA-PSS  (SHA-256)                            -> digital signatures
  * SHA-256, HMAC-SHA256, HKDF-SHA256             -> hashing, integrity, key derivation
  * PBKDF2-HMAC-SHA256                            -> password hashing
"""

import base64
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import config


class IntegrityError(Exception):
    """Raised when a MAC, authentication tag or signature fails to verify."""


# --- Encoding helpers ------------------------------------------------------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def canonical_json(obj) -> bytes:
    """Deterministic JSON encoding so that hashes and signatures are reproducible."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --- Hashing / HMAC --------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_verify(key: bytes, data: bytes, tag: bytes) -> None:
    if not hmac.compare_digest(hmac_sha256(key, data), tag):
        raise IntegrityError("HMAC verification failed")


def hkdf(master: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(master)


# --- Password hashing ------------------------------------------------------

def hash_password(password: str, salt: bytes | None = None,
                  iterations: int = config.PBKDF2_ITERATIONS) -> dict:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {"salt": b64e(salt), "hash": b64e(digest), "iterations": iterations}


def verify_password(password: str, record: dict) -> bool:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 b64d(record["salt"]), record["iterations"])
    return hmac.compare_digest(digest, b64d(record["hash"]))


# --- AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC) --------------------------

def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, enc.update(padded) + enc.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# --- AES-256-GCM (authenticated encryption, used at rest) ------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as exc:
        raise IntegrityError("AES-GCM authentication tag invalid") from exc


# --- RSA ------------------------------------------------------------------

_OAEP = asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None)
_PSS = asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH)


def rsa_generate(bits: int = config.RSA_KEY_BITS) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(data, _OAEP)


def rsa_decrypt(private_key, data: bytes) -> bytes:
    return private_key.decrypt(data, _OAEP)


def rsa_sign(private_key, data: bytes) -> bytes:
    return private_key.sign(data, _PSS, hashes.SHA256())


def rsa_verify(public_key, signature: bytes, data: bytes) -> None:
    try:
        public_key.verify(signature, data, _PSS, hashes.SHA256())
    except InvalidSignature as exc:
        raise IntegrityError("RSA-PSS signature invalid") from exc


def private_key_to_pem(key, password: bytes | None = None) -> bytes:
    enc = (serialization.BestAvailableEncryption(password) if password
           else serialization.NoEncryption())
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, enc)


def public_key_to_pem(key) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key(pem: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(pem, password=password)


def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem)


def key_fingerprint(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256_hex(der)[:32]
